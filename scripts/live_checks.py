#!/usr/bin/env python3
"""Tests de sécurité exécutés contre l'application EN MARCHE (HTTPS, Nginx, MariaDB, Redis).

Complète les tests pytest (qui tournent sans conteneur) : ici, ce sont les vrais services.
Équivalent scripté de ce qu'on ferait à la main avec curl, openssl et Burp Repeater.

Prérequis : `docker compose up -d`, `flask init-db`, `flask seed-demo` (alice, bob) et un
administrateur `admin` créé avec `flask create-admin`. Bibliothèque standard uniquement.

    python scripts/live_checks.py --demo-password '...' --admin-password '...'

ATTENTION : le script crée des comptes jetables (désactivés ensuite) et des documents (supprimés ensuite),
restaure ce qu'il modifie en base (classification, ligne de journal) et finit par une rafale de connexions (T25) qui bloque votre IP
une minute. Ne le lancez pas sur une base de production.
"""
import argparse
import http.client
import http.cookiejar
import re
import secrets
import socket
import ssl
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import deque
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS = []
LOGIN_TIMES = deque()          # horodatages des POST /auth/login (pour rester sous la limite de 10/min)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Browser:
    """Un « navigateur » : jar de cookies propre, TLS validé par la CA locale, redirections non suivies."""

    def __init__(self, base, cafile):
        self.base = base
        self.jar = http.cookiejar.CookieJar()
        ctx = ssl.create_default_context(cafile=cafile)
        ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT   # l'ancienne CA locale n'a pas keyUsage (corrigé dans gen_certs.sh)
        # La CA locale n'a pas de CRL/OCSP : on ne vérifie que la chaîne et le nom d'hôte
        self.opener = urllib.request.build_opener(
            NoRedirect(), urllib.request.HTTPCookieProcessor(self.jar), urllib.request.HTTPSHandler(context=ctx))

    def request(self, path, data=None):
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        # Un vrai navigateur envoie Referer ; Flask-WTF l'exige en HTTPS (protection CSRF supplémentaire)
        req = urllib.request.Request(self.base + path, data=body, headers={"Referer": self.base + "/"})
        start = time.perf_counter()
        try:
            resp = self.opener.open(req, timeout=20)
        except urllib.error.HTTPError as err:
            resp = err
        raw = resp.read().decode("utf-8", "replace")
        return resp.status if hasattr(resp, "status") else resp.code, resp.headers, raw, time.perf_counter() - start

    def get(self, path):
        return self.request(path)

    def raw(self, path, data=None, body=None, content_type=None):
        """Comme request(), mais renvoie les OCTETS du corps (fichiers) et accepte un corps déjà encodé."""
        if body is None and data is not None:
            body = urllib.parse.urlencode(data).encode()
        headers = {"Referer": self.base + "/"}
        if content_type:
            headers["Content-Type"] = content_type
        req = urllib.request.Request(self.base + path, data=body, headers=headers)
        try:
            resp = self.opener.open(req, timeout=60)
        except urllib.error.HTTPError as err:
            resp = err
        return resp.status if hasattr(resp, "status") else resp.code, resp.headers, resp.read()

    def upload(self, filename, content, classification, title="", description="", token_page="/documents/upload"):
        """Envoie le formulaire de dépôt de fichier (multipart/form-data) comme le ferait un navigateur."""
        boundary = "----SecureAuth" + secrets.token_hex(8)
        fields = {"csrf_token": self.token(token_page), "classification": str(classification),
                  "title": title, "content": description}
        parts = [f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode() for k, v in fields.items()]
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\n'
                     "Content-Type: application/octet-stream\r\n\r\n".encode() + content + b"\r\n")
        parts.append(f"--{boundary}--\r\n".encode())
        return self.raw("/documents/upload", body=b"".join(parts), content_type=f"multipart/form-data; boundary={boundary}")

    def token(self, page):
        _, _, html, _ = self.get(page)
        m = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)
        if not m:
            raise RuntimeError(f"pas de jeton CSRF sur {page}")
        return m.group(1)

    def post(self, path, data=None, token_page="/"):
        payload = dict(data or {})
        payload["csrf_token"] = self.token(token_page)
        return self.request(path, payload)

    def login(self, username, password):
        throttle()
        status, headers, html, elapsed = self.request("/auth/login", {
            "csrf_token": self.token("/auth/login"), "identifier": username, "password": password})
        LOGIN_TIMES.append(time.time())
        return status, html, elapsed

    def sid(self):
        for cookie in self.jar:
            if cookie.name == "__Host-sid":
                return cookie.value
        return None


def throttle():
    """Reste sous la limite de 10 connexions/minute (sinon on testerait la limite sans le vouloir)."""
    while LOGIN_TIMES and time.time() - LOGIN_TIMES[0] > 61:
        LOGIN_TIMES.popleft()
    if len(LOGIN_TIMES) >= 8:
        wait = 62 - (time.time() - LOGIN_TIMES[0])
        print(f"   ... pause de {wait:.0f}s pour respecter la limitation de débit", flush=True)
        time.sleep(max(wait, 1))
        LOGIN_TIMES.clear()


def check(test, scenario, expected, obtained, ok):
    RESULTS.append((test, scenario, expected, obtained, ok))
    print(f"[{'OK' if ok else 'KO'}] {test} {scenario} -> attendu : {expected} ; obtenu : {obtained}", flush=True)


def sql(statement):
    """Exécute du SQL dans le conteneur MariaDB (comme un attaquant ayant accès à la base)."""
    proc = subprocess.run(
        ["docker", "compose", "exec", "-T", "db", "sh", "-c", 'mariadb -uroot -p"$MARIADB_ROOT_PASSWORD" secureauth -N'],
        input=statement, capture_output=True, text=True, encoding="utf-8", errors="replace", cwd=ROOT, timeout=60)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr)
    return proc.stdout.strip()


def doc_ids(browser):
    _, _, html, _ = browser.get("/documents/")
    return {ref: pid for pid, ref in re.findall(r'href="/documents/([0-9a-f-]{36})">([A-Z]+-[0-9A-Z-]+)</a>', html)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="https://localhost")
    ap.add_argument("--cafile", default=str(ROOT / "pki" / "ca.crt"))
    ap.add_argument("--demo-password", required=True, help="mot de passe d'alice et bob (seed-demo)")
    ap.add_argument("--admin-password", required=True, help="mot de passe du compte admin")
    ap.add_argument("--no-wait", action="store_true", help="ne pas attendre la fin de la fenêtre de limitation de débit au départ")
    ap.add_argument("--output", default=str(ROOT / "docs" / "preuves" / "live-checks.txt"))
    args = ap.parse_args()
    new = lambda: Browser(args.base, args.cafile)
    if not args.no_wait:
        print("Attente de 65 s : une exécution précédente a pu épuiser le quota de connexions (10/min).", flush=True)
        time.sleep(65)

    # ---------------- Transport et en-têtes (T04, T22, T23) -------------------------------------
    b = new()
    status, headers, _, _ = b.get("/auth/login")
    cookie = headers.get("Set-Cookie", "")
    flags = all(f in cookie for f in ("__Host-sid=", "Secure", "HttpOnly", "SameSite=Lax", "Path=/")) and "Domain" not in cookie
    check("T04", "drapeaux du cookie de session", "__Host-, Secure, HttpOnly, SameSite=Lax, sans Domain", cookie.split(";", 1)[1].strip()[:70] if ";" in cookie else cookie, flags)
    expires = re.search(r"Expires=([^;]+)", cookie)
    check("T07", "expiration du cookie", "environ 30 min", expires.group(1) if expires else "absente", bool(expires))

    needed = ["X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Content-Security-Policy", "Strict-Transport-Security"]
    missing = [h for h in needed if h not in headers]
    check("T23", "en-têtes de sécurité (curl -I)", "tous présents", "tous présents" if not missing else f"manquants : {missing}", not missing)

    check("T23", "version de Nginx masquée", "server: nginx sans numéro", headers.get("Server"), re.fullmatch(r"nginx", headers.get("Server", "")) is not None)

    # T22 : seul TLS 1.2 / 1.3 est accepté
    def tls_ok(minimum, maximum):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(args.cafile)
        ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
        ctx.minimum_version, ctx.maximum_version = minimum, maximum
        try:
            with socket.create_connection(("localhost", 443), timeout=5) as raw, ctx.wrap_socket(raw, server_hostname="localhost") as tls:
                return tls.version()
        except (ssl.SSLError, OSError) as exc:
            return f"refusé ({type(exc).__name__})"
    v12, v13 = tls_ok(ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2), tls_ok(ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3)
    check("T22", "connexion TLS 1.2 puis TLS 1.3", "acceptées", f"{v12} / {v13}", v12 == "TLSv1.2" and v13 == "TLSv1.3")
    try:
        proc = subprocess.run(["docker", "run", "--rm", "--network", "container:secure-auth-platform-nginx-1", "alpine/openssl",
                               "s_client", "-connect", "127.0.0.1:443", "-tls1_1"], capture_output=True, text=True, timeout=120, input="")
        refused = "Cipher is (NONE)" in proc.stdout + proc.stderr or "alert protocol version" in proc.stdout + proc.stderr or proc.returncode != 0
        check("T22", "openssl s_client -tls1_1", "refusée", "refusée (alert protocol version)" if refused else "ACCEPTÉE", refused)
    except Exception as exc:  # image indisponible : on le dit, sans fausser le résultat
        check("T22", "openssl s_client -tls1_1", "refusée", f"non exécuté ({type(exc).__name__})", False)

    # HTTP -> HTTPS
    try:
        conn = http.client.HTTPConnection("localhost", 80, timeout=5)
        conn.request("GET", "/auth/login")
        r = conn.getresponse()
        check("T23", "redirection HTTP vers HTTPS", "301 vers https://", f"{r.status} {r.getheader('Location')}", r.status == 301 and str(r.getheader("Location")).startswith("https://"))
    except OSError as exc:
        check("T23", "redirection HTTP vers HTTPS", "301", f"port 80 injoignable ({exc})", False)

    # ---------------- Infrastructure (T24) --------------------------------------------------------------
    import json
    ps = subprocess.run(["docker", "compose", "ps", "--format", "json"], capture_output=True, text=True, cwd=ROOT, timeout=60).stdout
    published = {}
    for line in ps.splitlines():
        if line.strip().startswith("{"):
            row = json.loads(line)
            published[row["Service"]] = sorted({p["PublishedPort"] for p in row.get("Publishers") or [] if p.get("PublishedPort")})
    for service, port, name in (("db", 3306, "MariaDB"), ("redis", 6379, "Redis")):
        ports = published.get(service)
        try:
            socket.create_connection(("localhost", port), timeout=3).close()
            probe = f"localhost:{port} répond (autre service de la machine, pas le conteneur)"
        except OSError:
            probe = f"localhost:{port} refuse la connexion"
        check("T24", f"port {port} de {name} publié sur l'hôte par Docker ?", "aucun port publié",
              f"ports publiés : {ports if ports is not None else 'service absent'} ; {probe}", ports == [])
    check("T24", "ports publiés par docker compose ps (nginx)", "80 et 443 uniquement", str(sorted(published.get("nginx", []))), sorted(published.get("nginx", [])) == [80, 443])

    # ---------------- Authentification (T01, T03, T05, T06, T08) ------------------------------------------------
    b = new()
    unknown = [b.login(f"fantome{i}", "Mot-de-passe-faux-123")[2] for i in range(3)]
    s_unknown, html_unknown, _ = b.login("fantome9", "Mot-de-passe-faux-123")
    known = [b.login("bob", "Mot-de-passe-faux-123")[2] for i in range(3)]  # 3 échecs < 5 : pas de verrouillage
    s_known, html_known, _ = b.login("bob", "Mot-de-passe-faux-123")
    same = s_unknown == s_known == 200 and "Identifiants invalides" in html_unknown and "Identifiants invalides" in html_known
    gap = abs(statistics.median(unknown) - statistics.median(known))
    check("T01", "compte inconnu vs mauvais mot de passe", "même message, durée comparable",
          f"même message={same}, médianes {statistics.median(unknown)*1000:.0f} ms / {statistics.median(known)*1000:.0f} ms", same and gap < 0.08)

    s, html, _ = b.login("' OR '1'='1' --", "x" * 12)
    check("T03", "injection SQL dans le formulaire", "échec normal, aucune erreur SQL",
          f"{s}, message générique={'Identifiants invalides' in html}", s == 200 and "Identifiants invalides" in html and "SQL" not in html and "Traceback" not in html)

    raw_status, _, _, _ = b.request("/auth/login", {"identifier": "bob", "password": "x" * 12})   # aucun jeton
    check("T08", "POST de connexion sans jeton CSRF", "HTTP 400", raw_status, raw_status == 400)

    before = new()
    before.get("/auth/login")
    sid_before = before.sid()
    status, _, _ = before.login("alice", args.demo_password)
    sid_after = before.sid()
    check("T05", "identifiant de session avant / après connexion", "différent", f"{(sid_before or '')[:8]}… -> {(sid_after or '')[:8]}…",
          status == 302 and sid_before and sid_after and sid_before != sid_after)

    old_cookie = sid_after
    before.post("/auth/logout")
    replay = new()
    replay.jar.set_cookie(http.cookiejar.Cookie(0, "__Host-sid", old_cookie, None, False, "localhost", False, False, "/", True, True, None, False, None, None, {}))
    r_status, r_headers, _, _ = replay.get("/documents/")
    check("T06", "rejeu du cookie après déconnexion", "redirection vers la connexion", f"{r_status} {r_headers.get('Location')}",
          r_status == 302 and "/auth/login" in (r_headers.get("Location") or ""))

    # ---------------- Autorisation (T09 à T16) ---------------------------------------------------------------------
    alice, bob, admin = new(), new(), new()
    assert alice.login("alice", args.demo_password)[0] == 302, "connexion alice impossible (mot de passe de démo ?)"
    assert bob.login("bob", args.demo_password)[0] == 302, "connexion bob impossible"
    assert admin.login("admin", args.admin_password)[0] == 302, "connexion admin impossible"
    ids = doc_ids(alice)
    ts, sec1, sec2 = ids.get("TS-001"), ids.get("SEC-001"), None
    bob_ids = doc_ids(bob)
    sec2 = bob_ids.get("SEC-002")
    if not (ts and sec1 and sec2):
        sys.exit("jeu de démonstration incomplet : lancez flask seed-demo")

    code = bob.get(f"/documents/{ts}")[0]
    check("T09", "bob (SECRET) -> TS-001 (TRÈS SECRET)", "HTTP 404", code, code == 404)
    code = alice.get(f"/documents/{sec2}")[0]
    check("T10", "alice (habilitée) -> SEC-002 (hors liste d'accès)", "HTTP 404", code, code == 404)
    forbidden, unknown_uuid, integer = bob.get(f"/documents/{ts}"), bob.get(f"/documents/{uuid.uuid4()}"), bob.get("/documents/1")
    check("T11", "IDOR : document interdit / UUID inconnu / identifiant entier", "404 identiques",
          f"{forbidden[0]} / {unknown_uuid[0]} / {integer[0]}", forbidden[0] == unknown_uuid[0] == integer[0] == 404)
    code = admin.get(f"/documents/{ts}")[0]
    check("T12", "administrateur -> TS-001", "HTTP 404", code, code == 404)

    status, _, html, _ = admin.post(f"/documents/{ts}/access/grant", {"username": "admin"}, f"/documents/{ts}/access")
    redirected = admin.get(f"/documents/{ts}/access")[2]
    check("T13", "l'administrateur s'attribue un accès", "refus + ADMIN_SELF_MODIFY_DENIED",
          "refusé" if "ne peut pas" in redirected else "message absent", "ne peut pas" in redirected and admin.get(f"/documents/{ts}")[0] == 404)
    admin_id = sql("SELECT id FROM users WHERE username = 'admin';")
    admin.post(f"/admin/users/{admin_id}/clearance", {"level": "3"}, "/admin/users")
    own_level = sql("SELECT clearance_level FROM users WHERE username = 'admin';")
    check("T13", "l'administrateur modifie sa propre habilitation", "refus (habilitation inchangée)", f"habilitation en base = {own_level}", own_level == "0")

    code = bob.get("/admin/users")[0]
    check("T14", "agent -> /admin/users", "HTTP 403", code, code == 403)

    bob_id = sql("SELECT id FROM users WHERE username = 'bob';")
    admin.post(f"/admin/users/{bob_id}/clearance", {"level": "1"}, "/admin/users")
    lost = bob.get(f"/documents/{sec1}")[0]
    admin.post(f"/admin/users/{bob_id}/clearance", {"level": "2"}, "/admin/users")   # on restaure la démo
    check("T15", "habilitation de bob abaissée à 1, session déjà ouverte", "accès perdu immédiatement (404)", lost, lost == 404)

    forged = bob.post("/documents/new", {"title": "t", "classification": "3", "content": "c"}, "/documents/new")[0]
    check("T16", "création au-dessus de l'habilitation (champ modifié)", "refus (403)", forged, forged == 403)

    # ---------------- Cryptographie et intégrité (T17, T18, T19, T21) -----------------------------------------------------
    dump = sql("SELECT reference, HEX(nonce), HEX(ciphertext) FROM secure_documents WHERE reference = 'TS-001';")
    readable = sql("SELECT reference, CAST(ciphertext AS CHAR) FROM secure_documents WHERE reference = 'TS-001';")
    check("T18", "lecture directe de la table secure_documents", "binaire illisible, ni titre ni contenu",
          f"nonce+ciphertext = {dump[:60]}…", "Aurore" not in readable and "Aurore" not in dump)

    sql("UPDATE secure_documents SET classification = 0 WHERE reference = 'TS-001';")
    try:
        tampered = alice.get(f"/documents/{ts}")
    finally:
        sql("UPDATE secure_documents SET classification = 3 WHERE reference = 'TS-001';")    # restauration
    logged = sql("SELECT COUNT(*) FROM audit_logs WHERE event = 'INTEGRITY_FAILURE';")
    check("T17", "classification de TS-001 passée à 0 directement en base", "déchiffrement refusé + INTEGRITY_FAILURE",
          f"HTTP {tampered[0]}, {logged} ligne(s) INTEGRITY_FAILURE", tampered[0] == 500 and int(logged) >= 1 and "Aurore" not in tampered[2])
    code = alice.get(f"/documents/{ts}")[0]
    check("T17", "après restauration de la classification", "lecture à nouveau possible", code, code == 200)

    title = f"<script>alert('{secrets.token_hex(2)}')</script>"
    status, headers, _, _ = alice.post("/documents/new", {"title": title, "classification": "0", "content": title}, "/documents/new")
    page = alice.get(headers.get("Location", "/documents/"))[2]
    check("T21", "balise <script> dans un titre de document", "affichée comme texte, bloquée par la CSP",
          "échappée (&lt;script&gt;)" if "&lt;script&gt;" in page and "<script>alert" not in page else "NON ÉCHAPPÉE", "&lt;script&gt;" in page and "<script>alert" not in page)

    verify = lambda: admin.post("/admin/audit/verify", {}, "/admin/audit/verify")[2]
    before_attack = verify()
    check("T19", "journal intact avant l'attaque", "Chaîne intègre", "Chaîne intègre" if "Chaîne intègre" in before_attack else "corrompue", "Chaîne intègre" in before_attack)
    victim = sql("SELECT id FROM audit_logs WHERE event = 'LOGIN_SUCCESS' ORDER BY id LIMIT 1;")
    original = sql(f"SELECT outcome FROM audit_logs WHERE id = {victim};")
    sql(f"UPDATE audit_logs SET outcome = 'FAILURE' WHERE id = {victim};")
    try:
        report = verify()
    finally:
        sql(f"UPDATE audit_logs SET outcome = '{original}' WHERE id = {victim};")     # restauration exacte
    detected = "Chaîne corrompue" in report and f">{victim}<" in report
    check("T19", f"ligne {victim} du journal modifiée directement en base", "ligne désignée par la page de vérification",
          f"désignée : {detected}", detected)
    final = verify()
    check("T19", "après restauration de la ligne", "Chaîne intègre à nouveau", "Chaîne intègre" if "Chaîne intègre" in final else "corrompue", "Chaîne intègre" in final)

    # ---------------- Parcours complet sur la vraie base (MariaDB est plus strict que SQLite) ----------------------------------
    pages = [(alice, "/documents/"), (alice, "/documents/new"), (alice, f"/documents/{ts}"), (alice, f"/documents/{ts}/access"),
             (admin, "/admin/"), (admin, "/admin/users"), (admin, "/admin/documents"), (admin, "/admin/audit"),
             (admin, "/admin/audit?page=2"), (admin, "/admin/audit?event=DOC_READ"), (admin, "/admin/audit/verify")]
    codes = [(url, who.get(url)[0]) for who, url in pages]
    bad = [(url, code) for url, code in codes if code != 200]
    check("SMOKE", f"{len(pages)} pages des espaces documents et administration", "toutes en HTTP 200", "toutes en 200" if not bad else f"{bad}", not bad)

    # ---------------- Comptes créés par l'administrateur (T26) ----------------------------------------------------------------------
    newcomer = f"ajout{secrets.token_hex(3)}"
    temp_pw, final_pw = f"Provisoire-{secrets.token_hex(4)}-Test-42", f"Definitif-{secrets.token_hex(4)}-Test-42"
    code = bob.get("/admin/users/new")[0]
    check("T26", "un agent ouvre le formulaire d'ajout d'utilisateur", "HTTP 403", code, code == 403)
    status = admin.post("/admin/users/new", {"username": newcomer, "email": f"{newcomer}@example.com", "clearance": "2",
                                             "password": temp_pw, "confirm": temp_pw}, "/admin/users/new")[0]
    row = sql(f"SELECT role, clearance_level, must_change_password, LEFT(password_hash, 9) FROM users WHERE username = '{newcomer}';").split()
    check("T26", "l'administrateur ajoute un agent (habilitation SECRET)", "rôle user, niveau 2, mot de passe provisoire, Argon2id",
          " / ".join(row), status == 302 and row == ["user", "2", "1", "$argon2id"])
    logged = sql(f"SELECT COUNT(*) FROM audit_logs WHERE event = 'USER_CREATE' AND details LIKE '{newcomer}%' AND details NOT LIKE '%{temp_pw}%';")
    check("T26", "création journalisée (USER_CREATE) sans le mot de passe", "1 ligne", f"{logged} ligne(s)", logged == "1")
    agent = new()
    logged_in_status = agent.login(newcomer, temp_pw)[0]
    first = agent.get("/documents/")
    check("T26", "première page demandée avec le mot de passe provisoire", "redirection vers /auth/password",
          f"{first[0]} {first[1].get('Location')}", logged_in_status == 302 and first[0] == 302 and str(first[1].get("Location")).endswith("/auth/password"))
    agent.post("/auth/password", {"current_password": temp_pw, "new_password": final_pw, "confirm": final_pw}, "/auth/password")
    flag = sql(f"SELECT must_change_password FROM users WHERE username = '{newcomer}';")
    after = agent.get("/documents/")[0]
    check("T26", "après le changement de mot de passe", "accès rétabli, indicateur à 0", f"HTTP {after}, indicateur = {flag}", after == 200 and flag == "0")

    # ---------------- Dépôt de fichiers PDF / DOC / DOCX (T27 à T30) ---------------------------------------------------------------
    marker = f"MARQUEUR-{secrets.token_hex(6)}"
    pdf = b"%PDF-1.4\n" + marker.encode() + b"\n" + secrets.token_bytes(3 * 1024 * 1024)   # 3 Mo : plus que les 2 Mo des autres pages
    file_name = f"plan-{secrets.token_hex(3)}.pdf"
    status, headers, _ = alice.upload(file_name, pdf, 2, title=f"Dépôt de test {marker}")
    location = headers.get("Location") or ""
    pid = location.rsplit("/", 1)[-1]
    check("T27", "alice dépose un PDF de 3 Mo classé SECRET", "HTTP 302 vers la fiche du document", f"{status} {location}",
          status == 302 and re.fullmatch(r"[0-9a-f-]{36}", pid) is not None)
    stored = sql(f"SELECT file_size, LENGTH(file_ciphertext), INSTR(file_ciphertext, '{marker}'), INSTR(ciphertext, '{file_name}'), "
                 f"INSTR(file_ciphertext, '{file_name}') FROM secure_documents WHERE public_id = '{pid}';").split()
    check("T27", "lecture directe de la colonne file_ciphertext", "taille + 16 octets (étiquette GCM), ni contenu ni nom de fichier en clair",
          f"taille {stored[0]}, stocké {stored[1]}, marqueur/nom trouvés à : {stored[2:]}",
          stored == [str(len(pdf)), str(len(pdf) + 16), "0", "0", "0"])
    code, headers, data = alice.raw(f"/documents/{pid}/download")
    check("T27", "téléchargement par alice", "octets identiques, application/pdf, attachment, nosniff, no-store",
          f"{code}, identique={data == pdf}, {headers.get('Content-Type')}, {headers.get('Content-Disposition', '')[:22]}, "
          f"{headers.get('X-Content-Type-Options')}, {headers.get('Cache-Control')}",
          code == 200 and data == pdf and headers.get("Content-Type") == "application/pdf" and headers.get("Content-Disposition", "").startswith("attachment")
          and headers.get("X-Content-Type-Options") == "nosniff" and headers.get("Cache-Control") == "no-store")

    code = bob.raw(f"/documents/{pid}/download")[0]
    denied = sql(f"SELECT COUNT(*) FROM audit_logs WHERE event = 'DOC_ACCESS_DENIED' AND target_id = '{pid}';")
    check("T28", "bob (SECRET, absent de la liste d'accès) télécharge le fichier", "HTTP 404 + DOC_ACCESS_DENIED", f"{code}, {denied} refus journalisé(s)", code == 404 and int(denied) >= 1)
    alice.post(f"/documents/{pid}/access/grant", {"username": "bob"}, f"/documents/{pid}/access")
    code, _, data = bob.raw(f"/documents/{pid}/download")
    downloads = sql(f"SELECT COUNT(*) FROM audit_logs WHERE event = 'DOC_DOWNLOAD' AND target_id = '{pid}';")
    check("T28", "après partage par le propriétaire", "bob télécharge les mêmes octets, DOC_DOWNLOAD journalisé", f"{code}, identique={data == pdf}, {downloads} téléchargement(s) journalisé(s)",
          code == 200 and data == pdf and downloads == "2")
    sql(f"UPDATE secure_documents SET classification = 0 WHERE public_id = '{pid}';")
    try:
        code = alice.raw(f"/documents/{pid}/download")[0]
    finally:
        sql(f"UPDATE secure_documents SET classification = 2 WHERE public_id = '{pid}';")    # restauration
    broken = sql(f"SELECT COUNT(*) FROM audit_logs WHERE event = 'INTEGRITY_FAILURE' AND target_id = '{pid}';")
    check("T28", "classification du document passée à 0 directement en base", "téléchargement refusé (500) + INTEGRITY_FAILURE", f"HTTP {code}, {broken} ligne(s)", code == 500 and int(broken) >= 1)

    before_count = sql("SELECT COUNT(*) FROM secure_documents;")
    refused = {
        "faux PDF (texte déguisé)": alice.upload("faux.pdf", b"ceci n'est pas un pdf", 0)[0],
        "exécutable .exe": alice.upload("virus.exe", b"MZ" + b"\x00" * 600, 0)[0],
        "page .html": alice.upload("page.html", b"<script>alert(1)</script>", 0)[0],
    }
    check("T29", "faux PDF, .exe et .html déposés", "HTTP 400 pour chacun", str(refused), set(refused.values()) == {400})
    try:
        big = alice.upload("enorme.pdf", b"%PDF-1.4\n" + b"A" * (11 * 1024 * 1024), 0)[0]
    except (OSError, urllib.error.URLError) as exc:
        big = f"connexion coupée par Nginx ({type(exc).__name__})"
    try:
        wide = alice.raw("/documents/new", body=b"x" * (3 * 1024 * 1024), content_type="application/x-www-form-urlencoded")[0]
    except (OSError, urllib.error.URLError) as exc:
        wide = f"connexion coupée par Nginx ({type(exc).__name__})"
    after_count = sql("SELECT COUNT(*) FROM secure_documents;")
    # Nginx répond 413, ou coupe la connexion pendant l'envoi : dans les deux cas rien n'atteint l'application
    stopped = lambda value: value == 413 or str(value).startswith("connexion coupée")
    check("T29", "fichier de 11 Mo, puis corps de 3 Mo sur une autre page", "refusés par Nginx : seule la page de dépôt dépasse 2 Mo",
          f"11 Mo -> {big} ; 3 Mo ailleurs -> {wide}", stopped(big) and stopped(wide))
    check("T29", "documents enregistrés après ces refus", "aucun de plus", f"{before_count} -> {after_count}", before_count == after_count)

    directive = f"directive-{secrets.token_hex(3)}.pdf"
    status, headers, _ = admin.upload(directive, pdf[:5000], 3, title="Directive de test")
    found = re.search(r"/documents/([0-9a-f-]{36})/access$", headers.get("Location") or "")
    pid_ts = found.group(1) if found else ""
    check("T30", "l'administrateur dépose un document TRÈS SECRET", "accepté, puis redirigé vers le partage (il ne peut pas le lire)",
          f"{status} {headers.get('Location')}", status == 302 and re.fullmatch(r"[0-9a-f-]{36}", pid_ts) is not None)
    owner = sql(f"SELECT classification, (SELECT username FROM users WHERE id = owner_id), (SELECT clearance_level FROM users WHERE id = owner_id) FROM secure_documents WHERE public_id = '{pid_ts}';").split()
    admin_read, admin_down = admin.get(f"/documents/{pid_ts}")[0], admin.raw(f"/documents/{pid_ts}/download")[0]
    check("T30", "l'administrateur relit ou télécharge son propre dépôt", "HTTP 404 (pas de lecture vers le haut)",
          f"classification/propriétaire/habilitation = {owner} ; lecture {admin_read}, téléchargement {admin_down}",
          owner == ["3", "admin", "0"] and admin_read == 404 and admin_down == 404)
    admin.post(f"/documents/{pid_ts}/access/grant", {"username": "bob"}, f"/documents/{pid_ts}/access")
    admin.post(f"/documents/{pid_ts}/access/grant", {"username": "alice"}, f"/documents/{pid_ts}/access")
    bob_code, alice_code = bob.raw(f"/documents/{pid_ts}/download")[0], alice.raw(f"/documents/{pid_ts}/download")[0]
    check("T30", "partage à bob (SECRET) puis à alice (TRÈS SECRET)", "bob refusé (404), alice télécharge (200)", f"bob {bob_code}, alice {alice_code}", bob_code == 404 and alice_code == 200)

    # Nettoyage : documents et compte de test créés ci-dessus (les comptes ne se suppriment pas : on le désactive)
    sql(f"DELETE FROM document_access WHERE document_id IN (SELECT id FROM secure_documents WHERE public_id IN ('{pid}', '{pid_ts}'));")
    sql(f"DELETE FROM secure_documents WHERE public_id IN ('{pid}', '{pid_ts}');")
    newcomer_id = sql("SELECT id FROM users WHERE username = '" + newcomer + "';")
    admin.post(f"/admin/users/{newcomer_id}/active", {}, "/admin/users")

    # ---------------- Verrouillage (T02) puis rafale (T25) ----------------------------------------------------------------------------
    lock = new()
    name = f"lock{secrets.token_hex(3)}"
    password = f"Verrou-{secrets.token_hex(4)}-Test-42"
    lock.post("/auth/register", {"username": name, "email": f"{name}@example.com", "password": password, "confirm": password}, "/auth/register")
    codes = [lock.login(name, "Mauvais-mot-de-passe-1")[0] for _ in range(6)]
    final_status, final_html, _ = lock.login(name, password)
    check("T02", "6 échecs consécutifs puis le BON mot de passe", "compte verrouillé, même message", f"{final_status}, message générique={'Identifiants invalides' in final_html}",
          final_status == 200 and "Identifiants invalides" in final_html and lock.get("/documents/")[0] == 302)
    locked_until = sql(f"SELECT locked_until IS NOT NULL FROM users WHERE username = '{name}';")
    check("T02", "colonne locked_until renseignée", "1", locked_until, locked_until == "1")

    burst = new()
    time.sleep(62)
    token = burst.token("/auth/login")
    results = []
    for _ in range(16):
        results.append(burst.request("/auth/login", {"csrf_token": token, "identifier": "rafale", "password": "x" * 12})[0])
    first = results.index(429) + 1 if 429 in results else None
    check("T25", "rafale de 16 connexions (équivalent Burp Intruder)", "HTTP 429 après le seuil", f"codes {results[:3]}…{results[-3:]}, premier 429 à la requête n°{first}", first is not None)

    # ---------------- Rapport ---------------------------------------------------------------------------------------------------------------------
    ok = sum(1 for r in RESULTS if r[4])
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(f"Tests de sécurité contre l'application en marche : {args.base}\n")
        fh.write(f"Exécutés le {time.strftime('%Y-%m-%d %H:%M:%S')} - {ok}/{len(RESULTS)} vérifications conformes\n\n")
        for test, scenario, expected, obtained, passed in RESULTS:
            fh.write(f"[{'OK' if passed else 'KO'}] {test}  {scenario}\n       attendu : {expected}\n       obtenu  : {obtained}\n")
    print(f"\n{ok}/{len(RESULTS)} vérifications conformes -> {args.output}")
    sys.exit(0 if ok == len(RESULTS) else 1)


if __name__ == "__main__":
    main()
