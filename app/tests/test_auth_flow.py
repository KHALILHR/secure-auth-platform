"""Inscription, connexion, sessions, déconnexion, mot de passe, create-admin (plan §8).

Couvre T01 (message unique), T04 (drapeaux du cookie), T05 (fixation de session),
T06 (rejeu après déconnexion) et T08 (CSRF). La protection CSRF reste ACTIVE :
chaque POST lit d'abord le jeton dans le formulaire, comme un navigateur.
"""
import re

import pytest
from argon2 import PasswordHasher

from secureauth.auth.service import LOGIN_REFUSED, REGISTER_REFUSED, is_safe_next
from secureauth.extensions import db
from secureauth.models import AuditLog, User
from secureauth.security.audit import verify_chain

PASSWORD = "Cheval-Agrafe-Lune-42"
NEW_PASSWORD = "Riviere-Tracteur-Opale-77"
COOKIE = "__Host-sid"


# --- Outils ------------------------------------------------------------------------

def csrf(client, url):
    html = client.get(url).data.decode()
    match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)
    assert match, f"pas de jeton CSRF sur {url}"
    return match.group(1)


def register(client, username="alice", email="alice@example.com", password=PASSWORD, confirm=None):
    return client.post("/auth/register", data={
        "csrf_token": csrf(client, "/auth/register"),
        "username": username, "email": email,
        "password": password, "confirm": password if confirm is None else confirm,
    })


def login(client, identifier="alice", password=PASSWORD, next_url=None):
    url = "/auth/login" + (f"?next={next_url}" if next_url else "")
    return client.post(url, data={
        "csrf_token": csrf(client, "/auth/login"),
        "identifier": identifier, "password": password,
    })


def logout(client):
    return client.post("/auth/logout", data={"csrf_token": csrf(client, "/")})


def sid(client):
    cookie = client.get_cookie(COOKIE)
    return cookie.value if cookie else None


def events(name):
    return AuditLog.query.filter_by(event=name).all()


@pytest.fixture
def alice(client):
    assert register(client).status_code == 302
    return db.session.query(User).filter_by(username="alice").one()


# --- Inscription ---------------------------------------------------------------------

def test_register_creates_plain_agent(client):
    resp = register(client)
    assert resp.status_code == 302 and resp.headers["Location"] == "/auth/login"
    user = User.query.filter_by(username="alice").one()
    assert user.role == "user" and user.clearance_level == 0 and user.is_active
    assert user.password_hash.startswith("$argon2id$")
    assert user.email == "alice@example.com"
    assert len(events("REGISTER")) == 1


def test_register_normalizes_email(client):
    register(client, email="  Alice@Example.COM ")
    assert User.query.one().email == "alice@example.com"


def test_register_duplicate_username_gives_generic_message(client, alice):
    resp = register(client, username="ALICE", email="autre@example.com")
    assert REGISTER_REFUSED.encode() in resp.data
    assert User.query.count() == 1


def test_register_duplicate_email_gives_same_generic_message(client, alice):
    resp = register(client, username="alice2", email="ALICE@example.com")
    assert REGISTER_REFUSED.encode() in resp.data
    assert User.query.count() == 1


def test_register_weak_password_refused(client):
    resp = register(client, password="password1234")
    assert "trop courant".encode() in resp.data
    assert User.query.count() == 0


def test_register_password_equal_to_username_refused(client):
    resp = register(client, username="cheval-agrafe", password="Cheval-Agrafe")
    assert User.query.count() == 0
    assert resp.status_code == 200


def test_register_confirmation_mismatch_refused(client):
    resp = register(client, confirm=PASSWORD + "x")
    assert "diffèrent".encode() in resp.data
    assert User.query.count() == 0


@pytest.mark.parametrize("bad", ["ab", "a" * 33, "alice bob", "<script>", "alice;--"])
def test_register_invalid_username_refused(client, bad):
    register(client, username=bad)
    assert User.query.count() == 0


def test_register_invalid_email_refused(client):
    register(client, email="pas-un-email")
    assert User.query.count() == 0


# --- Connexion -----------------------------------------------------------------------

def test_login_with_username(client, alice):
    resp = login(client)
    assert resp.status_code == 302 and resp.headers["Location"] == "/"
    assert b"Bienvenue, alice" in client.get("/").data
    assert len(events("LOGIN_SUCCESS")) == 1


def test_login_with_email_case_insensitive(client, alice):
    assert login(client, identifier="ALICE@Example.com").status_code == 302


def test_login_username_case_insensitive(client, alice):
    assert login(client, identifier="Alice").status_code == 302


def test_unknown_account_and_wrong_password_look_identical(client, alice):
    """T01 : même code HTTP, même message, que le compte existe ou non."""
    wrong = login(client, identifier="alice", password="Mauvais-Mot-De-Passe-1")
    unknown = login(client, identifier="personne", password="Mauvais-Mot-De-Passe-1")
    assert wrong.status_code == unknown.status_code == 200
    assert LOGIN_REFUSED.encode() in wrong.data and LOGIN_REFUSED.encode() in unknown.data
    assert sid(client) is not None and b"Bienvenue" not in client.get("/", follow_redirects=True).data


def test_failures_are_logged(client, alice):
    login(client, password="Mauvais-Mot-De-Passe-1")
    login(client, identifier="personne")
    details = sorted(e.details for e in events("LOGIN_FAILURE"))
    assert details == ["compte inconnu", "mot de passe incorrect"]


def test_disabled_account_refused_even_with_good_password(client, alice):
    alice.is_active = False
    db.session.commit()
    resp = login(client)
    assert LOGIN_REFUSED.encode() in resp.data
    assert events("LOGIN_FAILURE")[0].outcome == "DENIED"


def test_logged_in_user_is_sent_away_from_login_page(client, alice):
    login(client)
    assert client.get("/auth/login").status_code == 302


def test_index_redirects_anonymous_to_login(client):
    resp = client.get("/")
    assert resp.status_code == 302 and resp.headers["Location"] == "/auth/login"


def test_login_updates_last_login(client, alice):
    assert alice.last_login_at is None
    login(client)
    db.session.refresh(alice)
    assert alice.last_login_at is not None


def test_login_rehashes_weak_hash(client, alice):
    alice.password_hash = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash(PASSWORD)
    db.session.commit()
    login(client)
    db.session.refresh(alice)
    assert "m=65536,t=3,p=4" in alice.password_hash


# --- Redirection après connexion (anti redirection ouverte) -------------------------------

def test_next_internal_path_is_followed(client, alice):
    assert login(client, next_url="/auth/password").headers["Location"] == "/auth/password"


@pytest.mark.parametrize("evil", ["https://pirate.example", "//pirate.example", "/\\pirate.example"])
def test_next_external_url_is_ignored(client, alice, evil):
    assert login(client, next_url=evil).headers["Location"] == "/"


@pytest.mark.parametrize("target, ok", [
    ("/documents", True), ("/", True), (None, False), ("", False),
    ("https://x.example", False), ("//x.example", False), ("/\\x.example", False), ("javascript:alert(1)", False),
])
def test_is_safe_next(target, ok):
    assert is_safe_next(target) is ok


# --- Session : cookie, fixation, rejeu -------------------------------------------------------

def test_session_cookie_flags(client, alice):
    """T04 : préfixe __Host-, Secure, HttpOnly, SameSite=Lax, Path=/ sans Domain."""
    resp = login(client)
    header = next(h for h in resp.headers.getlist("Set-Cookie") if h.startswith(COOKIE + "="))
    for flag in ("Secure", "HttpOnly", "SameSite=Lax", "Path=/"):
        assert flag in header, f"{flag} absent de : {header}"
    assert "Domain=" not in header


def test_session_id_changes_at_login(client, alice):
    """T05 : l'identifiant connu AVANT la connexion ne vaut plus rien APRÈS."""
    client.get("/auth/login")
    before = sid(client)
    assert before is not None
    login(client)
    after = sid(client)
    assert after != before

    client.set_cookie(COOKIE, before)  # l'attaquant rejoue l'identifiant qu'il avait imposé
    assert client.get("/").status_code == 302


def test_logout_requires_post(client, alice):
    login(client)
    assert client.get("/auth/logout").status_code == 405


def test_logout_destroys_session_server_side(client, alice):
    """T06 : rejouer le cookie après déconnexion renvoie vers la connexion."""
    login(client)
    stolen = sid(client)
    assert client.get("/").status_code == 200

    resp = logout(client)
    assert resp.status_code == 302 and resp.headers["Location"] == "/auth/login"
    assert len(events("LOGOUT")) == 1

    client.set_cookie(COOKIE, stolen)
    assert client.get("/").status_code == 302


def test_post_without_csrf_token_is_rejected(client, alice):
    """T08 : un formulaire piégé sur un autre site n'a pas le jeton."""
    resp = client.post("/auth/login", data={"identifier": "alice", "password": PASSWORD})
    assert resp.status_code == 400
    assert events("LOGIN_SUCCESS") == []


def test_logout_without_csrf_token_is_rejected(client, alice):
    login(client)
    assert client.post("/auth/logout").status_code == 400
    assert client.get("/").status_code == 200  # toujours connecté


# --- Changement de mot de passe ----------------------------------------------------------------

def change(client, current=PASSWORD, new=NEW_PASSWORD, confirm=None):
    return client.post("/auth/password", data={
        "csrf_token": csrf(client, "/auth/password"),
        "current_password": current, "new_password": new,
        "confirm": new if confirm is None else confirm,
    })


def test_password_page_requires_login(client):
    assert client.get("/auth/password").status_code == 302


def test_password_change_success(client, alice):
    login(client)
    before = sid(client)
    resp = change(client)
    assert resp.status_code == 302
    assert sid(client) != before                      # session régénérée
    assert client.get("/").status_code == 200         # toujours connecté
    assert len(events("PASSWORD_CHANGE")) == 1

    logout(client)
    assert LOGIN_REFUSED.encode() in login(client, password=PASSWORD).data
    assert login(client, password=NEW_PASSWORD).status_code == 302


def test_password_change_wrong_current_refused(client, alice):
    login(client)
    old_hash = alice.password_hash
    resp = change(client, current="Pas-Le-Bon-Mot-De-Passe")
    assert "actuel incorrect".encode() in resp.data
    db.session.refresh(alice)
    assert alice.password_hash == old_hash
    assert events("PASSWORD_CHANGE")[0].outcome == "FAILURE"


def test_password_change_same_as_current_refused(client, alice):
    login(client)
    # l'apostrophe de « l'actuel » est échappée en &#39; par Jinja (anti-XSS)
    assert "doit être différent".encode() in change(client, new=PASSWORD).data


def test_password_change_policy_applies(client, alice):
    login(client)
    assert "trop courant".encode() in change(client, new="password1234").data


# --- Journal : jamais de mot de passe, chaîne intacte ------------------------------------------

def test_no_password_ever_reaches_the_audit_log(client, alice):
    login(client, password="Mauvais-Mot-De-Passe-1")
    login(client)
    change(client)
    for row in AuditLog.query.all():
        for secret in (PASSWORD, NEW_PASSWORD, "Mauvais-Mot-De-Passe-1"):
            assert secret not in (row.details or "")
    assert verify_chain().ok


# --- flask create-admin ---------------------------------------------------------------------------

def test_create_admin(app):
    result = app.test_cli_runner().invoke(
        args=["create-admin", "--username", "admin", "--email", "Admin@Agence.example"],
        input=f"{PASSWORD}\n{PASSWORD}\n",
    )
    assert result.exit_code == 0, result.output
    admin = User.query.filter_by(username="admin").one()
    assert admin.role == "admin" and admin.clearance_level == 0
    assert admin.email == "admin@agence.example"
    assert PASSWORD not in result.output  # saisie masquée, jamais réaffichée


def test_create_admin_refuses_weak_password(app):
    result = app.test_cli_runner().invoke(
        args=["create-admin", "--username", "admin", "--email", "a@agence.example"],
        input="password1234\npassword1234\n",
    )
    assert result.exit_code != 0
    assert User.query.count() == 0


def test_create_admin_refuses_duplicate(app, client, alice):
    result = app.test_cli_runner().invoke(
        args=["create-admin", "--username", "Alice", "--email", "x@agence.example"],
        input=f"{PASSWORD}\n{PASSWORD}\n",
    )
    assert result.exit_code != 0
    assert User.query.filter_by(role="admin").count() == 0


def test_admin_cannot_be_created_through_registration(client):
    client.post("/auth/register", data={
        "csrf_token": csrf(client, "/auth/register"), "username": "pirate",
        "email": "p@example.com", "password": PASSWORD, "confirm": PASSWORD,
        "role": "admin", "clearance_level": "3",  # champs ajoutés à la main (Burp)
    })
    user = User.query.filter_by(username="pirate").one()
    assert user.role == "user" and user.clearance_level == 0
