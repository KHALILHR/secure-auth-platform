"""Outils communs aux tests de la semaine 3 : comptes, connexion réelle (CSRF actif), documents."""
import re

from secureauth.documents import service as documents
from secureauth.extensions import db
from secureauth.models import AuditLog, User
from secureauth.security.passwords import hash_password

PASSWORD = "Cheval-Agrafe-Lune-42"
COOKIE = "__Host-sid"


def make_user(username, *, role="user", clearance=0, active=True):
    """Crée un compte directement en base et le retourne (rôle et habilitation au choix)."""
    user = User(
        username=username,
        email=f"{username}@example.com",
        password_hash=hash_password(PASSWORD),
        role=role,
        clearance_level=clearance,
        is_active=active,
    )
    db.session.add(user)
    db.session.commit()
    return user


def csrf_token(client, url="/auth/login"):
    html = client.get(url).data.decode()
    match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)
    assert match, f"pas de jeton CSRF sur {url}"
    return match.group(1)


def login(client, username, password=PASSWORD):
    """Connexion par le vrai formulaire (le jeton CSRF reste exigé)."""
    resp = client.post("/auth/login", data={
        "csrf_token": csrf_token(client, "/auth/login"),
        "identifier": username, "password": password,
    })
    return resp


def logged_in(app, username, **kwargs):
    """Crée l'utilisateur, ouvre son navigateur (client) connecté, et retourne (client, user)."""
    user = make_user(username, **kwargs)
    client = app.test_client()
    resp = login(client, username)
    assert resp.status_code == 302, "la connexion de test a échoué"
    return client, user


def post(client, url, data=None, token_page="/"):
    """POST avec jeton CSRF valide (lu sur une page où il apparaît dans un formulaire)."""
    payload = dict(data or {})
    payload["csrf_token"] = csrf_token(client, token_page)
    return client.post(url, data=payload)


def new_document(owner, title="Titre confidentiel", content="Contenu confidentiel", level=0, reference=None):
    return documents.create_document(owner, title, content, level, reference=reference)


def events(name):
    return AuditLog.query.filter_by(event=name).all()


def normalize(html: bytes) -> str:
    """Masque le jeton CSRF (il change à chaque requête) pour comparer deux pages."""
    return re.sub(r'value="[A-Za-z0-9_.\-]{40,}"', 'value="TOKEN"', html.decode())
