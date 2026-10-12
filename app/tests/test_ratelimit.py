"""Limitation de débit par adresse IP : HTTP 429 après le seuil (T25, EF-06 complété, semaine 5)."""
import fakeredis
import pytest

from conftest import IsolatedClient
from helpers import csrf_token

from secureauth import create_app
from secureauth.extensions import db
from secureauth.security.audit import ensure_chain_head


@pytest.fixture
def limited_app():
    """Application avec la limitation ACTIVE et des seuils bas (les autres tests la désactivent)."""
    app = create_app({
        "TESTING": True,
        "SESSION_REDIS": fakeredis.FakeRedis(),
        "SQLALCHEMY_ENGINE_OPTIONS": {},
        "RATELIMIT_ENABLED": True,
        "RATELIMIT_STORAGE_URI": "memory://",
        "LOGIN_RATE_LIMIT": "4 per minute",
        "REGISTER_RATE_LIMIT": "3 per hour",
        "PASSWORD_RATE_LIMIT": "2 per hour",
    })
    app.test_client_class = IsolatedClient  # un contexte par requête, comme en production
    with app.app_context():
        db.create_all()
        ensure_chain_head()
        yield app
        db.session.remove()
        db.drop_all()


def attempt_login(client, username="ghost"):
    return client.post("/auth/login", data={"csrf_token": csrf_token(client), "identifier": username, "password": "x" * 12})


def test_burst_of_logins_gets_429_after_threshold(limited_app):
    """T25 : une rafale de connexions (Burp Intruder) est stoppée net."""
    client = limited_app.test_client()
    codes = [attempt_login(client).status_code for _ in range(7)]
    assert codes[:4] == [200, 200, 200, 200]
    assert codes[4:] == [429, 429, 429]


def test_429_page_is_generic(limited_app):
    client = limited_app.test_client()
    for _ in range(4):
        attempt_login(client)
    resp = attempt_login(client)
    assert resp.status_code == 429
    html = resp.data.decode()
    assert "Trop de requêtes" in html and "Traceback" not in html


def test_limit_applies_per_ip_not_per_account(limited_app):
    """Changer de nom d'utilisateur ne contourne pas la limite (sinon, énumération en rafale)."""
    client = limited_app.test_client()
    codes = [attempt_login(client, f"user{i}").status_code for i in range(6)]
    assert 429 in codes


def test_get_pages_are_not_limited(limited_app):
    client = limited_app.test_client()
    assert all(client.get("/auth/login").status_code == 200 for _ in range(30))


def test_registration_is_limited(limited_app):
    client = limited_app.test_client()
    codes = []
    for i in range(5):
        codes.append(client.post("/auth/register", data={
            "csrf_token": csrf_token(client, "/auth/register"), "username": f"user{i}",
            "email": f"user{i}@example.com", "password": "Cheval-Agrafe-Lune-42", "confirm": "Cheval-Agrafe-Lune-42",
        }).status_code)
    assert codes[:3] == [302, 302, 302] and codes[3:] == [429, 429]


def test_other_ip_is_not_penalised(limited_app):
    """Un autre client (autre adresse IP) garde son quota intact."""
    client = limited_app.test_client()
    for _ in range(5):
        attempt_login(client)
    other = limited_app.test_client()
    resp = other.post("/auth/login", data={"csrf_token": csrf_token(other), "identifier": "ghost", "password": "x" * 12},
                      environ_overrides={"REMOTE_ADDR": "203.0.113.9"})
    assert resp.status_code == 200
