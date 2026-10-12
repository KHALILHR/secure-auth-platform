"""Injection SQL (T03) : toutes les requêtes passent par l'ORM, aucune concaténation avec une saisie."""
import pytest
from sqlalchemy import inspect

from helpers import PASSWORD, csrf_token, logged_in, make_user

from secureauth.auth.service import LOGIN_REFUSED
from secureauth.extensions import db
from secureauth.models import User

PAYLOADS = [
    "' OR '1'='1' --",
    "admin'--",
    '" OR ""="',
    "'; DROP TABLE users; --",
    "x' UNION SELECT password_hash FROM users --",
    "1; SELECT SLEEP(5)",
]


def assert_harmless(resp):
    body = resp.data.decode("utf-8", "replace").lower()
    assert resp.status_code in (200, 302, 400, 404), resp.status_code
    assert "sqlalchemy" not in body and "syntax error" not in body and "traceback" not in body


@pytest.mark.parametrize("payload", PAYLOADS)
def test_login_identifier_is_not_injectable(app, payload):
    make_user("alice")
    client = app.test_client()
    resp = client.post("/auth/login", data={"csrf_token": csrf_token(client), "identifier": payload, "password": PASSWORD})
    assert_harmless(resp)
    assert resp.status_code == 200 and LOGIN_REFUSED.encode() in resp.data  # échec normal : aucun contournement
    assert client.get("/documents/").status_code == 302                      # aucune session ouverte
    assert "users" in inspect(db.engine).get_table_names() and User.query.count() == 1


@pytest.mark.parametrize("payload", PAYLOADS)
def test_registration_fields_are_not_injectable(app, payload):
    client = app.test_client()
    resp = client.post("/auth/register", data={"csrf_token": csrf_token(client, "/auth/register"), "username": payload,
                                               "email": f"{payload}@example.com", "password": PASSWORD, "confirm": PASSWORD})
    assert_harmless(resp)
    assert User.query.count() == 0  # forme refusée avant tout accès à la base


@pytest.mark.parametrize("payload", PAYLOADS)
def test_query_strings_and_paths_are_not_injectable(app, payload):
    admin_client, _ = logged_in(app, "root", role="admin")
    for url in (f"/admin/audit?event={payload}", f"/admin/audit?page={payload}", f"/documents/{payload}"):
        assert_harmless(admin_client.get(url))
    assert "users" in inspect(db.engine).get_table_names()


def test_grant_username_is_not_injectable(app):
    from helpers import new_document, post
    alice_client, alice = logged_in(app, "alice", clearance=1)
    doc = new_document(alice, level=1)
    for payload in PAYLOADS:
        assert_harmless(post(alice_client, f"/documents/{doc.public_id}/access/grant", {"username": payload},
                             token_page=f"/documents/{doc.public_id}/access"))
    assert User.query.count() == 1
