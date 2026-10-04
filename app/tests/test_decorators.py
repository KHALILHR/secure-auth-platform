"""login_required, role_required et le rechargement de g.user depuis la base (plan §5.2-5.3)."""
from datetime import datetime, timedelta, timezone

import pytest
from flask import g

from secureauth import ABSOLUTE_SESSION_LIFETIME
from secureauth.extensions import db
from secureauth.models import User
from secureauth.security.decorators import login_required, role_required
from secureauth.security.passwords import hash_password


@pytest.fixture
def declare_probe_routes(app):
    """Deux routes jetables, juste pour observer le comportement des décorateurs."""

    @app.route("/_probe/membre")
    @login_required
    def probe_membre():
        return f"bonjour {g.user.username}"

    @app.route("/_probe/admin")
    @role_required("admin")
    def probe_admin():
        return "zone admin"

    return app


def _make_user(role="user", clearance=0, active=True):
    """Crée un utilisateur et retourne son id (pas l'objet : il serait détaché
    de la session dès la sortie du `with app.app_context()` de l'appelant)."""
    user = User(
        username="alice",
        email="alice@example.com",
        password_hash=hash_password("Cheval-Agrafe-Lune-42"),
        role=role,
        clearance_level=clearance,
        is_active=active,
    )
    db.session.add(user)
    db.session.commit()
    return user.id


def _login(client, user_id, auth_time=None):
    with client.session_transaction() as sess:
        sess["user_id"] = user_id
        sess["auth_time"] = auth_time or datetime.now(timezone.utc)


# --- login_required --------------------------------------------------------------

def test_anonymous_is_redirected_to_login(declare_probe_routes, client):
    resp = client.get("/_probe/membre")
    assert resp.status_code == 302
    assert "/auth/login" in resp.headers["Location"]


def test_logged_in_user_passes(declare_probe_routes, app, client):
    with app.app_context():
        user_id = _make_user()
    _login(client, user_id)
    resp = client.get("/_probe/membre")
    assert resp.status_code == 200
    assert b"bonjour alice" in resp.data


def test_redirect_preserves_next_url(declare_probe_routes, client):
    resp = client.get("/_probe/membre")
    assert resp.headers["Location"] == "/auth/login?next=/_probe/membre"


# --- role_required -----------------------------------------------------------------

def test_role_required_rejects_anonymous_with_redirect(declare_probe_routes, client):
    resp = client.get("/_probe/admin")
    assert resp.status_code == 302


def test_role_required_rejects_wrong_role_with_403(declare_probe_routes, app, client):
    with app.app_context():
        user_id = _make_user(role="user")
    _login(client, user_id)
    resp = client.get("/_probe/admin")
    assert resp.status_code == 403


def test_role_required_accepts_matching_role(declare_probe_routes, app, client):
    with app.app_context():
        admin_id = _make_user(role="admin")
    _login(client, admin_id)
    resp = client.get("/_probe/admin")
    assert resp.status_code == 200


# --- g.user rechargé depuis la base, pas depuis le cookie -------------------------

def test_disabled_account_loses_access_immediately(declare_probe_routes, app, client):
    """Le cookie de session reste valide, mais le compte est désactivé entre-temps."""
    with app.app_context():
        user_id = _make_user(active=True)
    _login(client, user_id)
    assert client.get("/_probe/membre").status_code == 200

    with app.app_context():
        db.session.get(User, user_id).is_active = False
        db.session.commit()

    resp = client.get("/_probe/membre")
    assert resp.status_code == 302  # session détruite, comme si jamais connecté


def test_clearance_change_is_visible_on_next_request(declare_probe_routes, app, client):
    @app.route("/_probe/clearance")
    def probe_clearance():
        return str(g.user.clearance_level) if g.user else "anonyme"

    with app.app_context():
        user_id = _make_user(clearance=1)
    _login(client, user_id)
    assert client.get("/_probe/clearance").data == b"1"

    with app.app_context():
        db.session.get(User, user_id).clearance_level = 3
        db.session.commit()

    assert client.get("/_probe/clearance").data == b"3"


def test_deleted_user_clears_session(declare_probe_routes, app, client):
    with app.app_context():
        user_id = _make_user()
    _login(client, user_id)

    with app.app_context():
        db.session.delete(db.session.get(User, user_id))
        db.session.commit()

    resp = client.get("/_probe/membre")
    assert resp.status_code == 302


def test_session_without_auth_time_is_rejected(declare_probe_routes, app, client):
    with app.app_context():
        user_id = _make_user()
    with client.session_transaction() as sess:
        sess["user_id"] = user_id  # pas de auth_time : session malformée / ancienne
    resp = client.get("/_probe/membre")
    assert resp.status_code == 302


def test_session_beyond_absolute_lifetime_is_rejected(declare_probe_routes, app, client):
    with app.app_context():
        user_id = _make_user()
    too_old = datetime.now(timezone.utc) - ABSOLUTE_SESSION_LIFETIME - timedelta(minutes=1)
    _login(client, user_id, auth_time=too_old)
    resp = client.get("/_probe/membre")
    assert resp.status_code == 302


def test_session_just_under_absolute_lifetime_is_accepted(declare_probe_routes, app, client):
    with app.app_context():
        user_id = _make_user()
    still_valid = datetime.now(timezone.utc) - ABSOLUTE_SESSION_LIFETIME + timedelta(minutes=1)
    _login(client, user_id, auth_time=still_valid)
    resp = client.get("/_probe/membre")
    assert resp.status_code == 200


def test_unknown_user_id_in_session_is_rejected(declare_probe_routes, app, client):
    _login(client, 999999)  # identifiant qui n'existe pas en base
    resp = client.get("/_probe/membre")
    assert resp.status_code == 302


# --- Pages d'erreur ------------------------------------------------------------------

def test_404_page_does_not_leak_internals(app, client):
    resp = client.get("/cette-route-n-existe-pas")
    assert resp.status_code == 404
    assert b"Traceback" not in resp.data


def test_templates_have_no_inline_style_or_script():
    """CSP stricte : aucun attribut style= ni balise <script> inline dans les gabarits."""
    import pathlib
    import re

    templates = pathlib.Path(__file__).parent.parent / "secureauth" / "templates"
    for path in templates.rglob("*.html"):
        html = path.read_text(encoding="utf-8")
        assert not re.search(r"\sstyle\s*=", html), f"style inline dans {path.name}"
        assert not re.search(r"<script(?![^>]*\bsrc=)", html), f"script inline dans {path.name}"


def test_logged_in_page_contains_csrf_hidden_field(declare_probe_routes, app, client):
    @app.route("/_probe/page")
    @login_required
    def probe_page():
        from flask import render_template
        return render_template("base.html")

    with app.app_context():
        user_id = _make_user()
    _login(client, user_id)
    html = client.get("/_probe/page").data.decode()
    assert '<input type="hidden" name="csrf_token" value="' in html


def test_403_page_is_rendered(declare_probe_routes, app, client):
    with app.app_context():
        user_id = _make_user(role="user")
    _login(client, user_id)
    resp = client.get("/_probe/admin")
    assert resp.status_code == 403
    assert "403".encode() in resp.data
