"""Espace administrateur : accès, habilitations, activation, journal, vérification (T08, T13 à T15, T19)."""
from sqlalchemy import text

from helpers import events, logged_in, make_user, new_document, post

from secureauth.extensions import db
from secureauth.models import AuditLog, User
from secureauth.security import audit

ADMIN_GET = ["/admin/", "/admin/users", "/admin/documents", "/admin/audit", "/admin/audit/verify"]


# --- Qui peut entrer -------------------------------------------------------------------------------

def test_agent_gets_403_on_every_admin_route(app):
    """T14 : un agent appelle chaque route /admin/*."""
    agent_client, _ = logged_in(app, "alice", clearance=3)
    victim = make_user("bob")
    for url in ADMIN_GET:
        assert agent_client.get(url).status_code == 403, url
    for url, data in ((f"/admin/users/{victim.id}/clearance", {"level": 3}),
                      (f"/admin/users/{victim.id}/active", {}),
                      ("/admin/audit/verify", {})):
        assert post(agent_client, url, data).status_code == 403, url
    assert db.session.get(User, victim.id).clearance_level == 0


def test_anonymous_is_redirected_to_login(app):
    client = app.test_client()
    for url in ADMIN_GET:
        resp = client.get(url)
        assert resp.status_code == 302 and "/auth/login" in resp.headers["Location"], url


def test_admin_pages_render(app):
    admin_client, _ = logged_in(app, "root", role="admin")
    make_user("alice", clearance=2)
    for url in ADMIN_GET:
        assert admin_client.get(url).status_code == 200, url
    assert b"alice" in admin_client.get("/admin/users").data


def test_admin_post_without_csrf_is_rejected(app):
    """T08 : action d'administration sans jeton CSRF."""
    admin_client, _ = logged_in(app, "root", role="admin")
    victim = make_user("bob")
    resp = admin_client.post(f"/admin/users/{victim.id}/clearance", data={"level": 3})
    assert resp.status_code == 400
    assert db.session.get(User, victim.id).clearance_level == 0


# --- Habilitations ---------------------------------------------------------------------------------------

def test_clearance_change_is_logged_and_immediate(app):
    """T15 : l'habilitation baisse, l'accès est perdu à la requête suivante, sans reconnexion."""
    alice = make_user("alice", clearance=3)
    bob_client, bob = logged_in(app, "bob", clearance=2)
    admin_client, _ = logged_in(app, "root", role="admin")
    doc = new_document(alice, level=2)
    from secureauth.documents import service
    service.grant_access(alice, bob, doc)
    assert bob_client.get(f"/documents/{doc.public_id}").status_code == 200

    resp = post(admin_client, f"/admin/users/{bob.id}/clearance", {"level": 1}, token_page="/admin/users")
    assert resp.status_code == 302
    assert bob_client.get(f"/documents/{doc.public_id}").status_code == 404  # même session, accès perdu
    log = events("CLEARANCE_CHANGE")
    assert len(log) == 1 and "SECRET -> CONFIDENTIEL" in log[0].details


def test_admin_cannot_modify_own_clearance_or_status(app):
    """T13 : l'administrateur modifie sa propre habilitation ou désactive son propre compte."""
    admin_client, admin = logged_in(app, "root", role="admin")
    post(admin_client, f"/admin/users/{admin.id}/clearance", {"level": 3}, token_page="/admin/users")
    post(admin_client, f"/admin/users/{admin.id}/active", {}, token_page="/admin/users")
    db.session.refresh(admin)
    assert admin.clearance_level == 0 and admin.is_active
    assert len(events("ADMIN_SELF_MODIFY_DENIED")) == 2
    assert not events("CLEARANCE_CHANGE")


def test_invalid_clearance_is_refused(app):
    admin_client, _ = logged_in(app, "root", role="admin")
    bob = make_user("bob")
    for level in (4, -1, 99, "abc", ""):
        post(admin_client, f"/admin/users/{bob.id}/clearance", {"level": level}, token_page="/admin/users")
    assert db.session.get(User, bob.id).clearance_level == 0
    assert not events("CLEARANCE_CHANGE")


def test_unknown_user_gives_404(app):
    admin_client, _ = logged_in(app, "root", role="admin")
    assert post(admin_client, "/admin/users/9999/clearance", {"level": 1}, token_page="/admin/users").status_code == 404


# --- Activation -------------------------------------------------------------------------------------------------

def test_disable_account_cuts_the_open_session_then_enable(app):
    bob_client, bob = logged_in(app, "bob", clearance=1)
    admin_client, _ = logged_in(app, "root", role="admin")
    assert bob_client.get("/documents/").status_code == 200

    post(admin_client, f"/admin/users/{bob.id}/active", {}, token_page="/admin/users")  # case décochée = désactiver
    assert bob_client.get("/documents/").status_code == 302  # session détruite à la requête suivante
    assert events("ACCOUNT_DISABLE")

    post(admin_client, f"/admin/users/{bob.id}/active", {"active": "y"}, token_page="/admin/users")
    assert events("ACCOUNT_ENABLE")
    assert db.session.get(User, bob.id).is_active


# --- Documents (métadonnées) ----------------------------------------------------------------------------------------

def test_admin_sees_metadata_but_never_titles(app):
    alice = make_user("alice", clearance=3)
    admin_client, _ = logged_in(app, "root", role="admin")
    new_document(alice, title="TITRE-CONFIDENTIEL", content="CORPS", level=3, reference="TS-001")
    page = admin_client.get("/admin/documents").data
    assert b"TS-001" in page and b"alice" in page
    assert b"TITRE-CONFIDENTIEL" not in page and b"CORPS" not in page


# --- Journal ---------------------------------------------------------------------------------------------------------------

def test_audit_page_is_paginated_and_filterable(app):
    admin_client, admin = logged_in(app, "root", role="admin")
    for i in range(60):
        audit.log_event("LOGIN_FAILURE", "FAILURE", details=f"essai {i}")
    page1 = admin_client.get("/admin/audit").data.decode()
    assert "Page 1 sur 2" in page1 and page1.count("LOGIN_FAILURE</td>") == 50
    page2 = admin_client.get("/admin/audit?page=2").data.decode()
    assert "Page 2 sur 2" in page2
    only_login = admin_client.get("/admin/audit?event=LOGIN_SUCCESS").data.decode()
    assert "LOGIN_FAILURE</td>" not in only_login and "LOGIN_SUCCESS</td>" in only_login
    ignored = admin_client.get("/admin/audit?event=' OR 1=1 --")
    assert ignored.status_code == 200  # filtre inconnu : ignoré, pas d'erreur SQL


def test_verify_page_reports_intact_chain_and_logs_itself(app):
    admin_client, admin = logged_in(app, "root", role="admin")
    resp = post(admin_client, "/admin/audit/verify", {}, token_page="/admin/audit/verify")
    assert resp.status_code == 200 and "Chaîne intègre" in resp.data.decode()
    assert events("AUDIT_VERIFY")[-1].outcome == "SUCCESS"


def test_verify_page_designates_the_tampered_line(app):
    """T19 : une ligne modifiée directement en base est désignée par la page d'administration."""
    admin_client, admin = logged_in(app, "root", role="admin")
    target = audit.log_event("REGISTER", "SUCCESS", actor_id=None, details="origine")
    db.session.execute(text("UPDATE audit_logs SET details = 'falsifié' WHERE id = :id"), {"id": target.id})
    db.session.commit()
    html = post(admin_client, "/admin/audit/verify", {}, token_page="/admin/audit/verify").data.decode()
    assert "Chaîne corrompue" in html and f">{target.id}<" in html
    assert events("AUDIT_VERIFY")[-1].outcome == "FAILURE"


def test_verify_page_detects_deleted_line(app):
    """T20 : suppression d'une ligne au milieu du journal."""
    admin_client, _ = logged_in(app, "root", role="admin")
    ids = [audit.log_event("LOGIN_FAILURE", "FAILURE", details=str(i)).id for i in range(4)]
    db.session.execute(text("DELETE FROM audit_logs WHERE id = :id"), {"id": ids[1]})
    db.session.commit()
    html = post(admin_client, "/admin/audit/verify", {}, token_page="/admin/audit/verify").data.decode()
    assert "Chaîne corrompue" in html
