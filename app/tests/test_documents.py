"""Espace documents : lecture, création, partage, IDOR, intégrité, XSS (T09 à T12, T16, T17, T21)."""
import uuid

from sqlalchemy import text

from helpers import events, logged_in, make_user, new_document, normalize, post

from secureauth.extensions import db
from secureauth.models import AuditLog, DocumentAccess, SecureDocument


def read(client, doc):
    return client.get(f"/documents/{doc.public_id}")


# --- Création et lecture --------------------------------------------------------------

def test_create_then_read_roundtrip(app):
    alice, _ = logged_in(app, "alice", clearance=2)
    resp = post(alice, "/documents/new", {"title": "Plan Aurore", "classification": 2, "content": "Ligne 1\nLigne 2"},
                token_page="/documents/new")
    assert resp.status_code == 302
    doc = SecureDocument.query.one()
    assert doc.reference.startswith("SEC-") and doc.classification == 2
    page = alice.get(resp.headers["Location"])
    assert page.status_code == 200
    assert b"Plan Aurore" in page.data and b"Ligne 2" in page.data
    assert events("DOC_CREATE") and events("DOC_READ")


def test_owner_gets_access_automatically(app):
    alice, user = logged_in(app, "alice", clearance=1)
    doc = new_document(user, level=1)
    entry = DocumentAccess.query.filter_by(document_id=doc.id).one()
    assert entry.user_id == user.id and entry.granted_by == user.id


def test_list_shows_only_readable_documents(app):
    alice_client, alice = logged_in(app, "alice", clearance=3)
    bob_client, bob = logged_in(app, "bob", clearance=2)
    new_document(alice, title="Ultra-secret", level=3)
    shared = new_document(alice, title="Partagé", level=2)
    new_document(bob, title="Perso de bob", level=2)
    from secureauth.documents import service
    service.grant_access(alice, bob, shared)
    page = bob_client.get("/documents/").data
    assert b"Partag" in page and b"Perso de bob" in page
    assert b"Ultra-secret" not in page
    assert b"Ultra-secret" in alice_client.get("/documents/").data


def test_anonymous_is_sent_to_login(app):
    doc = new_document(make_user("alice"), level=0)
    resp = app.test_client().get(f"/documents/{doc.public_id}")
    assert resp.status_code == 302 and "/auth/login" in resp.headers["Location"]


# --- Contrôle d'accès : 404 uniforme ----------------------------------------------------

def test_read_up_gives_404_and_is_logged(app):
    """T09 : agent SECRET vers un document TRÈS SECRET."""
    alice = make_user("alice", clearance=3)
    bob_client, bob = logged_in(app, "bob", clearance=2)
    doc = new_document(alice, level=3)
    from secureauth.documents import service
    db.session.add(DocumentAccess(document_id=doc.id, user_id=bob.id, granted_by=alice.id))  # même listé
    db.session.commit()
    assert read(bob_client, doc).status_code == 404
    denied = events("DOC_ACCESS_DENIED")
    assert len(denied) == 1 and denied[0].actor_id == bob.id and denied[0].target_id == doc.public_id


def test_need_to_know_gives_404(app):
    """T10 : habilitation suffisante, mais absent de la liste d'accès."""
    alice = make_user("alice", clearance=2)
    bob_client, _ = logged_in(app, "bob", clearance=3)
    doc = new_document(alice, level=1)
    assert read(bob_client, doc).status_code == 404
    assert len(events("DOC_ACCESS_DENIED")) == 1


def test_idor_other_document_unknown_uuid_and_garbage_all_look_the_same(app):
    """T11 : un document interdit, un UUID inexistant et un identifiant absurde donnent la même réponse."""
    alice = make_user("alice", clearance=2)
    bob_client, bob = logged_in(app, "bob", clearance=2)
    secret = new_document(alice, level=2)
    mine = new_document(bob, level=2)
    assert read(bob_client, mine).status_code == 200  # contrôle : mon propre document passe

    forbidden = read(bob_client, secret)
    unknown = bob_client.get(f"/documents/{uuid.uuid4()}")
    garbage = bob_client.get("/documents/1")
    traversal = bob_client.get("/documents/..%2F..%2Fetc%2Fpasswd")
    assert forbidden.status_code == unknown.status_code == garbage.status_code == 404
    assert traversal.status_code == 404
    assert normalize(forbidden.data) == normalize(unknown.data) == normalize(garbage.data)
    # Le refus d'un document existant est tracé ; l'identifiant inexistant ne laisse pas de ligne de refus
    assert len(events("DOC_ACCESS_DENIED")) == 1


def test_integer_ids_are_never_exposed(app):
    alice_client, alice = logged_in(app, "alice", clearance=1)
    doc = new_document(alice, level=1)
    page = alice_client.get("/documents/").data.decode()
    assert doc.public_id in page and f"/documents/{doc.id}\"" not in page


def test_admin_cannot_read_any_document(app):
    """T12 : l'administrateur gère mais ne lit pas."""
    alice = make_user("alice", clearance=3)
    admin_client, _ = logged_in(app, "root", role="admin", clearance=3)
    doc = new_document(alice, title="Confidentiel défense", level=0)
    resp = read(admin_client, doc)
    assert resp.status_code == 404 and b"Confidentiel d" not in resp.data
    assert b"Confidentiel d" not in admin_client.get("/documents/").data


# --- Création : niveau forgé -----------------------------------------------------------------

def test_forged_classification_is_refused(app):
    """T16 : le champ classification modifié dans la requête (3 pour un agent SECRET) est refusé."""
    bob_client, _ = logged_in(app, "bob", clearance=2)
    resp = post(bob_client, "/documents/new", {"title": "t", "classification": 3, "content": "c"},
                token_page="/documents/new")
    assert resp.status_code == 403
    assert SecureDocument.query.count() == 0
    assert any("au-dessus" in (e.details or "") for e in events("DOC_CREATE"))


def test_create_validates_fields(app):
    bob_client, _ = logged_in(app, "bob", clearance=1)
    for data in ({"title": "", "classification": 0, "content": "c"},
                 {"title": "t", "classification": 0, "content": ""},
                 {"title": "x" * 201, "classification": 0, "content": "c"},
                 {"title": "t", "classification": 0, "content": "x" * 20_001}):
        resp = post(bob_client, "/documents/new", data, token_page="/documents/new")
        assert resp.status_code == 200
    assert SecureDocument.query.count() == 0


def test_create_without_csrf_token_is_rejected(app):
    """T08 : POST sans jeton CSRF."""
    bob_client, _ = logged_in(app, "bob", clearance=1)
    resp = bob_client.post("/documents/new", data={"title": "t", "classification": 0, "content": "c"})
    assert resp.status_code == 400 and SecureDocument.query.count() == 0


# --- Intégrité -------------------------------------------------------------------------------------

def test_tampered_classification_blocks_decryption(app):
    """T17 : passer un document de TRÈS SECRET à PUBLIC en base ne le rend pas lisible, et l'incident est tracé."""
    alice_client, alice = logged_in(app, "alice", clearance=3)
    doc = new_document(alice, title="Contenu ultra secret", content="TEXTE-ULTRA-SECRET", level=3)
    db.session.execute(text("UPDATE secure_documents SET classification = 0 WHERE id = :id"), {"id": doc.id})
    db.session.commit()
    resp = read(alice_client, doc)
    assert resp.status_code == 500
    assert b"TEXTE-ULTRA-SECRET" not in resp.data and b"Contenu ultra secret" not in resp.data
    assert len(events("INTEGRITY_FAILURE")) == 1


def test_tampered_ciphertext_flagged_in_list(app):
    alice_client, alice = logged_in(app, "alice", clearance=1)
    doc = new_document(alice, title="Titre original", level=1)
    db.session.execute(text("UPDATE secure_documents SET nonce = :n WHERE id = :id"), {"n": b"\x00" * 12, "id": doc.id})
    db.session.commit()
    page = alice_client.get("/documents/").data
    assert b"Titre original" not in page and "Intégrité compromise".encode() in page
    assert events("INTEGRITY_FAILURE")


# --- XSS -----------------------------------------------------------------------------------------------

def test_stored_xss_is_escaped_everywhere(app):
    """T21 : un titre ou un contenu avec balisage actif s'affiche comme du texte."""
    alice_client, alice = logged_in(app, "alice", clearance=0)
    payload = "<script>alert(1)</script><img src=x onerror=alert(2)>"
    doc = new_document(alice, title=payload, content=payload, level=0)
    for url in (f"/documents/{doc.public_id}", "/documents/"):
        html = alice_client.get(url).data.decode()
        assert "<script>alert(1)</script>" not in html and "<img src=x" not in html
        assert "&lt;script&gt;" in html


# --- Partage ----------------------------------------------------------------------------------------------

def test_owner_grants_then_revokes_access(app):
    alice_client, alice = logged_in(app, "alice", clearance=2)
    bob_client, bob = logged_in(app, "bob", clearance=2)
    doc = new_document(alice, level=2)
    assert read(bob_client, doc).status_code == 404

    resp = post(alice_client, f"/documents/{doc.public_id}/access/grant", {"username": "bob"},
                token_page=f"/documents/{doc.public_id}/access")
    assert resp.status_code == 302
    assert read(bob_client, doc).status_code == 200
    assert events("ACCESS_GRANT")

    resp = post(alice_client, f"/documents/{doc.public_id}/access/revoke", {"user_id": bob.id},
                token_page=f"/documents/{doc.public_id}/access")
    assert resp.status_code == 302
    assert read(bob_client, doc).status_code == 404
    assert events("ACCESS_REVOKE")


def test_grant_to_insufficiently_cleared_agent_is_refused(app):
    """Le partage vers un agent insuffisamment habilité est refusé et tracé (scénario de démonstration n°4)."""
    alice_client, alice = logged_in(app, "alice", clearance=3)
    bob = make_user("bob", clearance=2)
    doc = new_document(alice, level=3)
    post(alice_client, f"/documents/{doc.public_id}/access/grant", {"username": "bob"},
         token_page=f"/documents/{doc.public_id}/access")
    assert DocumentAccess.query.filter_by(document_id=doc.id, user_id=bob.id).first() is None
    denied = [e for e in events("ACCESS_GRANT") if e.outcome == "DENIED"]
    assert denied and "insuffisante" in denied[0].details


def test_owner_cannot_remove_own_access(app):
    alice_client, alice = logged_in(app, "alice", clearance=1)
    doc = new_document(alice, level=1)
    post(alice_client, f"/documents/{doc.public_id}/access/revoke", {"user_id": alice.id},
         token_page=f"/documents/{doc.public_id}/access")
    assert read(alice_client, doc).status_code == 200


def test_stranger_cannot_manage_access(app):
    alice = make_user("alice", clearance=1)
    eve_client, eve = logged_in(app, "eve", clearance=3)
    doc = new_document(alice, level=1)
    assert eve_client.get(f"/documents/{doc.public_id}/access").status_code == 404
    resp = post(eve_client, f"/documents/{doc.public_id}/access/grant", {"username": "eve"})
    assert resp.status_code == 404
    assert DocumentAccess.query.filter_by(user_id=eve.id).first() is None


def test_admin_manages_access_without_reading(app):
    alice = make_user("alice", clearance=2)
    bob = make_user("bob", clearance=2)
    admin_client, admin = logged_in(app, "root", role="admin")
    doc = new_document(alice, title="Titre invisible", level=2)
    page = admin_client.get(f"/documents/{doc.public_id}/access")
    assert page.status_code == 200 and b"Titre invisible" not in page.data
    post(admin_client, f"/documents/{doc.public_id}/access/grant", {"username": "bob"},
         token_page=f"/documents/{doc.public_id}/access")
    assert DocumentAccess.query.filter_by(document_id=doc.id, user_id=bob.id).first() is not None
    assert read(admin_client, doc).status_code == 404  # il a géré l'accès des autres, il ne lit toujours pas


def test_admin_cannot_grant_himself_access(app):
    """T13 : l'administrateur s'attribue un accès, refusé et tracé ADMIN_SELF_MODIFY_DENIED."""
    alice = make_user("alice", clearance=0)
    admin_client, admin = logged_in(app, "root", role="admin")
    doc = new_document(alice, level=0)
    post(admin_client, f"/documents/{doc.public_id}/access/grant", {"username": "root"},
         token_page=f"/documents/{doc.public_id}/access")
    assert DocumentAccess.query.filter_by(user_id=admin.id).first() is None
    assert len(events("ADMIN_SELF_MODIFY_DENIED")) == 1
    assert read(admin_client, doc).status_code == 404


# --- Journal et en-têtes ------------------------------------------------------------------------------------

def test_no_document_content_ever_reaches_the_audit_log(app):
    """ES-12 : ni titre, ni contenu, ni clé dans le journal."""
    alice_client, alice = logged_in(app, "alice", clearance=2)
    bob_client, bob = logged_in(app, "bob", clearance=0)
    doc = new_document(alice, title="TITRE-A-NE-JAMAIS-JOURNALISER", content="CONTENU-A-NE-JAMAIS-JOURNALISER", level=2)
    read(alice_client, doc)
    read(bob_client, doc)
    dump = " ".join(f"{r.details} {r.event} {r.target_id}" for r in AuditLog.query.all())
    assert "JAMAIS-JOURNALISER" not in dump
    assert doc.reference in dump  # la référence, elle, est non sensible


def test_authenticated_pages_are_not_cached(app):
    alice_client, alice = logged_in(app, "alice", clearance=0)
    doc = new_document(alice, level=0)
    assert read(alice_client, doc).headers["Cache-Control"] == "no-store"


def test_read_page_shows_classification_banner(app):
    alice_client, alice = logged_in(app, "alice", clearance=3)
    doc = new_document(alice, level=3)
    html = read(alice_client, doc).data.decode()
    assert html.count("classification-banner level-3") == 2  # bandeau haut et bas
    assert "TRÈS SECRET" in html


def test_temporary_reference_fits_the_database_column(app):
    """Régression trouvée sur MariaDB (« Data too long for column reference ») : SQLite n'impose pas la longueur."""
    from secureauth.documents.service import temporary_reference
    from secureauth.models import new_public_id
    limit = SecureDocument.reference.type.length
    assert limit == 32
    assert len(temporary_reference(new_public_id())) <= limit
    assert temporary_reference("00000000-0000-4000-8000-000000000000") != temporary_reference(new_public_id())


def test_document_references_are_unique_and_fit_the_column(app):
    alice = make_user("alice", clearance=3)
    refs = {new_document(alice, level=lvl).reference for lvl in (0, 1, 2, 3, 3, 2)}
    assert len(refs) == 6 and all(len(r) <= 32 for r in refs)
