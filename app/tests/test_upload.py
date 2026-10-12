"""Dépôt de fichiers PDF, DOC et DOCX : validation, chiffrement, téléchargement, droits, intégrité."""
import io
import zipfile

import pytest
from sqlalchemy import text

from helpers import csrf_token, events, logged_in, make_user, post

from secureauth.documents import service, uploads
from secureauth.extensions import db
from secureauth.models import AuditLog, SecureDocument
from secureauth.security import crypto

MARKER = b"CONTENU-TRES-SECRET-9f3a"


def make_pdf(size=600):
    return b"%PDF-1.4\n" + MARKER + b"\n" + b"A" * size + b"\n%%EOF"


def make_doc():
    return uploads.OLE_SIGNATURE + MARKER + b"\x00" * 600


def make_docx():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("word/document.xml", "<w:document/>" + MARKER.decode())
    return buffer.getvalue()


def upload(client, data, name="plan-aurore.pdf", *, level=0, title="", content=""):
    return client.post("/documents/upload", data={
        "csrf_token": csrf_token(client, "/documents/upload"),
        "classification": level, "title": title, "content": content,
        "file": (io.BytesIO(data), name),
    }, content_type="multipart/form-data")


def stored():
    return SecureDocument.query.one()


# --- Dépôt réussi ------------------------------------------------------------------------------------

@pytest.mark.parametrize("name, builder, mime", [
    ("plan-aurore.pdf", make_pdf, "application/pdf"),
    ("note.doc", make_doc, "application/msword"),
    ("rapport.docx", make_docx, "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
])
def test_upload_then_download_returns_the_same_bytes(app, name, builder, mime):
    alice, _ = logged_in(app, "alice", clearance=2)
    original = builder()
    resp = upload(alice, original, name, level=2, title="Dossier Aurore")
    assert resp.status_code == 302
    doc = stored()
    assert doc.has_file and doc.file_size == len(original) and doc.classification == 2

    page = alice.get(resp.headers["Location"])
    assert page.status_code == 200 and name.encode() in page.data and b"Dossier Aurore" in page.data

    download = alice.get(f"/documents/{doc.public_id}/download")
    assert download.status_code == 200
    assert download.data == original
    assert download.mimetype == mime
    assert download.headers["Content-Disposition"].startswith("attachment")
    assert name in download.headers["Content-Disposition"]
    assert download.headers["Cache-Control"] == "no-store"


def test_file_and_filename_are_encrypted_in_database(app):
    alice, _ = logged_in(app, "alice", clearance=1)
    upload(alice, make_pdf(), "plan-aurore.pdf", level=1, title="Titre secret")
    doc = stored()
    for blob in (doc.ciphertext, doc.file_ciphertext):
        assert MARKER not in blob
        assert b"plan-aurore" not in blob
        assert b"Titre secret" not in blob
    raw = db.session.execute(text("SELECT file_ciphertext FROM secure_documents")).scalar()
    assert MARKER not in raw and doc.file_nonce != doc.nonce


def test_title_defaults_to_the_file_name(app):
    alice, _ = logged_in(app, "alice")
    upload(alice, make_pdf(), "Charte du système.pdf")
    page = alice.get("/documents/")
    assert "Charte du système".encode() in page.data and b"tag-file" in page.data


def test_upload_is_audited_without_name_or_content(app):
    alice, _ = logged_in(app, "alice", clearance=1)
    upload(alice, make_pdf(), "plan-aurore.pdf", level=1, title="Titre secret")
    detail = events("DOC_CREATE")[0].details
    assert "pdf" in detail and "octets" in detail
    for row in AuditLog.query.all():
        text_ = f"{row.details or ''}{row.target_id or ''}"
        assert "plan-aurore" not in text_ and "Titre secret" not in text_ and MARKER.decode() not in text_


def test_upload_button_is_on_the_documents_page(app):
    alice, _ = logged_in(app, "alice")
    page = alice.get("/documents/")
    assert b"/documents/upload" in page.data and "Déposer un fichier".encode() in page.data
    form = alice.get("/documents/upload")
    assert form.status_code == 200 and b'type="file"' in form.data and b"multipart/form-data" in form.data


# --- Fichiers refusés ------------------------------------------------------------------------------------

@pytest.mark.parametrize("name, data", [
    ("virus.exe", b"MZ" + b"\x00" * 600),
    ("page.html", b"<script>alert(1)</script>"),
    ("archive.zip", make_docx()),
    ("sans-extension", make_pdf()),
    ("faux.pdf", b"ceci n'est pas un pdf du tout"),
    ("faux.docx", b"PK\x03\x04 pas une archive valide"),
    ("faux.doc", make_pdf()),
    ("vide.pdf", b""),
])
def test_invalid_uploads_are_refused_and_logged(app, name, data):
    alice, _ = logged_in(app, "alice", clearance=1)
    resp = upload(alice, data, name)
    assert resp.status_code == 400
    assert SecureDocument.query.count() == 0
    refused = [row for row in events("DOC_CREATE") if row.outcome == "FAILURE"]
    assert len(refused) == 1 and "fichier refusé" in refused[0].details


def test_a_zip_that_is_not_a_word_file_is_refused(app):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("readme.txt", "bonjour")
    alice, _ = logged_in(app, "alice")
    assert upload(alice, buffer.getvalue(), "faux.docx").status_code == 400
    assert SecureDocument.query.count() == 0


def test_file_over_the_limit_is_refused(app):
    alice, _ = logged_in(app, "alice")
    too_big = b"%PDF-1.4\n" + b"A" * uploads.UPLOAD_MAX_BYTES
    resp = upload(alice, too_big, "gros.pdf")
    assert resp.status_code == 400 and b"volumineux" in resp.data
    assert SecureDocument.query.count() == 0


def test_file_between_2_and_8_mb_is_accepted(app):
    """La limite de 2 Mo des formulaires est relevée pour cette seule page."""
    alice, _ = logged_in(app, "alice")
    big = b"%PDF-1.4\n" + b"A" * (3 * 1024 * 1024)
    assert upload(alice, big, "moyen.pdf").status_code == 302
    assert stored().file_size == len(big)


def test_request_far_over_the_limit_gets_413(app):
    alice, _ = logged_in(app, "alice")
    assert upload(alice, b"%PDF-" + b"A" * (uploads.REQUEST_MAX_BYTES + 1024), "enorme.pdf").status_code == 413
    assert SecureDocument.query.count() == 0


def test_large_bodies_are_still_refused_on_every_other_page(app):
    """La limite relevée ne vaut que pour la page de dépôt : ailleurs, 2 Mo."""
    alice, _ = logged_in(app, "alice")
    for url in ("/documents/new", "/auth/password", "/documents/00000000-0000-4000-8000-000000000000/access/grant"):
        resp = alice.post(url, data={"file": (io.BytesIO(b"A" * (3 * 1024 * 1024)), "x.bin")},
                          content_type="multipart/form-data")
        assert resp.status_code == 413, url


def test_missing_file_is_a_form_error(app):
    alice, _ = logged_in(app, "alice")
    resp = alice.post("/documents/upload", data={"csrf_token": csrf_token(alice, "/documents/upload"),
                                                 "classification": 0}, content_type="multipart/form-data")
    assert resp.status_code == 200 and b"Choisissez un fichier" in resp.data
    assert SecureDocument.query.count() == 0


def test_upload_without_csrf_token_is_rejected(app):
    alice, _ = logged_in(app, "alice")
    resp = alice.post("/documents/upload", data={"classification": 0, "file": (io.BytesIO(make_pdf()), "a.pdf")},
                      content_type="multipart/form-data")
    assert resp.status_code == 400 and SecureDocument.query.count() == 0


def test_anonymous_cannot_upload_or_download(app):
    client = app.test_client()
    assert client.get("/documents/upload").status_code == 302
    assert client.get("/documents/00000000-0000-4000-8000-000000000000/download").status_code == 302


# --- Noms de fichier hostiles --------------------------------------------------------------------------

@pytest.mark.parametrize("raw, expected", [
    ("../../etc/passwd.pdf", "passwd.pdf"),
    ("..\\..\\windows\\system32\\a.docx", "a.docx"),
    ('x"; filename=evil.exe.pdf', "x__ filename_evil.exe.pdf"),
    ("ligne\r\nSet-Cookie: a=b.pdf", "ligne__Set-Cookie_ a_b.pdf"),
    ("  .pdf", "pdf"),
])
def test_filenames_are_sanitised(raw, expected):
    assert uploads.clean_filename(raw) == expected


def test_hostile_filename_cannot_inject_headers(app):
    """Même si un nom hostile était déjà en base (le client de test ne sait pas l'envoyer en multipart)."""
    alice, owner = logged_in(app, "alice")
    doc = service.create_document(owner, "t", "c", 0, filename='x"\r\nSet-Cookie: pwn=1.pdf', file_bytes=make_pdf())
    db.session.commit()
    download = alice.get(f"/documents/{doc.public_id}/download")
    assert download.status_code == 200
    assert not [value for key, value in download.headers if key == "Set-Cookie" and "pwn" in value]
    disposition = download.headers["Content-Disposition"]
    assert "\r" not in disposition and "\n" not in disposition and disposition.startswith("attachment")


def test_a_quote_in_a_stored_name_is_neutralised_on_download(app):
    alice, owner = logged_in(app, "alice")
    doc = service.create_document(owner, "t", "c", 0, filename='a"b;c.pdf', file_bytes=make_pdf())
    db.session.commit()
    disposition = alice.get(f"/documents/{doc.public_id}/download").headers["Content-Disposition"]
    assert "a_b_c.pdf" in disposition and 'a"b' not in disposition


def test_client_mime_type_is_ignored(app):
    alice, _ = logged_in(app, "alice")
    resp = alice.post("/documents/upload", data={
        "csrf_token": csrf_token(alice, "/documents/upload"), "classification": 0,
        "file": (io.BytesIO(make_pdf()), "a.pdf", "text/html"),
    }, content_type="multipart/form-data")
    assert resp.status_code == 302
    assert alice.get(f"/documents/{stored().public_id}/download").mimetype == "application/pdf"


# --- Classification et droits --------------------------------------------------------------------------

def test_agent_cannot_classify_above_clearance(app):
    alice, _ = logged_in(app, "alice", clearance=1)
    resp = upload(alice, make_pdf(), level=3)
    assert resp.status_code == 403
    assert SecureDocument.query.count() == 0
    assert any(row.outcome == "DENIED" for row in events("DOC_CREATE"))


def test_form_only_offers_levels_up_to_the_clearance(app):
    alice, _ = logged_in(app, "alice", clearance=1)
    page = alice.get("/documents/upload").data.decode()
    assert "CONFIDENTIEL" in page and "SECRET</option>" not in page and "TRÈS SECRET</option>" not in page


def test_read_up_is_not_possible_with_a_file(app):
    alice, owner = logged_in(app, "alice", clearance=3)
    upload(alice, make_pdf(), level=3)
    doc = stored()
    bob, _ = logged_in(app, "bob", clearance=1)
    assert bob.get(f"/documents/{doc.public_id}/download").status_code == 404
    assert bob.get(f"/documents/{doc.public_id}").status_code == 404
    assert any(row.event == "DOC_ACCESS_DENIED" for row in AuditLog.query.all())
    assert not events("DOC_DOWNLOAD")


def test_need_to_know_applies_to_downloads(app):
    alice, _ = logged_in(app, "alice", clearance=2)
    upload(alice, make_pdf(), level=1)
    doc = stored()
    bob, bob_user = logged_in(app, "bob", clearance=2)
    assert bob.get(f"/documents/{doc.public_id}/download").status_code == 404   # cleared, but not on the list
    ok, _ = service.grant_access(doc.owner, bob_user, doc)
    db.session.commit()
    assert ok
    assert bob.get(f"/documents/{doc.public_id}/download").data == make_pdf()
    assert [row.actor_id for row in events("DOC_DOWNLOAD")] == [bob_user.id]


def test_download_of_a_text_document_is_404(app):
    alice, owner = logged_in(app, "alice")
    doc = service.create_document(owner, "Texte", "Rien à télécharger", 0)
    db.session.commit()
    assert alice.get(f"/documents/{doc.public_id}/download").status_code == 404


def test_unknown_or_malformed_download_ids_are_404(app):
    alice, _ = logged_in(app, "alice")
    assert alice.get("/documents/not-a-uuid/download").status_code == 404
    assert alice.get("/documents/00000000-0000-4000-8000-000000000000/download").status_code == 404


# --- Administrateur : choisit la classification, ne lit pas ---------------------------------------------

def test_admin_can_upload_at_any_classification_but_cannot_read_it(app):
    admin, root = logged_in(app, "root", role="admin", clearance=0)
    resp = upload(admin, make_pdf(), level=3, title="Note de service")
    assert resp.status_code == 302 and resp.headers["Location"].endswith("/access")  # va au partage, pas à la lecture
    doc = stored()
    assert doc.classification == 3 and doc.owner_id == root.id
    assert admin.get(f"/documents/{doc.public_id}").status_code == 404
    assert admin.get(f"/documents/{doc.public_id}/download").status_code == 404
    assert b"TS-" in admin.get("/admin/documents").data   # métadonnées visibles, jamais le titre
    assert b"Note de service" not in admin.get("/admin/documents").data
    assert b"Note de service" not in admin.get("/documents/").data


def test_admin_uploads_then_shares_with_a_cleared_agent_only(app):
    admin, root = logged_in(app, "root", role="admin")
    upload(admin, make_pdf(), level=2)
    doc = stored()
    alice_client, alice = logged_in(app, "alice", clearance=2)
    low = make_user("low", clearance=1)

    access_page = f"/documents/{doc.public_id}/access"
    post(admin, f"{access_page}/grant", {"username": "low"}, token_page=access_page)
    assert "habilitation du destinataire insuffisante" in admin.get(access_page).data.decode()
    assert not [e for e in doc.accesses if e.user_id == low.id]
    post(admin, f"{access_page}/grant", {"username": "alice"}, token_page=access_page)
    assert alice_client.get(f"/documents/{doc.public_id}/download").data == make_pdf()
    # l'administrateur ne peut pas s'ajouter lui-même
    post(admin, f"{access_page}/grant", {"username": "root"}, token_page=access_page)
    assert admin.get(f"/documents/{doc.public_id}/download").status_code == 404
    assert events("ADMIN_SELF_MODIFY_DENIED")


def test_admin_text_document_also_accepts_any_level(app):
    admin, _ = logged_in(app, "root", role="admin")
    resp = post(admin, "/documents/new", {"title": "Directive", "classification": 3, "content": "Texte"},
                token_page="/documents/new")
    assert resp.status_code == 302 and stored().classification == 3


# --- Intégrité --------------------------------------------------------------------------------------------

def test_tampered_file_blob_is_detected(app):
    alice, _ = logged_in(app, "alice")
    upload(alice, make_pdf())
    doc = stored()
    blob = bytearray(doc.file_ciphertext)
    blob[10] ^= 0x01
    doc.file_ciphertext = bytes(blob)
    db.session.commit()
    assert alice.get(f"/documents/{doc.public_id}/download").status_code == 500
    assert any("fichier" in (row.details or "") for row in events("INTEGRITY_FAILURE"))
    assert not events("DOC_DOWNLOAD")


def test_downgrading_the_classification_of_a_file_blocks_the_download(app):
    alice, _ = logged_in(app, "alice", clearance=3)
    upload(alice, make_pdf(), level=3)
    doc = stored()
    doc.classification = 0  # un attaquant de la base « déclasse » le document
    db.session.commit()
    assert alice.get(f"/documents/{doc.public_id}/download").status_code == 500
    assert events("INTEGRITY_FAILURE")


def test_file_and_metadata_blobs_cannot_be_swapped(app):
    kwargs = dict(public_id="11111111-1111-4111-8111-111111111111", classification=1, owner_id=7)
    nonce, blob = crypto.encrypt_file(b"octets", **kwargs)
    assert crypto.decrypt_file(nonce, blob, **kwargs) == b"octets"
    with pytest.raises(crypto.IntegrityError):
        crypto.decrypt_metadata(nonce, blob, **kwargs)        # un fichier ne se fait pas passer pour des métadonnées
    meta_nonce, meta = crypto.encrypt_document("t", "c", filename="a.pdf", **kwargs)
    with pytest.raises(crypto.IntegrityError):
        crypto.decrypt_file(meta_nonce, meta, **kwargs)        # ni l'inverse
    for changed in ({"classification": 0}, {"owner_id": 8}, {"public_id": "22222222-2222-4222-8222-222222222222"}):
        with pytest.raises(crypto.IntegrityError):
            crypto.decrypt_file(nonce, blob, **{**kwargs, **changed})


def test_every_file_gets_a_fresh_nonce(app):
    kwargs = dict(public_id="11111111-1111-4111-8111-111111111111", classification=1, owner_id=7)
    nonces = {crypto.encrypt_file(b"x", **kwargs)[0] for _ in range(50)}
    assert len(nonces) == 50 and all(len(n) == crypto.NONCE_SIZE for n in nonces)


def test_old_documents_without_filename_still_decrypt(app):
    kwargs = dict(public_id="11111111-1111-4111-8111-111111111111", classification=0, owner_id=1)
    nonce, blob = crypto.encrypt_document("Titre", "Contenu", **kwargs)
    assert crypto.decrypt_document(nonce, blob, **kwargs) == ("Titre", "Contenu")
    assert crypto.decrypt_metadata(nonce, blob, **kwargs)["filename"] is None


def test_file_and_filename_must_come_together(app):
    owner = make_user("alice")
    with pytest.raises(ValueError):
        service.create_document(owner, "t", "c", 0, file_bytes=b"x")
    with pytest.raises(ValueError):
        service.create_document(owner, "t", "c", 0, filename="a.pdf")
