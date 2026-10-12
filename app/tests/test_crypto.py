"""AES-256-GCM : confidentialité, intégrité et données associées (T17, T18)."""
import base64

import pytest
from sqlalchemy import text

from helpers import make_user, new_document

from secureauth.extensions import db
from secureauth.security.crypto import IntegrityError, NONCE_SIZE, decrypt_document, encrypt_document

ARGS = {"public_id": "6f1c1d0e-0000-4000-8000-000000000001", "classification": 2, "owner_id": 7}


def test_roundtrip(app):
    nonce, ciphertext = encrypt_document("Titre", "Contenu é à ç", **ARGS)
    assert decrypt_document(nonce, ciphertext, **ARGS) == ("Titre", "Contenu é à ç")


def test_ciphertext_does_not_contain_plaintext(app):
    nonce, ciphertext = encrypt_document("TITRE-SECRET", "CONTENU-SECRET", **ARGS)
    assert b"TITRE-SECRET" not in ciphertext and b"CONTENU-SECRET" not in ciphertext


def test_nonce_is_96_bits_and_never_reused(app):
    """Un nonce réutilisé avec la même clé détruirait la sécurité de GCM : 500 chiffrements, 500 nonces distincts."""
    nonces = {encrypt_document("t", "c", **ARGS)[0] for _ in range(500)}
    assert len(nonces) == 500
    assert all(len(n) == NONCE_SIZE for n in nonces)


def test_same_plaintext_gives_different_ciphertexts(app):
    assert encrypt_document("t", "c", **ARGS)[1] != encrypt_document("t", "c", **ARGS)[1]


@pytest.mark.parametrize("field, value", [("classification", 0), ("owner_id", 8),
                                          ("public_id", "6f1c1d0e-0000-4000-8000-000000000002")])
def test_associated_data_is_sealed(app, field, value):
    """T17 : changer la classification, le propriétaire ou l'identifiant public rend le déchiffrement impossible."""
    nonce, ciphertext = encrypt_document("t", "c", **ARGS)
    with pytest.raises(IntegrityError):
        decrypt_document(nonce, ciphertext, **{**ARGS, field: value})


def test_modified_ciphertext_detected(app):
    nonce, ciphertext = encrypt_document("t", "c", **ARGS)
    forged = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
    with pytest.raises(IntegrityError):
        decrypt_document(nonce, forged, **ARGS)


def test_truncated_ciphertext_and_bad_nonce_detected(app):
    nonce, ciphertext = encrypt_document("t", "c", **ARGS)
    with pytest.raises(IntegrityError):
        decrypt_document(nonce, ciphertext[:-1], **ARGS)
    with pytest.raises(IntegrityError):
        decrypt_document(b"\x00" * NONCE_SIZE, ciphertext, **ARGS)
    with pytest.raises(IntegrityError):
        decrypt_document(b"\x00", ciphertext, **ARGS)


def test_wrong_key_detected(app):
    nonce, ciphertext = encrypt_document("t", "c", **ARGS)
    app.config["ENCRYPTION_KEY"] = base64.b64decode(base64.b64encode(b"X" * 32))
    with pytest.raises(IntegrityError):
        decrypt_document(nonce, ciphertext, **ARGS)


def test_database_holds_only_ciphertext(app):
    """T18 : lire directement la table ne donne que du binaire illisible, ni titre ni contenu."""
    alice = make_user("alice", clearance=2)
    new_document(alice, title="PLAN-AURORE-TITRE", content="COORDONNEES-SECRETES", level=2)
    row = db.session.execute(text("SELECT reference, nonce, ciphertext FROM secure_documents")).one()
    assert b"PLAN-AURORE-TITRE" not in row.ciphertext and b"COORDONNEES-SECRETES" not in row.ciphertext
    assert len(row.nonce) == NONCE_SIZE
    dump = " ".join(str(c) for r in db.session.execute(text("SELECT * FROM secure_documents")).all() for c in r)
    assert "PLAN-AURORE-TITRE" not in dump and "COORDONNEES-SECRETES" not in dump
