"""Jeu de démonstration (`flask seed-demo`, EF-21) et déroulement du scénario final (cahier des charges, section 13)."""
from sqlalchemy import text

from helpers import PASSWORD, events, login, make_user, post

from secureauth.cli import seed_demo_command, verify_audit_command
from secureauth.extensions import db
from secureauth.models import AuditLog, SecureDocument, User


def seed(app):
    result = app.test_cli_runner().invoke(seed_demo_command, ["--password", PASSWORD])
    assert result.exit_code == 0, result.output
    return result


def client_of(app, username):
    client = app.test_client()
    assert login(client, username).status_code == 302
    return client


def doc(reference):
    return SecureDocument.query.filter_by(reference=reference).one()


def titles(client):
    return client.get("/documents/").data.decode()


def test_seed_creates_accounts_and_four_encrypted_documents(app):
    seed(app)
    assert {(u.username, u.clearance_level, u.role) for u in User.query.all()} == {("alice", 3, "user"), ("bob", 2, "user")}
    assert {d.reference for d in SecureDocument.query.all()} == {"TS-001", "SEC-001", "SEC-002", "PUB-001"}
    raw = db.session.execute(text("SELECT ciphertext FROM secure_documents")).all()
    assert all(b"Aurore" not in row.ciphertext for row in raw)


def test_seed_is_idempotent(app):
    seed(app)
    seed(app)
    assert User.query.count() == 2 and SecureDocument.query.count() == 4


def test_seed_never_creates_an_admin(app):
    seed(app)
    assert User.query.filter_by(role="admin").count() == 0


def test_seed_refuses_a_weak_password(app):
    result = app.test_cli_runner().invoke(seed_demo_command, ["--password", "court"])
    assert result.exit_code != 0 and User.query.count() == 0


def test_final_demonstration_scenario(app):
    """Les huit étapes de la démonstration finale, de bout en bout."""
    seed(app)
    make_user("admin", role="admin")
    alice, bob, admin = client_of(app, "alice"), client_of(app, "bob"), client_of(app, "admin")

    # 2. alice (TRÈS SECRET) voit TS-001, SEC-001 et PUB-001
    page = titles(alice)
    for ref in ("TS-001", "SEC-001", "PUB-001"):
        assert ref in page

    # 3. bob (SECRET) ne voit pas TS-001 ; forcer l'URL donne 404 et le refus est journalisé
    assert "TS-001" not in titles(bob) and "SEC-001" in titles(bob)
    assert bob.get(f"/documents/{doc('TS-001').public_id}").status_code == 404
    assert any(e.actor_id == User.query.filter_by(username="bob").one().id for e in events("DOC_ACCESS_DENIED"))

    # 4. alice tente de partager TS-001 avec bob : refusé, habilitation insuffisante
    post(alice, f"/documents/{doc('TS-001').public_id}/access/grant", {"username": "bob"},
         token_page=f"/documents/{doc('TS-001').public_id}/access")
    assert bob.get(f"/documents/{doc('TS-001').public_id}").status_code == 404

    # 5. l'administrateur baisse bob à 1 : bob perd immédiatement SEC-001 et SEC-002
    bob_id = User.query.filter_by(username="bob").one().id
    post(admin, f"/admin/users/{bob_id}/clearance", {"level": 1}, token_page="/admin/users")
    assert bob.get(f"/documents/{doc('SEC-001').public_id}").status_code == 404
    assert bob.get(f"/documents/{doc('SEC-002').public_id}").status_code == 404
    assert bob.get(f"/documents/{doc('PUB-001').public_id}").status_code == 200

    # 6. l'administrateur tente d'ouvrir TS-001 : 404, il gère mais ne lit pas
    assert admin.get(f"/documents/{doc('TS-001').public_id}").status_code == 404

    # 7. attaque en base : TS-001 passé à PUBLIC, le déchiffrement est refusé (INTEGRITY_FAILURE)
    db.session.execute(text("UPDATE secure_documents SET classification = 0 WHERE reference = 'TS-001'"))
    db.session.commit()
    assert alice.get(f"/documents/{doc('TS-001').public_id}").status_code == 500
    assert events("INTEGRITY_FAILURE")

    # 8. attaque sur le journal : une ligne modifiée est désignée par verify-audit
    victim = AuditLog.query.filter_by(event="LOGIN_SUCCESS").first()
    db.session.execute(text("UPDATE audit_logs SET outcome = 'FAILURE' WHERE id = :id"), {"id": victim.id})
    db.session.commit()
    result = app.test_cli_runner().invoke(verify_audit_command)
    assert result.exit_code == 1 and f"ligne {victim.id}" in result.output
