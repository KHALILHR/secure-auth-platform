"""Journal d'audit chaîné : chaque attaque sur le registre doit être détectée (T19, T20)."""
import hashlib
import hmac

import pytest
from sqlalchemy import text

from secureauth.extensions import db
from secureauth.models import AuditChainHead, AuditLog
from secureauth.security import audit


def _fill(n=5):
    """Écrit n lignes et retourne leurs identifiants."""
    return [
        audit.log_event("LOGIN_FAILURE", "FAILURE", actor_id=None, details=f"essai {i}").id
        for i in range(1, n + 1)
    ]


def _sql(statement, **params):
    """Simule un attaquant qui modifie la base directement, sans passer par l'application."""
    db.session.execute(text(statement), params)
    db.session.commit()


# --- Écriture -----------------------------------------------------------------

def test_first_line_starts_from_genesis(app):
    entry = audit.log_event("REGISTER", "SUCCESS", actor_id=None)
    assert entry.prev_tag == "0" * 64
    assert len(entry.integrity_tag) == 64


def test_each_line_points_to_previous(app):
    ids = _fill(3)
    rows = [db.session.get(AuditLog, i) for i in ids]
    assert rows[1].prev_tag == rows[0].integrity_tag
    assert rows[2].prev_tag == rows[1].integrity_tag


def test_head_follows_last_line(app):
    ids = _fill(3)
    head = db.session.get(AuditChainHead, 1)
    assert head.last_log_id == ids[-1]
    assert head.last_tag == db.session.get(AuditLog, ids[-1]).integrity_tag


def test_tag_is_hmac_sha256_of_prev_tag_and_canonical_json(app):
    entry = audit.log_event("LOGOUT", "SUCCESS", actor_id=None)
    expected = hmac.new(
        app.config["HMAC_KEY"],
        (entry.prev_tag + audit.canonical_json(entry)).encode(),
        hashlib.sha256,
    ).hexdigest()
    assert entry.integrity_tag == expected


def test_microseconds_survive_database_roundtrip(app):
    entry = audit.log_event("LOGOUT", "SUCCESS")
    signed = entry.created_at
    db.session.expire_all()
    assert db.session.get(AuditLog, entry.id).created_at == signed


def test_unknown_event_or_outcome_is_rejected(app):
    with pytest.raises(ValueError):
        audit.log_event("HACK", "SUCCESS")
    with pytest.raises(ValueError):
        audit.log_event("LOGOUT", "MAYBE")


def test_details_are_flattened_and_truncated(app):
    entry = audit.log_event("LOGOUT", "SUCCESS", details="ligne1\nLOGIN_SUCCESS faux\r\n" + "x" * 600)
    assert "\n" not in entry.details and "\r" not in entry.details
    assert len(entry.details) == 500


def test_ip_comes_from_request(app):
    with app.test_request_context(environ_base={"REMOTE_ADDR": "203.0.113.7"}):
        entry = audit.log_event("LOGIN_FAILURE", "FAILURE")
    assert entry.ip_address == "203.0.113.7"


def test_pending_changes_are_committed_with_the_log(app):
    # l'action et sa trace sont atomiques : une seule validation
    db.session.add(AuditChainHead(id=99, last_log_id=0, last_tag="f" * 64))
    audit.log_event("LOGOUT", "SUCCESS")
    db.session.rollback()
    assert db.session.get(AuditChainHead, 99) is not None


# --- Vérification : chaîne saine -------------------------------------------------

def test_empty_chain_is_valid(app):
    assert audit.verify_chain().ok


def test_intact_chain_is_valid(app):
    _fill(5)
    report = audit.verify_chain()
    assert report.ok and report.checked == 5


# --- Vérification : attaques -----------------------------------------------------

def test_modified_details_detected(app):
    ids = _fill(5)
    _sql("UPDATE audit_logs SET details = 'rien a signaler' WHERE id = :id", id=ids[2])
    report = audit.verify_chain()
    assert not report.ok
    assert report.first_bad_id == ids[2]
    assert report.checked == 2


def test_modified_outcome_detected(app):
    ids = _fill(3)
    _sql("UPDATE audit_logs SET outcome = 'SUCCESS' WHERE id = :id", id=ids[0])
    assert audit.verify_chain().first_bad_id == ids[0]


def test_modified_actor_detected(app):
    ids = _fill(3)
    _sql("UPDATE audit_logs SET actor_id = NULL, ip_address = '10.0.0.1' WHERE id = :id", id=ids[1])
    assert audit.verify_chain().first_bad_id == ids[1]


def test_deleted_middle_line_detected(app):
    ids = _fill(5)
    _sql("DELETE FROM audit_logs WHERE id = :id", id=ids[2])
    report = audit.verify_chain()
    assert not report.ok
    assert report.first_bad_id == ids[3]  # la ligne suivante ne pointe plus vers la bonne
    assert "lien rompu" in report.reason


def test_deleted_last_lines_detected(app):
    ids = _fill(5)
    _sql("DELETE FROM audit_logs WHERE id >= :id", id=ids[3])
    report = audit.verify_chain()
    assert not report.ok
    assert "tête" in report.reason


def test_all_lines_deleted_detected(app):
    _fill(3)
    _sql("DELETE FROM audit_logs")
    assert not audit.verify_chain().ok


def test_deleted_head_detected(app):
    _fill(2)
    _sql("DELETE FROM audit_chain_head")
    report = audit.verify_chain()
    assert not report.ok and "tête" in report.reason


def test_swapped_lines_detected(app):
    ids = _fill(4)
    a, b = db.session.get(AuditLog, ids[1]), db.session.get(AuditLog, ids[2])
    fields = ("created_at", "actor_id", "event", "outcome", "target_type",
              "target_id", "ip_address", "details", "prev_tag", "integrity_tag")
    for f in fields:
        va, vb = getattr(a, f), getattr(b, f)
        setattr(a, f, vb)
        setattr(b, f, va)
    db.session.commit()
    report = audit.verify_chain()
    assert not report.ok and report.first_bad_id == ids[1]


def test_forged_tag_without_key_detected(app):
    """L'attaquant modifie une ligne et recalcule l'empreinte, mais sans la vraie clé."""
    ids = _fill(3)
    row = db.session.get(AuditLog, ids[1])
    row.details = "falsifie"
    row.integrity_tag = hmac.new(b"devine" * 6, (row.prev_tag + audit.canonical_json(row)).encode(),
                                 hashlib.sha256).hexdigest()
    db.session.commit()
    assert audit.verify_chain().first_bad_id == ids[1]


def test_hmac_key_change_invalidates_chain(app):
    _fill(2)
    app.config["HMAC_KEY"] = b"K" * 32
    assert not audit.verify_chain().ok


# --- Commande flask verify-audit -----------------------------------------------

def test_cli_reports_intact_chain(app):
    _fill(3)
    result = app.test_cli_runner().invoke(args=["verify-audit"])
    assert result.exit_code == 0
    assert "Chaîne intègre : 3 ligne(s)" in result.output


def test_cli_reports_corruption_and_fails(app):
    ids = _fill(3)
    _sql("UPDATE audit_logs SET event = 'LOGOUT' WHERE id = :id", id=ids[1])
    result = app.test_cli_runner().invoke(args=["verify-audit"])
    assert result.exit_code == 1
    assert f"CHAÎNE CORROMPUE à la ligne {ids[1]}" in result.output


def test_cli_logs_its_own_verification(app):
    _fill(1)
    app.test_cli_runner().invoke(args=["verify-audit"])
    last = db.session.query(AuditLog).order_by(AuditLog.id.desc()).first()
    assert last.event == "AUDIT_VERIFY" and last.outcome == "SUCCESS"
    assert audit.verify_chain().ok  # la ligne AUDIT_VERIFY est elle-même bien chaînée
