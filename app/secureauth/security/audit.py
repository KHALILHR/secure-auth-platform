"""Journal d'audit infalsifiable : HMAC-SHA256 chaîné (plan §7.3).

Analogie : un registre à pages numérotées où chaque page porte l'empreinte de la
précédente. Réécrire, arracher ou intervertir une page casse toutes les suivantes,
et la tête de chaîne (dernière page connue) révèle les pages arrachées à la fin.
Sans la clé HMAC_KEY, impossible de recalculer des empreintes valides.
"""
import hashlib
import hmac
import json
from dataclasses import dataclass

from flask import current_app, has_request_context, request

from ..extensions import db
from ..models import AuditChainHead, AuditLog, utcnow

GENESIS_TAG = "0" * 64  # prev_tag de la toute première ligne
HEAD_ID = 1
DETAILS_MAX = 500

OUTCOMES = ("SUCCESS", "DENIED", "FAILURE")
EVENTS = frozenset({
    "REGISTER", "LOGIN_SUCCESS", "LOGIN_FAILURE", "LOGIN_LOCKED", "LOGOUT",
    "PASSWORD_CHANGE", "DOC_CREATE", "DOC_READ", "DOC_ACCESS_DENIED",
    "ACCESS_GRANT", "ACCESS_REVOKE", "CLEARANCE_CHANGE", "ACCOUNT_DISABLE",
    "ACCOUNT_ENABLE", "ADMIN_SELF_MODIFY_DENIED", "INTEGRITY_FAILURE", "AUDIT_VERIFY",
})


def canonical_json(entry: AuditLog) -> str:
    """Sérialisation stable d'une ligne : mêmes champs, même ordre, mêmes séparateurs."""
    return json.dumps(
        {
            "created_at": entry.created_at.isoformat(timespec="microseconds"),
            "actor_id": entry.actor_id,
            "event": entry.event,
            "outcome": entry.outcome,
            "target_type": entry.target_type,
            "target_id": entry.target_id,
            "ip_address": entry.ip_address,
            "details": entry.details,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def compute_tag(prev_tag: str, entry: AuditLog) -> str:
    key = current_app.config["HMAC_KEY"]
    message = (prev_tag + canonical_json(entry)).encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def ensure_chain_head() -> None:
    """Crée la tête de chaîne si elle n'existe pas (appelé par `flask init-db`)."""
    if db.session.get(AuditChainHead, HEAD_ID) is None:
        db.session.add(AuditChainHead(id=HEAD_ID, last_log_id=0, last_tag=GENESIS_TAG))
        db.session.commit()


def _clean_details(details: str | None) -> str | None:
    if details is None:
        return None
    # Pas de retour à la ligne : une ligne de journal ne peut pas en imiter une autre
    flat = " ".join(str(details).split())
    return flat[:DETAILS_MAX]


def log_event(
    event: str,
    outcome: str,
    actor_id: int | None = None,
    target_type: str | None = None,
    target_id: str | int | None = None,
    details: str | None = None,
) -> AuditLog:
    """Ajoute une ligne signée au journal et valide la transaction.

    Toute modification en attente dans la session (ex. compteur d'échecs) est
    validée avec la ligne d'audit : l'action et sa trace sont atomiques.
    Ne JAMAIS passer de mot de passe, contenu de document, session ou clé dans `details`.
    """
    if event not in EVENTS:
        raise ValueError(f"Événement d'audit inconnu : {event}")
    if outcome not in OUTCOMES:
        raise ValueError(f"Résultat d'audit inconnu : {outcome}")

    # Verrou exclusif sur la tête : avec 3 workers Gunicorn, deux écritures
    # simultanées ne peuvent pas partir du même prev_tag (SELECT ... FOR UPDATE).
    head = db.session.get(AuditChainHead, HEAD_ID, with_for_update=True)
    if head is None:
        head = AuditChainHead(id=HEAD_ID, last_log_id=0, last_tag=GENESIS_TAG)
        db.session.add(head)

    entry = AuditLog(
        created_at=utcnow(),
        actor_id=actor_id,
        event=event,
        outcome=outcome,
        target_type=target_type,
        target_id=None if target_id is None else str(target_id),
        ip_address=request.remote_addr if has_request_context() else None,
        details=_clean_details(details),
        prev_tag=head.last_tag,
    )
    entry.integrity_tag = compute_tag(head.last_tag, entry)
    db.session.add(entry)
    db.session.flush()  # attribue entry.id

    head.last_log_id = entry.id
    head.last_tag = entry.integrity_tag
    db.session.commit()  # libère le verrou
    return entry


@dataclass
class ChainReport:
    ok: bool
    checked: int
    first_bad_id: int | None = None
    reason: str | None = None


def verify_chain() -> ChainReport:
    """Recalcule toute la chaîne et signale la PREMIÈRE anomalie.

    Détecte : ligne modifiée, ligne supprimée au milieu, lignes interverties,
    dernières lignes supprimées (comparaison avec la tête), tête supprimée.
    """
    head = db.session.get(AuditChainHead, HEAD_ID)
    if head is None:
        return ChainReport(False, 0, None, "tête de chaîne absente")

    prev_tag = GENESIS_TAG
    last_id = 0
    checked = 0
    for entry in db.session.query(AuditLog).order_by(AuditLog.id).yield_per(500):
        if not hmac.compare_digest(entry.prev_tag, prev_tag):
            return ChainReport(False, checked, entry.id, "lien rompu avec la ligne précédente (suppression ou réordonnancement)")
        if not hmac.compare_digest(entry.integrity_tag, compute_tag(prev_tag, entry)):
            return ChainReport(False, checked, entry.id, "contenu modifié (empreinte HMAC invalide)")
        prev_tag = entry.integrity_tag
        last_id = entry.id
        checked += 1

    if head.last_log_id != last_id or not hmac.compare_digest(head.last_tag, prev_tag):
        return ChainReport(False, checked, last_id or None, "fin de chaîne différente de la tête (dernières lignes supprimées)")
    return ChainReport(True, checked)
