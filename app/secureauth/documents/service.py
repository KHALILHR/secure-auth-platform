"""Logique des documents classifiés, séparée des routes pour être testable seule.

Chaque fonction applique la politique (`security/policy.py`) elle-même : même si une
route oubliait un contrôle, le service refuserait quand même (défense en profondeur).
Aucun contenu de document, titre ou clé n'est jamais écrit dans le journal d'audit.
"""
import uuid

from ..extensions import db
from ..models import CLASSIFICATION_LABELS, DocumentAccess, SecureDocument, User, new_public_id, utcnow
from ..security import audit, policy
from ..security.crypto import IntegrityError, decrypt_file, decrypt_metadata, encrypt_document, encrypt_file
from .uploads import extension_of

REFERENCE_PREFIX = {0: "PUB", 1: "CONF", 2: "SEC", 3: "TS"}
TITLE_MAX = 200
CONTENT_MAX = 20_000


def temporary_reference(public_id: str) -> str:
    """Référence provisoire (l'identifiant numérique n'existe qu'après le flush). Doit tenir dans la colonne :
    MariaDB refuse les valeurs trop longues, SQLite (tests) les accepte sans rien dire."""
    return f"TMP-{public_id.replace('-', '')[:24]}"


class NotAllowed(Exception):
    """L'acteur n'a pas le droit d'effectuer cette action."""


def parse_public_id(value: str) -> str | None:
    """Accepte uniquement un UUID bien formé (renvoie sa forme canonique) : sinon None, donc 404."""
    try:
        return str(uuid.UUID(value))
    except (ValueError, AttributeError, TypeError):
        return None


def get_by_public_id(public_id: str) -> SecureDocument | None:
    canonical = parse_public_id(public_id)
    if canonical is None:
        return None
    return SecureDocument.query.filter_by(public_id=canonical).first()


def create_document(owner: User, title: str, content: str, classification: int,
                    reference: str | None = None, *, filename: str | None = None,
                    file_bytes: bytes | None = None) -> SecureDocument:
    """Crée un document chiffré. Le propriétaire reçoit automatiquement l'accès (il ne peut jamais le perdre).

    Avec `file_bytes` (déjà validé par `uploads.validate_upload`), le fichier est chiffré à part ;
    son nom rejoint le titre et le contenu dans les métadonnées chiffrées.
    """
    if not policy.can_create(owner, classification):
        raise NotAllowed("création au-dessus de l'habilitation")
    if (file_bytes is None) != (filename is None):
        raise ValueError("un fichier et son nom vont ensemble")

    public_id = new_public_id()
    nonce, ciphertext = encrypt_document(
        title, content, public_id=public_id, classification=classification, owner_id=owner.id,
        filename=filename,
    )
    doc = SecureDocument(
        public_id=public_id,
        reference=reference or temporary_reference(public_id),  # remplacée juste après
        classification=classification,
        owner_id=owner.id,
        nonce=nonce,
        ciphertext=ciphertext,
    )
    if file_bytes is not None:
        doc.file_nonce, doc.file_ciphertext = encrypt_file(
            file_bytes, public_id=public_id, classification=classification, owner_id=owner.id
        )
        doc.file_size = len(file_bytes)
    db.session.add(doc)
    db.session.flush()  # attribue doc.id
    if reference is None:
        doc.reference = f"{REFERENCE_PREFIX[classification]}-{utcnow().year}-{doc.id:04d}"
    db.session.add(DocumentAccess(document_id=doc.id, user_id=owner.id, granted_by=owner.id))

    details = f"{doc.reference} ({CLASSIFICATION_LABELS[classification]})"
    if file_bytes is not None:
        # Ni le nom ni le contenu du fichier dans le journal : seulement le format et la taille
        details += f", fichier {extension_of(filename)} de {len(file_bytes)} octets"
    audit.log_event("DOC_CREATE", "SUCCESS", actor_id=owner.id, target_type="document", target_id=doc.public_id,
                    details=details)
    return doc


def open_metadata(user: User, doc: SecureDocument) -> dict:
    """Titre, contenu et nom de fichier d'un document que `user` peut lire. Lève IntegrityError (et journalise) si altéré."""
    if not policy.can_read(user, doc):
        raise NotAllowed("lecture refusée")
    try:
        return decrypt_metadata(
            doc.nonce, doc.ciphertext,
            public_id=doc.public_id, classification=doc.classification, owner_id=doc.owner_id,
        )
    except IntegrityError:
        audit.log_event("INTEGRITY_FAILURE", "FAILURE", actor_id=user.id, target_type="document",
                        target_id=doc.public_id, details=f"déchiffrement impossible : {doc.reference}")
        raise


def open_document(user: User, doc: SecureDocument) -> tuple[str, str]:
    """Déchiffre un document que `user` a le droit de lire. Lève IntegrityError (et journalise) si altéré."""
    data = open_metadata(user, doc)
    return data["title"], data["content"]


def open_file(user: User, doc: SecureDocument) -> tuple[str, bytes]:
    """Nom et octets du fichier d'un document lisible. Lève NotAllowed, LookupError (pas de fichier) ou IntegrityError."""
    meta = open_metadata(user, doc)
    if not doc.has_file or meta["filename"] is None:
        raise LookupError("ce document n'a pas de fichier")
    try:
        data = decrypt_file(
            doc.file_nonce, doc.file_ciphertext,
            public_id=doc.public_id, classification=doc.classification, owner_id=doc.owner_id,
        )
    except IntegrityError:
        audit.log_event("INTEGRITY_FAILURE", "FAILURE", actor_id=user.id, target_type="document",
                        target_id=doc.public_id, details=f"fichier indéchiffrable : {doc.reference}")
        raise
    return meta["filename"], data


def log_download(user: User, doc: SecureDocument) -> None:
    audit.log_event("DOC_DOWNLOAD", "SUCCESS", actor_id=user.id, target_type="document",
                    target_id=doc.public_id, details=doc.reference)


def log_denied_read(user: User, doc: SecureDocument) -> None:
    audit.log_event("DOC_ACCESS_DENIED", "DENIED", actor_id=user.id, target_type="document",
                    target_id=doc.public_id,
                    details=f"{doc.reference} ({CLASSIFICATION_LABELS[doc.classification]}), "
                            f"habilitation {CLASSIFICATION_LABELS[user.clearance_level]}")


def log_read(user: User, doc: SecureDocument) -> None:
    audit.log_event("DOC_READ", "SUCCESS", actor_id=user.id, target_type="document",
                    target_id=doc.public_id, details=doc.reference)


def access_entries(doc: SecureDocument) -> list[DocumentAccess]:
    return (
        DocumentAccess.query.filter_by(document_id=doc.id)
        .order_by(DocumentAccess.granted_at, DocumentAccess.id)
        .all()
    )


def grant_access(actor: User, grantee: User, doc: SecureDocument) -> tuple[bool, str]:
    """Ajoute `grantee` à la liste d'accès. Retourne (succès, message)."""
    if not policy.can_grant(actor, grantee, doc):
        reason = policy.explain_grant_denial(actor, grantee, doc)
        if actor.role == "admin" and grantee.id == actor.id:
            audit.log_event("ADMIN_SELF_MODIFY_DENIED", "DENIED", actor_id=actor.id, target_type="document",
                            target_id=doc.public_id, details="tentative de s'attribuer un accès")
        else:
            audit.log_event("ACCESS_GRANT", "DENIED", actor_id=actor.id, target_type="document",
                            target_id=doc.public_id, details=f"{grantee.username} : {reason}")
        return False, f"Partage refusé : {reason}."
    if policy.has_access_entry(grantee, doc):
        return False, f"{grantee.username} a déjà accès à ce document."
    db.session.add(DocumentAccess(document_id=doc.id, user_id=grantee.id, granted_by=actor.id))
    audit.log_event("ACCESS_GRANT", "SUCCESS", actor_id=actor.id, target_type="document",
                    target_id=doc.public_id, details=f"accès accordé à {grantee.username}")
    return True, f"Accès accordé à {grantee.username}."


def revoke_access(actor: User, grantee: User, doc: SecureDocument) -> tuple[bool, str]:
    """Retire `grantee` de la liste d'accès. Le propriétaire ne peut jamais être retiré."""
    if not policy.can_revoke(actor, grantee, doc):
        audit.log_event("ACCESS_REVOKE", "DENIED", actor_id=actor.id, target_type="document",
                        target_id=doc.public_id, details=f"{grantee.username} : refusé")
        return False, "Retrait refusé (le propriétaire garde toujours son accès)."
    entry = DocumentAccess.query.filter_by(document_id=doc.id, user_id=grantee.id).first()
    if entry is None:
        return False, f"{grantee.username} n'a pas accès à ce document."
    db.session.delete(entry)
    audit.log_event("ACCESS_REVOKE", "SUCCESS", actor_id=actor.id, target_type="document",
                    target_id=doc.public_id, details=f"accès retiré à {grantee.username}")
    return True, f"Accès retiré à {grantee.username}."
