"""Modèle de données (ERD du plan §6)."""
import uuid
from datetime import datetime, timezone

from sqlalchemy.dialects import mysql

from .extensions import db

# Niveaux de classification / habilitation (échelle commune)
CLASSIFICATION_LABELS = {0: "PUBLIC", 1: "CONFIDENTIEL", 2: "SECRET", 3: "TRÈS SECRET"}


def utcnow() -> datetime:
    # DATETIME MariaDB ne stocke pas de fuseau : tout est enregistré en UTC.
    return datetime.now(timezone.utc).replace(tzinfo=None)


def new_public_id() -> str:
    return str(uuid.uuid4())


# Le journal est signé par HMAC : la date relue en base doit être identique à la date
# signée. On stocke donc les microsecondes (DATETIME(6)) pour éviter toute troncature.
AuditDateTime = db.DateTime().with_variant(mysql.DATETIME(fsp=6), "mysql", "mariadb")


class User(db.Model):
    __tablename__ = "users"
    __table_args__ = (
        db.CheckConstraint("clearance_level BETWEEN 0 AND 3", name="ck_users_clearance"),
    )

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)  # normalisé en minuscules
    # Empreinte Argon2id, jamais le mot de passe en clair
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum("user", "admin", name="user_role"), nullable=False, default="user")
    clearance_level = db.Column(db.SmallInteger, nullable=False, default=0)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    # Contrôle des comptes : compteur d'échecs + verrouillage temporaire
    failed_attempts = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    last_login_at = db.Column(db.DateTime, nullable=True)
    password_changed_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    def is_locked(self) -> bool:
        return self.locked_until is not None and self.locked_until > utcnow()


class SecureDocument(db.Model):
    """Document classifié : titre et contenu sont chiffrés (AES-256-GCM) dans `ciphertext`."""

    __tablename__ = "secure_documents"
    __table_args__ = (
        db.CheckConstraint("classification BETWEEN 0 AND 3", name="ck_documents_classification"),
    )

    id = db.Column(db.Integer, primary_key=True)  # jamais exposé dans une URL
    public_id = db.Column(db.String(36), unique=True, nullable=False, default=new_public_id)
    reference = db.Column(db.String(32), unique=True, nullable=False)  # en clair, non sensible
    classification = db.Column(db.SmallInteger, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    nonce = db.Column(db.LargeBinary(12), nullable=False)   # 96 bits, unique à chaque chiffrement
    ciphertext = db.Column(db.LargeBinary, nullable=False)  # titre + contenu + tag GCM
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow, onupdate=utcnow)

    owner = db.relationship("User")
    accesses = db.relationship("DocumentAccess", back_populates="document", cascade="all, delete-orphan")


class DocumentAccess(db.Model):
    """Besoin d'en connaître : liste des agents autorisés pour un document."""

    __tablename__ = "document_access"
    __table_args__ = (
        db.UniqueConstraint("document_id", "user_id", name="uq_access_document_user"),
    )

    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey("secure_documents.id"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    granted_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    granted_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    document = db.relationship("SecureDocument", back_populates="accesses")
    user = db.relationship("User", foreign_keys=[user_id])
    grantor = db.relationship("User", foreign_keys=[granted_by])


class AuditLog(db.Model):
    """Journal de sécurité chaîné par HMAC-SHA256 (plan §7.3).

    `actor_id` n'a volontairement pas de SET NULL : modifier la ligne après coup
    casserait la signature. Aucun compte n'est supprimé (on le désactive).
    """

    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(AuditDateTime, nullable=False, default=utcnow, index=True)
    actor_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    event = db.Column(db.String(64), nullable=False, index=True)
    outcome = db.Column(db.Enum("SUCCESS", "DENIED", "FAILURE", name="audit_outcome"), nullable=False)
    target_type = db.Column(db.String(32), nullable=True)
    target_id = db.Column(db.String(36), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)  # 45 = longueur max d'une IPv6
    details = db.Column(db.String(500), nullable=True)    # jamais de contenu sensible
    prev_tag = db.Column(db.String(64), nullable=False)
    integrity_tag = db.Column(db.String(64), nullable=False)


class AuditChainHead(db.Model):
    """Tête de chaîne (une seule ligne, id = 1) : détecte la suppression des dernières lignes."""

    __tablename__ = "audit_chain_head"

    id = db.Column(db.Integer, primary_key=True)
    last_log_id = db.Column(db.Integer, nullable=False, default=0)
    last_tag = db.Column(db.String(64), nullable=False, default="0" * 64)
