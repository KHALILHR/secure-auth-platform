"""Point de décision unique pour l'autorisation (cahier des charges, section 6).

Analogie : le décorateur de route est le garde à l'entrée de l'étage (« avez-vous un
badge ? »). Ici, c'est le registre du service de sécurité : pour chaque document, il
tranche « cette personne a-t-elle le droit ? » avec les mêmes règles partout.
AUCUNE route ne compare une habilitation ou un rôle à la main : elle appelle ces
fonctions. Ainsi une règle se corrige à un seul endroit, et un test unique la couvre.

Trois principes :
  1. pas de lecture vers le haut : habilitation >= classification ;
  2. besoin d'en connaître : il faut figurer dans document_access ;
  3. séparation des rôles : l'administrateur gère mais ne lit pas, et ne
     modifie jamais ses propres droits.
"""
from ..extensions import db
from ..models import DocumentAccess, SecureDocument, User

MIN_LEVEL = 0
MAX_LEVEL = 3


def _is_owner(actor: User, doc: SecureDocument) -> bool:
    return actor.id == doc.owner_id


def _is_admin(actor: User) -> bool:
    return actor.role == "admin"


def has_access_entry(user: User, doc: SecureDocument) -> bool:
    """Vrai si l'agent figure sur la liste d'accès du document (besoin d'en connaître)."""
    return (
        db.session.query(DocumentAccess.id)
        .filter(DocumentAccess.document_id == doc.id, DocumentAccess.user_id == user.id)
        .first()
        is not None
    )


def can_read(user: User, doc: SecureDocument) -> bool:
    """Lecture d'un document : compte actif, non verrouillé, habilité ET sur la liste d'accès.

    L'administrateur n'a pas de ligne d'accès sur les documents des autres : sa lecture
    est donc refusée par construction (séparation des rôles).
    """
    return (
        user.is_active
        and not user.is_locked()
        and user.clearance_level >= doc.classification
        and has_access_entry(user, doc)
    )


def max_creation_level(user: User) -> int:
    """Classification maximale qu'on peut donner à un document déposé.

    Un agent : jamais au-dessus de sa propre habilitation. L'administrateur est l'autorité de
    classification : il choisit n'importe quel niveau, mais sa propre habilitation (0) ne change pas.
    Il pourra donc déposer un document SECRET sans jamais pouvoir le lire (pas de lecture vers le haut)
    et le confier à des agents habilités.
    """
    return MAX_LEVEL if _is_admin(user) else user.clearance_level


def can_create(user: User, level: int) -> bool:
    """Création ou dépôt d'un document : agent jusqu'à son habilitation, administrateur à tous les niveaux."""
    return user.is_active and MIN_LEVEL <= level <= max_creation_level(user)


def can_create_user(actor: User) -> bool:
    """Ouvrir un compte agent depuis l'espace administrateur. Réservé à l'administrateur actif."""
    return actor.is_active and _is_admin(actor)


def can_list_access(actor: User, doc: SecureDocument) -> bool:
    """Consulter la liste d'accès : propriétaire ou administrateur (EF-11)."""
    return actor.is_active and (_is_owner(actor, doc) or _is_admin(actor))


def can_grant(actor: User, grantee: User, doc: SecureDocument) -> bool:
    """Ajouter un agent à la liste d'accès (EF-12)."""
    return (
        actor.is_active
        and (_is_owner(actor, doc) or _is_admin(actor))
        and grantee.is_active
        and grantee.clearance_level >= doc.classification
        and not (_is_admin(actor) and grantee.id == actor.id)
    )


def explain_grant_denial(actor: User, grantee: User, doc: SecureDocument) -> str:
    """Motif lisible d'un refus de can_grant (pour le message affiché et le journal)."""
    if not (_is_owner(actor, doc) or _is_admin(actor)):
        return "droit insuffisant"
    if _is_admin(actor) and grantee.id == actor.id:
        return "un administrateur ne peut pas s'attribuer un accès"
    if not grantee.is_active:
        return "compte destinataire désactivé"
    if grantee.clearance_level < doc.classification:
        return "habilitation du destinataire insuffisante"
    return "refusé"


def can_revoke(actor: User, grantee: User, doc: SecureDocument) -> bool:
    """Retirer un agent de la liste d'accès (EF-13). Le propriétaire ne peut pas perdre son accès."""
    return (
        actor.is_active
        and (_is_owner(actor, doc) or _is_admin(actor))
        and grantee.id != doc.owner_id
    )


def can_admin_modify(actor: User, target: User) -> bool:
    """Modifier l'habilitation ou l'activation d'un compte (EF-15, EF-16) : jamais le sien."""
    return actor.is_active and _is_admin(actor) and target.id != actor.id


def can_view_metadata(actor: User) -> bool:
    """Métadonnées d'un document (référence, classification, propriétaire) : administrateur (EF-17)."""
    return actor.is_active and _is_admin(actor)


def readable_documents(user: User) -> list[SecureDocument]:
    """Documents que l'agent peut lire (EF-07). Chaque ligne repasse par can_read."""
    candidates = (
        SecureDocument.query.join(DocumentAccess, DocumentAccess.document_id == SecureDocument.id)
        .filter(DocumentAccess.user_id == user.id)
        .order_by(SecureDocument.created_at.desc(), SecureDocument.id.desc())
        .all()
    )
    return [doc for doc in candidates if can_read(user, doc)]
