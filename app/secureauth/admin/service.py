"""Actions de l'administrateur sur les comptes, séparées des routes pour être testables seules."""
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError

from ..auth.service import normalize_email
from ..extensions import db
from ..models import CLASSIFICATION_LABELS, User
from ..security import audit, policy
from ..security.passwords import hash_password, validate_password

ACCOUNT_TAKEN = "Ce nom d'utilisateur ou cette adresse e-mail est déjà utilisé."


def create_user(actor: User, username: str, email: str, password: str, clearance: int) -> tuple[User | None, list[str]]:
    """Ouvre un compte agent (rôle « user ») avec l'habilitation choisie. Retourne (utilisateur, erreurs).

    Le mot de passe saisi est PROVISOIRE : `must_change_password` oblige l'agent à le remplacer à sa première
    connexion, avant toute autre action. Un administrateur ne se crée jamais ici (uniquement `flask create-admin`).
    """
    if not policy.can_create_user(actor):
        audit.log_event("USER_CREATE", "DENIED", actor_id=actor.id, details="droit insuffisant")
        return None, ["Droit insuffisant."]
    if clearance not in CLASSIFICATION_LABELS:
        return None, ["Niveau d'habilitation invalide (0 à 3)."]

    username = username.strip()
    email = normalize_email(email)
    errors = validate_password(password, username)
    if errors:
        return None, errors

    taken = User.query.filter(
        (func.lower(User.username) == username.lower()) | (User.email == email)
    ).first()
    if taken is not None:
        # L'administrateur voit déjà la liste des comptes : un message précis ne révèle rien de plus
        return None, [ACCOUNT_TAKEN]

    user = User(username=username, email=email, password_hash=hash_password(password),
                role="user", clearance_level=clearance, must_change_password=True)
    db.session.add(user)
    try:
        db.session.flush()
    except IntegrityError:
        db.session.rollback()
        return None, [ACCOUNT_TAKEN]

    audit.log_event("USER_CREATE", "SUCCESS", actor_id=actor.id, target_type="user", target_id=user.id,
                    details=f"{user.username} : habilitation {CLASSIFICATION_LABELS[clearance]}")
    return user, []
