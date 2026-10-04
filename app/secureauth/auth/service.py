"""Logique d'authentification, séparée des routes pour être testable seule (plan §8).

Règle d'or : un attaquant ne doit jamais pouvoir distinguer « ce compte
n'existe pas » de « mauvais mot de passe », ni par le message, ni par le temps
de réponse.
"""
from datetime import datetime, timezone

from flask import current_app, session
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError

from ..extensions import db
from ..models import User, utcnow
from ..security import audit
from ..security.passwords import (
    hash_password,
    needs_rehash,
    validate_password,
    verify_or_dummy,
    verify_password,
)

REGISTER_REFUSED = "Inscription impossible avec ces informations."
LOGIN_REFUSED = "Identifiants invalides."


def normalize_email(email: str) -> str:
    return email.strip().lower()


def find_user(identifier: str) -> User | None:
    """Cherche par e-mail si l'identifiant contient @, sinon par nom (insensible à la casse)."""
    identifier = identifier.strip()
    if "@" in identifier:
        return User.query.filter(User.email == normalize_email(identifier)).first()
    return User.query.filter(func.lower(User.username) == identifier.lower()).first()


def register_user(username: str, email: str, password: str) -> tuple[User | None, list[str]]:
    """Crée un agent (role=user, habilitation 0). Retourne (utilisateur, erreurs)."""
    username = username.strip()
    email = normalize_email(email)

    errors = validate_password(password, username)
    if errors:
        return None, errors  # concerne le mot de passe saisi, ne révèle rien sur les comptes

    # Hachage AVANT le test d'unicité : même coût (≈ 50 ms) que le compte existe ou non
    password_hash = hash_password(password)

    taken = User.query.filter(
        (func.lower(User.username) == username.lower()) | (User.email == email)
    ).first()
    if taken is not None:
        return None, [REGISTER_REFUSED]

    user = User(username=username, email=email, password_hash=password_hash)
    db.session.add(user)
    try:
        db.session.flush()  # obtient user.id ; la contrainte unique protège contre deux inscriptions simultanées
    except IntegrityError:
        db.session.rollback()
        return None, [REGISTER_REFUSED]

    audit.log_event("REGISTER", "SUCCESS", actor_id=user.id, target_type="user", target_id=user.id)
    return user, []


def authenticate(identifier: str, password: str) -> User | None:
    """Vérifie les identifiants. Retourne l'utilisateur, ou None pour TOUT échec."""
    user = find_user(identifier)
    # Toujours un calcul Argon2 : sur le vrai hash, ou sur le hash factice si le compte n'existe pas
    password_ok = verify_or_dummy(user.password_hash if user else None, password)

    if user is None:
        audit.log_event("LOGIN_FAILURE", "FAILURE", details="compte inconnu")
        return None
    if not user.is_active:
        audit.log_event("LOGIN_FAILURE", "DENIED", actor_id=user.id,
                        target_type="user", target_id=user.id, details="compte désactivé")
        return None
    if not password_ok:
        audit.log_event("LOGIN_FAILURE", "FAILURE", actor_id=user.id,
                        target_type="user", target_id=user.id, details="mot de passe incorrect")
        return None
    return user


def _regenerate_session() -> None:
    """Nouvel identifiant de session ; l'ancien est supprimé de Redis.

    Attention (Flask-Session 0.8) : regenerate() ne fait rien si la session est
    vide. On l'appelle donc toujours APRÈS y avoir écrit user_id.
    """
    current_app.session_interface.regenerate(session)


def login_user(user: User, password: str) -> None:
    """Ouvre une session neuve pour `user` (anti-fixation de session)."""
    session.clear()  # aucune donnée d'avant connexion ne survit
    session["user_id"] = user.id
    session["auth_time"] = datetime.now(timezone.utc)
    _regenerate_session()

    user.last_login_at = utcnow()
    # Si les paramètres Argon2 ont été renforcés depuis, on profite d'avoir le
    # mot de passe en clair (seul moment possible) pour recalculer le hash.
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    audit.log_event("LOGIN_SUCCESS", "SUCCESS", actor_id=user.id, target_type="user", target_id=user.id)


def logout_user(user: User | None) -> None:
    if user is not None:
        audit.log_event("LOGOUT", "SUCCESS", actor_id=user.id, target_type="user", target_id=user.id)
    session.clear()  # Flask-Session supprime la session dans Redis et efface le cookie


def change_password(user: User, current: str, new: str) -> list[str]:
    """Change le mot de passe. Retourne la liste des erreurs (vide = succès)."""
    if not verify_password(user.password_hash, current):
        audit.log_event("PASSWORD_CHANGE", "FAILURE", actor_id=user.id,
                        target_type="user", target_id=user.id, details="mot de passe actuel incorrect")
        return ["Mot de passe actuel incorrect."]

    errors = validate_password(new, user.username)
    if not errors and new == current:
        errors.append("Le nouveau mot de passe doit être différent de l'actuel.")
    if errors:
        return errors

    user.password_hash = hash_password(new)
    user.password_changed_at = utcnow()
    _regenerate_session()  # un éventuel cookie volé avant le changement devient inutile
    audit.log_event("PASSWORD_CHANGE", "SUCCESS", actor_id=user.id, target_type="user", target_id=user.id)
    return []


def is_safe_next(target: str | None) -> bool:
    """Empêche la redirection ouverte : seul un chemin interne est accepté.

    Refusé : "https://pirate.example", "//pirate.example" (même schéma, autre
    site), "/\\pirate.example" (interprété comme // par certains navigateurs).
    """
    return bool(target) and target.startswith("/") and not target.startswith(("//", "/\\"))
