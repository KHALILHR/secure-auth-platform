"""Mots de passe : hachage Argon2id, hash factice anti-énumération, politique.

Analogie : on ne range jamais la clé de l'appartement chez le gardien, seulement
une serrure sur mesure (le hash) qui ne s'ouvre que avec la bonne clé et qu'on ne
peut pas « refondre » en clé. Argon2id rend chaque essai volontairement lent et
coûteux en mémoire, ce qui ruine la force brute.
"""
import secrets
from functools import lru_cache
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

MIN_LENGTH = 12
MAX_LENGTH = 128  # borne haute : évite qu'un mot de passe géant serve à saturer le serveur

_COMMON_FILE = Path(__file__).with_name("common_passwords.txt")

# Paramètres par défaut d'argon2-cffi = Argon2id (voir plan §7.1)
_hasher = PasswordHasher()

# Hash précalculé d'un secret aléatoire jamais divulgué. Sert à « payer » le même
# temps de calcul quand le compte n'existe pas (voir verify_or_dummy).
DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(32))


def hash_password(password: str) -> str:
    """Retourne l'empreinte Argon2id (sel aléatoire inclus dans la chaîne)."""
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Vrai si le mot de passe correspond. Ne lève jamais d'exception."""
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        # VerifyMismatch hérite de VerificationError ; un hash corrompu = refus
        return False


def needs_rehash(password_hash: str) -> bool:
    """Vrai si les paramètres du hash sont plus faibles que la configuration actuelle."""
    try:
        return _hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True


def verify_or_dummy(password_hash: str | None, password: str) -> bool:
    """Vérifie un mot de passe en prenant le même temps que le compte existe ou non.

    Si `password_hash` est None (compte inconnu), on vérifie quand même contre le
    hash factice puis on refuse : un attaquant ne peut pas deviner quels comptes
    existent en mesurant le temps de réponse.
    """
    if password_hash is None:
        verify_password(DUMMY_HASH, password)
        return False
    return verify_password(password_hash, password)


@lru_cache(maxsize=1)
def _common_passwords() -> frozenset[str]:
    lines = _COMMON_FILE.read_text(encoding="utf-8").splitlines()
    return frozenset(line.strip().lower() for line in lines if line.strip() and not line.startswith("#"))


def validate_password(password: str, username: str = "") -> list[str]:
    """Contrôle la politique du plan §7.1. Retourne la liste des problèmes (vide = valide)."""
    errors = []
    if len(password) < MIN_LENGTH:
        errors.append(f"Le mot de passe doit contenir au moins {MIN_LENGTH} caractères.")
    if len(password) > MAX_LENGTH:
        errors.append(f"Le mot de passe ne doit pas dépasser {MAX_LENGTH} caractères.")
    if username and password.lower() == username.lower():
        errors.append("Le mot de passe doit être différent du nom d'utilisateur.")
    if password.lower() in _common_passwords():
        errors.append("Ce mot de passe est trop courant.")
    return errors
