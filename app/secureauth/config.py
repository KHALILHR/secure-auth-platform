"""Configuration chargée depuis les variables d'environnement.

Principe « fail fast » : si un secret manque ou si une clé n'a pas la bonne
taille, l'application refuse de démarrer au lieu de tourner en mode dégradé.
"""
import base64
import binascii
import os
from datetime import timedelta

import redis


def _required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Variable d'environnement manquante : {name}")
    return value


def _key_256(name: str) -> bytes:
    """Décode une clé base64 et vérifie qu'elle fait exactement 32 octets (256 bits)."""
    try:
        raw = base64.b64decode(_required(name), validate=True)
    except binascii.Error as exc:
        raise RuntimeError(f"{name} n'est pas du base64 valide") from exc
    if len(raw) != 32:
        raise RuntimeError(f"{name} doit faire 32 octets une fois décodée (reçu : {len(raw)})")
    return raw


def load_config() -> dict:
    encryption_key = _key_256("ENCRYPTION_KEY")
    hmac_key = _key_256("HMAC_KEY")
    if encryption_key == hmac_key:
        raise RuntimeError("ENCRYPTION_KEY et HMAC_KEY doivent être différentes")

    return {
        "SECRET_KEY": _required("SECRET_KEY"),

        # Base de données
        "SQLALCHEMY_DATABASE_URI": _required("DATABASE_URL"),
        "SQLALCHEMY_ENGINE_OPTIONS": {"pool_pre_ping": True, "pool_recycle": 280},

        # Sessions côté serveur (Redis) : le cookie ne contient qu'un identifiant aléatoire
        "SESSION_TYPE": "redis",
        "SESSION_REDIS": redis.from_url(_required("REDIS_URL")),
        "SESSION_KEY_PREFIX": "sess:",
        "SESSION_PERMANENT": True,
        "PERMANENT_SESSION_LIFETIME": timedelta(minutes=30),

        # Drapeaux du cookie de session
        "SESSION_COOKIE_NAME": "__Host-sid",   # préfixe __Host- : Secure, Path=/, sans Domain
        "SESSION_COOKIE_SECURE": True,
        "SESSION_COOKIE_HTTPONLY": True,
        "SESSION_COOKIE_SAMESITE": "Lax",

        "MAX_CONTENT_LENGTH": 2 * 1024 * 1024,

        # Clés cryptographiques (utilisées en semaine 3), jamais stockées en base
        "ENCRYPTION_KEY": encryption_key,
        "HMAC_KEY": hmac_key,
    }
