"""Chiffrement des documents : AES-256-GCM (cahier des charges, section 7).

Analogie : un coffre scellé. Le contenu est enfermé (chiffrement) ET le coffre porte
un sceau (étiquette GCM) qui casse si quelqu'un touche au contenu, ou à l'étiquette
collée dessus (les « données associées » : identifiant public, classification,
propriétaire). Ces données associées ne sont pas cachées, mais elles sont scellées :
si un attaquant passe un document de TRÈS SECRET à PUBLIC directement en base, le
déchiffrement échoue (InvalidTag) au lieu de livrer le document.

Règles : bibliothèque `cryptography` uniquement, nonce de 96 bits tiré au hasard à
CHAQUE chiffrement (jamais réutilisé avec la même clé), clé de 256 bits hors base.
"""
import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import current_app

NONCE_SIZE = 12  # 96 bits : taille recommandée pour GCM


class IntegrityError(Exception):
    """Le déchiffrement a échoué : contenu, nonce, clé ou données associées ne correspondent plus."""


def build_aad(public_id: str, classification: int, owner_id: int) -> bytes:
    """Données associées : lient le texte chiffré à SON document, SA classification, SON propriétaire."""
    return f"{public_id}|{classification}|{owner_id}".encode("utf-8")


def _key() -> bytes:
    return current_app.config["ENCRYPTION_KEY"]


def encrypt_document(title: str, content: str, *, public_id: str, classification: int,
                     owner_id: int, filename: str | None = None) -> tuple[bytes, bytes]:
    """Chiffre titre + contenu (+ nom du fichier déposé) ENSEMBLE : le titre d'un document secret
    est lui-même sensible, et le nom d'un fichier (« plan-operation-aurore.pdf ») l'est aussi.

    Retourne (nonce, ciphertext). Le ciphertext inclut l'étiquette GCM de 16 octets.
    """
    payload = {"title": title, "content": content}
    if filename is not None:
        payload["filename"] = filename
    plaintext = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    nonce = os.urandom(NONCE_SIZE)
    aad = build_aad(public_id, classification, owner_id)
    return nonce, AESGCM(_key()).encrypt(nonce, plaintext, aad)


def decrypt_metadata(nonce: bytes, ciphertext: bytes, *, public_id: str, classification: int,
                     owner_id: int) -> dict:
    """Déchiffre et authentifie titre, contenu et nom de fichier. Lève IntegrityError à la moindre incohérence."""
    aad = build_aad(public_id, classification, owner_id)
    try:
        plaintext = AESGCM(_key()).decrypt(nonce, ciphertext, aad)
        data = json.loads(plaintext.decode("utf-8"))
        return {"title": data["title"], "content": data["content"], "filename": data.get("filename")}
    except (InvalidTag, ValueError, KeyError, TypeError, AttributeError) as exc:
        # Message volontairement neutre : on ne dit pas POURQUOI (pas d'oracle pour l'attaquant)
        raise IntegrityError("intégrité du document compromise") from exc


def decrypt_document(nonce: bytes, ciphertext: bytes, *, public_id: str, classification: int,
                     owner_id: int) -> tuple[str, str]:
    """Déchiffre et authentifie. Lève IntegrityError à la moindre incohérence."""
    data = decrypt_metadata(nonce, ciphertext, public_id=public_id, classification=classification, owner_id=owner_id)
    return data["title"], data["content"]


def _file_aad(public_id: str, classification: int, owner_id: int) -> bytes:
    # Suffixe distinct : un blob de fichier ne peut pas être collé à la place des métadonnées (ni l'inverse)
    return build_aad(public_id, classification, owner_id) + b"|file"


def encrypt_file(data: bytes, *, public_id: str, classification: int, owner_id: int) -> tuple[bytes, bytes]:
    """Chiffre le contenu brut d'un fichier. Nonce neuf, tiré au hasard, jamais partagé avec les métadonnées."""
    nonce = os.urandom(NONCE_SIZE)
    return nonce, AESGCM(_key()).encrypt(nonce, data, _file_aad(public_id, classification, owner_id))


def decrypt_file(nonce: bytes, ciphertext: bytes, *, public_id: str, classification: int, owner_id: int) -> bytes:
    try:
        return AESGCM(_key()).decrypt(nonce, ciphertext, _file_aad(public_id, classification, owner_id))
    except (InvalidTag, ValueError, TypeError) as exc:
        raise IntegrityError("intégrité du fichier compromise") from exc
