"""Contrôle des fichiers déposés (PDF, DOC, DOCX).

Trois barrières, dans cet ordre : la taille, l'extension (liste blanche) puis la signature
du contenu. Un fichier nommé « rapport.pdf » qui n'est pas un PDF est refusé : l'extension
seule ne prouve rien, c'est l'attaquant qui la choisit.

Ce contrôle vérifie le FORMAT, pas l'innocuité : un PDF bien formé peut contenir du code
actif. C'est pourquoi le fichier n'est jamais affiché par le navigateur : il est servi en
téléchargement (`Content-Disposition: attachment`) avec un type fixé par le serveur et
`X-Content-Type-Options: nosniff`.
"""
import io
import re
import zipfile

UPLOAD_MAX_BYTES = 8 * 1024 * 1024                       # taille maximale d'un fichier (8 Mo)
REQUEST_MAX_BYTES = UPLOAD_MAX_BYTES + 512 * 1024        # + formulaire multipart autour du fichier

OLE_SIGNATURE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"      # anciens .doc (conteneur OLE2)

# extension -> type MIME servi au téléchargement (jamais celui annoncé par le client)
MIME_TYPES = {
    "pdf": "application/pdf",
    "doc": "application/msword",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}
ACCEPT_ATTRIBUTE = ".pdf,.doc,.docx"


class UploadError(Exception):
    """Fichier refusé ; le message est destiné à l'utilisateur."""


def extension_of(filename: str) -> str:
    return filename.rsplit(".", 1)[-1].lower() if "." in filename else ""


def clean_filename(raw: str | None) -> str:
    """Nom de fichier sûr : pas de chemin, pas de caractère de contrôle, pas de séparateur.

    Le nom n'est jamais utilisé pour écrire sur le disque (le fichier va chiffré en base), mais il
    est renvoyé dans l'en-tête Content-Disposition : il ne doit contenir ni retour à la ligne ni guillemet.
    """
    name = (raw or "").replace("\\", "/").rsplit("/", 1)[-1]
    name = re.sub(r"[^\w.\- ()]", "_", name, flags=re.UNICODE).strip(" .")
    return name[:120]


def _looks_like_docx(data: bytes) -> bool:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = set(archive.namelist())
    except (zipfile.BadZipFile, OSError):
        return False
    return "[Content_Types].xml" in names and any(name.startswith("word/") for name in names)


def signature_matches(extension: str, data: bytes) -> bool:
    if extension == "pdf":
        return data.startswith(b"%PDF-")
    if extension == "doc":
        return data.startswith(OLE_SIGNATURE)
    if extension == "docx":
        return data.startswith(b"PK\x03\x04") and _looks_like_docx(data)
    return False


def validate_upload(raw_name: str | None, data: bytes) -> tuple[str, str]:
    """Retourne (nom nettoyé, extension) ou lève UploadError."""
    name = clean_filename(raw_name)
    extension = extension_of(name)
    if extension not in MIME_TYPES:
        raise UploadError("Format refusé : seuls les fichiers PDF, DOC et DOCX sont acceptés.")
    if not data:
        raise UploadError("Le fichier est vide.")
    if len(data) > UPLOAD_MAX_BYTES:
        raise UploadError(f"Fichier trop volumineux (maximum {UPLOAD_MAX_BYTES // (1024 * 1024)} Mo).")
    if not signature_matches(extension, data):
        raise UploadError("Le contenu ne correspond pas à l'extension du fichier.")
    return name, extension


def mimetype_for(filename: str) -> str:
    return MIME_TYPES.get(extension_of(filename), "application/octet-stream")


def human_size(size: int) -> str:
    if size < 1024:
        return f"{size} o"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} Ko"
    return f"{size / (1024 * 1024):.1f} Mo"
