"""Formulaires d'authentification (Flask-WTF : jeton CSRF inclus automatiquement).

Les formulaires ne vérifient que la FORME des données (longueur, caractères).
La politique de mot de passe et l'unicité des comptes sont dans service.py.
"""
from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField
from wtforms.validators import DataRequired, EqualTo, Length, Regexp

from ..security.passwords import MAX_LENGTH

def strip(value):
    """Retire les espaces autour d'un champ texte (copier-coller fréquent)."""
    return value.strip() if isinstance(value, str) else value


USERNAME_PATTERN = r"^[A-Za-z0-9_.-]{3,32}$"
# Contrôle de forme volontairement simple : la preuve qu'une adresse existe
# demanderait un e-mail de confirmation (hors périmètre).
EMAIL_PATTERN = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"


class RegisterForm(FlaskForm):
    username = StringField(
        "Nom d'utilisateur",
        filters=[strip],
        validators=[
            DataRequired(message="Champ obligatoire."),
            Regexp(USERNAME_PATTERN, message="3 à 32 caractères : lettres, chiffres, _ . -"),
        ],
    )
    email = StringField(
        "Adresse e-mail",
        filters=[strip],
        validators=[
            DataRequired(message="Champ obligatoire."),
            Length(max=255, message="255 caractères maximum."),
            Regexp(EMAIL_PATTERN, message="Adresse e-mail invalide."),
        ],
    )
    password = PasswordField(
        "Mot de passe",
        validators=[
            DataRequired(message="Champ obligatoire."),
            Length(max=MAX_LENGTH, message=f"{MAX_LENGTH} caractères maximum."),
        ],
    )
    confirm = PasswordField(
        "Confirmer le mot de passe",
        validators=[EqualTo("password", message="Les deux mots de passe diffèrent.")],
    )


class LoginForm(FlaskForm):
    identifier = StringField(
        "Nom d'utilisateur ou e-mail",
        filters=[strip],
        validators=[DataRequired(message="Champ obligatoire."), Length(max=255)],
    )
    password = PasswordField(
        "Mot de passe",
        validators=[DataRequired(message="Champ obligatoire."), Length(max=MAX_LENGTH)],
    )


class PasswordChangeForm(FlaskForm):
    current_password = PasswordField(
        "Mot de passe actuel",
        validators=[DataRequired(message="Champ obligatoire."), Length(max=MAX_LENGTH)],
    )
    new_password = PasswordField(
        "Nouveau mot de passe",
        validators=[DataRequired(message="Champ obligatoire."), Length(max=MAX_LENGTH)],
    )
    confirm = PasswordField(
        "Confirmer le nouveau mot de passe",
        validators=[EqualTo("new_password", message="Les deux mots de passe diffèrent.")],
    )
