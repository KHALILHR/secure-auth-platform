"""Formulaires de l'espace documents (forme des champs uniquement ; les droits sont dans policy.py)."""
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import IntegerField, SelectField, StringField, TextAreaField
from wtforms.validators import DataRequired, Length, NumberRange, Optional

from ..auth.forms import strip
from ..models import CLASSIFICATION_LABELS
from .service import CONTENT_MAX, TITLE_MAX


class _ClassifiedForm(FlaskForm):
    def set_choices(self, max_level: int) -> None:
        """Seuls les niveaux jusqu'à `max_level` sont proposés (et revérifiés côté serveur)."""
        self.classification.choices = [(lvl, label) for lvl, label in CLASSIFICATION_LABELS.items() if lvl <= max_level]


class DocumentForm(_ClassifiedForm):
    title = StringField(
        "Titre",
        filters=[strip],
        validators=[DataRequired(message="Champ obligatoire."), Length(max=TITLE_MAX, message=f"{TITLE_MAX} caractères maximum.")],
    )
    classification = SelectField("Classification", coerce=int)
    content = TextAreaField(
        "Contenu",
        validators=[DataRequired(message="Champ obligatoire."), Length(max=CONTENT_MAX, message=f"{CONTENT_MAX} caractères maximum.")],
    )


class UploadForm(_ClassifiedForm):
    """Dépôt d'un fichier PDF, DOC ou DOCX. Le format réel est contrôlé par `uploads.validate_upload`."""

    file = FileField("Fichier (PDF, DOC ou DOCX)", validators=[FileRequired(message="Choisissez un fichier.")])
    title = StringField(
        "Titre (facultatif : le nom du fichier par défaut)",
        filters=[strip],
        validators=[Optional(), Length(max=TITLE_MAX, message=f"{TITLE_MAX} caractères maximum.")],
    )
    classification = SelectField("Classification", coerce=int)
    content = TextAreaField(
        "Description (facultative)",
        validators=[Optional(), Length(max=CONTENT_MAX, message=f"{CONTENT_MAX} caractères maximum.")],
        render_kw={"class": "compact", "rows": 4},
    )


class GrantForm(FlaskForm):
    username = StringField(
        "Nom d'utilisateur de l'agent",
        filters=[strip],
        validators=[DataRequired(message="Champ obligatoire."), Length(max=32)],
    )


class RevokeForm(FlaskForm):
    user_id = IntegerField("Agent", validators=[DataRequired(), NumberRange(min=1)])
