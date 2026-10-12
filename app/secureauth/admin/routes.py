"""Espace administrateur (EF-14 à EF-19).

Toutes les routes exigent le rôle admin (403 sinon : l'existence de cet espace n'est
pas secrète). L'administrateur gère les comptes mais ne lit AUCUN document : ici, il ne
voit que des métadonnées (référence, classification, propriétaire), jamais un titre.
"""
from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for
from flask_wtf import FlaskForm
from wtforms import BooleanField, IntegerField, PasswordField, SelectField, StringField
from wtforms.validators import DataRequired, EqualTo, InputRequired, Length, NumberRange, Regexp

from ..auth.forms import EMAIL_PATTERN, USERNAME_PATTERN, strip
from ..extensions import db
from ..models import CLASSIFICATION_LABELS, AuditLog, DocumentAccess, SecureDocument, User
from ..security import audit, policy
from ..security.decorators import role_required
from ..security.passwords import MAX_LENGTH
from . import service

bp = Blueprint("admin", __name__, url_prefix="/admin")

PAGE_SIZE = 50


class ClearanceForm(FlaskForm):
    level = IntegerField("Habilitation", validators=[InputRequired(), NumberRange(min=0, max=3)])


class ActiveForm(FlaskForm):
    active = BooleanField("Actif")


class NewUserForm(FlaskForm):
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
    clearance = SelectField(
        "Habilitation de l'agent", coerce=int,
        choices=list(CLASSIFICATION_LABELS.items()),
    )
    password = PasswordField(
        "Mot de passe provisoire",
        validators=[
            DataRequired(message="Champ obligatoire."),
            Length(max=MAX_LENGTH, message=f"{MAX_LENGTH} caractères maximum."),
        ],
    )
    confirm = PasswordField(
        "Confirmer le mot de passe provisoire",
        validators=[EqualTo("password", message="Les deux mots de passe diffèrent.")],
    )


def _target_or_404(user_id: int) -> User:
    target = db.session.get(User, user_id)
    if target is None:
        abort(404)
    return target


@bp.get("/")
@role_required("admin")
def index():
    stats = {
        "users": User.query.count(),
        "active": User.query.filter_by(is_active=True).count(),
        "documents": SecureDocument.query.count(),
        "logs": AuditLog.query.count(),
    }
    return render_template("admin/index.html", stats=stats)


@bp.get("/users")
@role_required("admin")
def users():
    accounts = User.query.order_by(User.id).all()
    return render_template("admin/users.html", accounts=accounts, clearance_form=ClearanceForm(), active_form=ActiveForm())


@bp.route("/users/new", methods=["GET", "POST"])
@role_required("admin")
def new_user():
    form = NewUserForm()
    if form.validate_on_submit():
        user, errors = service.create_user(g.user, form.username.data, form.email.data,
                                           form.password.data, form.clearance.data)
        if user is not None:
            flash(f"Compte {user.username} créé ({CLASSIFICATION_LABELS[user.clearance_level]}). "
                  "Transmettez-lui le mot de passe provisoire : il devra le changer à sa première connexion.", "success")
            return redirect(url_for("admin.users"))
        for error in errors:
            flash(error, "error")
    return render_template("admin/user_new.html", form=form)


@bp.post("/users/<int:user_id>/clearance")
@role_required("admin")
def set_clearance(user_id):
    target = _target_or_404(user_id)
    form = ClearanceForm()
    if not form.validate_on_submit():
        flash("Niveau d'habilitation invalide (0 à 3).", "error")
        return redirect(url_for("admin.users"))
    if not policy.can_admin_modify(g.user, target):
        audit.log_event("ADMIN_SELF_MODIFY_DENIED", "DENIED", actor_id=g.user.id, target_type="user",
                        target_id=target.id, details="tentative de modifier sa propre habilitation")
        flash("Vous ne pouvez pas modifier vos propres droits.", "error")
        return redirect(url_for("admin.users"))
    old, new = target.clearance_level, form.level.data
    target.clearance_level = new
    audit.log_event("CLEARANCE_CHANGE", "SUCCESS", actor_id=g.user.id, target_type="user", target_id=target.id,
                    details=f"{target.username} : {CLASSIFICATION_LABELS[old]} -> {CLASSIFICATION_LABELS[new]}")
    flash(f"Habilitation de {target.username} : {CLASSIFICATION_LABELS[new]}.", "success")
    return redirect(url_for("admin.users"))


@bp.post("/users/<int:user_id>/active")
@role_required("admin")
def set_active(user_id):
    target = _target_or_404(user_id)
    form = ActiveForm()
    if not form.validate_on_submit():
        abort(400)
    if not policy.can_admin_modify(g.user, target):
        audit.log_event("ADMIN_SELF_MODIFY_DENIED", "DENIED", actor_id=g.user.id, target_type="user",
                        target_id=target.id, details="tentative de désactiver son propre compte")
        flash("Vous ne pouvez pas modifier votre propre compte.", "error")
        return redirect(url_for("admin.users"))
    target.is_active = form.active.data
    audit.log_event("ACCOUNT_ENABLE" if target.is_active else "ACCOUNT_DISABLE", "SUCCESS", actor_id=g.user.id,
                    target_type="user", target_id=target.id, details=target.username)
    flash(f"Compte {target.username} {'activé' if target.is_active else 'désactivé'}.", "success")
    return redirect(url_for("admin.users"))


@bp.get("/documents")
@role_required("admin")
def documents():
    if not policy.can_view_metadata(g.user):
        abort(403)
    rows = (
        db.session.query(SecureDocument, User, db.func.count(DocumentAccess.id))
        .join(User, User.id == SecureDocument.owner_id)
        .outerjoin(DocumentAccess, DocumentAccess.document_id == SecureDocument.id)
        .group_by(SecureDocument.id, User.id)
        .order_by(SecureDocument.id)
        .all()
    )
    return render_template("admin/documents.html", rows=rows)


@bp.get("/audit")
@role_required("admin")
def audit_log():
    page = request.args.get("page", 1, type=int)
    event = request.args.get("event", "", type=str)
    query = AuditLog.query
    if event in audit.EVENTS:
        query = query.filter(AuditLog.event == event)
    pagination = query.order_by(AuditLog.id.desc()).paginate(page=page, per_page=PAGE_SIZE, error_out=False)
    actor_ids = {row.actor_id for row in pagination.items if row.actor_id}
    names = {u.id: u.username for u in User.query.filter(User.id.in_(actor_ids)).all()} if actor_ids else {}
    return render_template("admin/audit.html", pagination=pagination, names=names,
                           events=sorted(audit.EVENTS), selected=event if event in audit.EVENTS else "")


@bp.route("/audit/verify", methods=["GET", "POST"])
@role_required("admin")
def verify():
    report = None
    if request.method == "POST":
        # CSRF vérifié globalement (CSRFProtect). La vérification est elle-même tracée, APRÈS le contrôle.
        report = audit.verify_chain()
        audit.log_event("AUDIT_VERIFY", "SUCCESS" if report.ok else "FAILURE", actor_id=g.user.id,
                        details=f"page admin, lignes valides={report.checked}, premiere_anomalie={report.first_bad_id}")
    return render_template("admin/verify.html", report=report)
