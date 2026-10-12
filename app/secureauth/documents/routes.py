"""Routes de l'espace documents (EF-07 à EF-13).

Règle d'or : un document qu'on n'a pas le droit de lire répond 404, comme s'il
n'existait pas (ES-01). Le refus est journalisé (DOC_ACCESS_DENIED) mais ne dit rien
à l'utilisateur sur l'existence du document.
"""
import io

from flask import Blueprint, abort, flash, g, redirect, render_template, request, send_file, url_for

from ..extensions import db
from ..models import CLASSIFICATION_LABELS, User
from ..security import audit, policy
from ..security.crypto import IntegrityError
from ..security.decorators import login_required
from . import service, uploads
from .forms import DocumentForm, GrantForm, RevokeForm, UploadForm

bp = Blueprint("documents", __name__, url_prefix="/documents")


def _document_or_404(public_id: str):
    doc = service.get_by_public_id(public_id)
    if doc is None:
        abort(404)
    return doc


@bp.get("/")
@login_required
def index():
    items = []
    for doc in policy.readable_documents(g.user):
        try:
            title, _ = service.open_document(g.user, doc)
        except IntegrityError:
            title = None  # document altéré : signalé, jamais affiché
        items.append({"doc": doc, "title": title})
    return render_template("documents/list.html", items=items)


@bp.route("/new", methods=["GET", "POST"])
@login_required
def new():
    form = DocumentForm()
    form.set_choices(policy.max_creation_level(g.user))

    if _forged_level():
        return render_template("documents/new.html", form=form), 403

    if form.validate_on_submit():
        try:
            doc = service.create_document(g.user, form.title.data, form.content.data, form.classification.data)
        except service.NotAllowed:
            abort(403)
        flash(f"Document {doc.reference} créé et chiffré.", "success")
        return _after_creation(doc)
    return render_template("documents/new.html", form=form)


def _forged_level() -> bool:
    """Vrai (et refus tracé) si la requête demande une classification que l'acteur n'a pas le droit de donner."""
    if request.method != "POST":
        return False
    requested = request.form.get("classification", type=int)
    if requested is None or policy.can_create(g.user, requested):
        return False
    # Niveau forgé dans la requête (champ modifié) : refusé et tracé (T16)
    audit.log_event("DOC_CREATE", "DENIED", actor_id=g.user.id,
                    details=f"niveau {requested} au-dessus de l'habilitation {g.user.clearance_level}")
    flash("Vous ne pouvez pas créer un document au-dessus de votre habilitation.", "error")
    return True


def _after_creation(doc):
    """Après un dépôt : l'auteur lit son document ; l'administrateur (qui ne lit pas) passe au partage."""
    if policy.can_read(g.user, doc):
        return redirect(url_for("documents.read", public_id=doc.public_id))
    flash("Vous ne pouvez pas lire ce niveau de classification : confiez le document aux agents habilités.", "success")
    return redirect(url_for("documents.access", public_id=doc.public_id))


@bp.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    form = UploadForm()
    form.set_choices(policy.max_creation_level(g.user))

    if _forged_level():
        return render_template("documents/upload.html", form=form, accept=uploads.ACCEPT_ATTRIBUTE), 403

    if form.validate_on_submit():
        upload_file = form.file.data
        # +1 : un octet de trop suffit à détecter un fichier trop gros sans le lire en entier
        data = upload_file.read(uploads.UPLOAD_MAX_BYTES + 1)
        try:
            filename, _ = uploads.validate_upload(upload_file.filename, data)
        except uploads.UploadError as exc:
            audit.log_event("DOC_CREATE", "FAILURE", actor_id=g.user.id, details=f"fichier refusé : {exc}")
            flash(str(exc), "error")
            return render_template("documents/upload.html", form=form, accept=uploads.ACCEPT_ATTRIBUTE), 400
        title = form.title.data or filename.rsplit(".", 1)[0][:service.TITLE_MAX]
        try:
            doc = service.create_document(g.user, title, form.content.data or "", form.classification.data,
                                          filename=filename, file_bytes=data)
        except service.NotAllowed:
            abort(403)
        flash(f"Fichier déposé : {doc.reference}, chiffré avant enregistrement.", "success")
        return _after_creation(doc)
    return render_template("documents/upload.html", form=form, accept=uploads.ACCEPT_ATTRIBUTE)


@bp.get("/<public_id>")
@login_required
def read(public_id):
    doc = _document_or_404(public_id)
    if not policy.can_read(g.user, doc):
        service.log_denied_read(g.user, doc)
        abort(404)  # jamais 403 : on ne confirme pas l'existence d'un document classifié
    try:
        meta = service.open_metadata(g.user, doc)
    except IntegrityError:
        abort(500)  # déjà journalisé (INTEGRITY_FAILURE) ; aucun contenu n'est transmis
    service.log_read(g.user, doc)
    return render_template("documents/read.html", doc=doc, title=meta["title"], content=meta["content"],
                           filename=meta["filename"], file_size=uploads.human_size(doc.file_size) if doc.has_file else None,
                           can_share=policy.can_list_access(g.user, doc))


@bp.get("/<public_id>/download")
@login_required
def download(public_id):
    doc = _document_or_404(public_id)
    if not policy.can_read(g.user, doc):
        service.log_denied_read(g.user, doc)
        abort(404)
    if not doc.has_file:
        abort(404)
    try:
        filename, data = service.open_file(g.user, doc)
    except IntegrityError:
        abort(500)  # déjà journalisé (INTEGRITY_FAILURE)
    service.log_download(g.user, doc)
    # Toujours en pièce jointe, avec un type fixé par le serveur : le navigateur n'exécute ni n'affiche rien
    # Le nom est nettoyé une seconde fois : un nom enregistré par un autre chemin ne doit jamais atteindre l'en-tête tel quel
    return send_file(io.BytesIO(data), mimetype=uploads.mimetype_for(filename), as_attachment=True,
                     download_name=uploads.clean_filename(filename) or "document")


@bp.get("/<public_id>/access")
@login_required
def access(public_id):
    doc = _document_or_404(public_id)
    if not policy.can_list_access(g.user, doc):
        service.log_denied_read(g.user, doc)
        abort(404)
    return render_template("documents/access.html", doc=doc, entries=service.access_entries(doc),
                           grant_form=GrantForm(), revoke_form=RevokeForm())


@bp.post("/<public_id>/access/grant")
@login_required
def grant(public_id):
    doc = _document_or_404(public_id)
    if not policy.can_list_access(g.user, doc):
        service.log_denied_read(g.user, doc)
        abort(404)
    form = GrantForm()
    if form.validate_on_submit():
        grantee = User.query.filter(db.func.lower(User.username) == form.username.data.lower()).first()
        if grantee is None:
            flash("Aucun agent de ce nom.", "error")
        else:
            ok, message = service.grant_access(g.user, grantee, doc)
            flash(message, "success" if ok else "error")
    else:
        flash("Nom d'utilisateur invalide.", "error")
    return redirect(url_for("documents.access", public_id=doc.public_id))


@bp.post("/<public_id>/access/revoke")
@login_required
def revoke(public_id):
    doc = _document_or_404(public_id)
    if not policy.can_list_access(g.user, doc):
        service.log_denied_read(g.user, doc)
        abort(404)
    form = RevokeForm()
    grantee = db.session.get(User, form.user_id.data) if form.validate_on_submit() else None
    if grantee is None:
        flash("Agent introuvable.", "error")
    else:
        ok, message = service.revoke_access(g.user, grantee, doc)
        flash(message, "success" if ok else "error")
    return redirect(url_for("documents.access", public_id=doc.public_id))
