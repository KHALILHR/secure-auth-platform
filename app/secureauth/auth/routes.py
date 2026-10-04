"""Routes d'authentification (plan §9) : les décisions sont dans service.py."""
from flask import Blueprint, flash, g, redirect, render_template, request, url_for

from ..security.decorators import login_required
from . import service
from .forms import LoginForm, PasswordChangeForm, RegisterForm

bp = Blueprint("auth", __name__, url_prefix="/auth")


@bp.route("/register", methods=["GET", "POST"])
def register():
    if g.user is not None:
        return redirect(url_for("core.index"))

    form = RegisterForm()
    if form.validate_on_submit():
        user, errors = service.register_user(form.username.data, form.email.data, form.password.data)
        if user is not None:
            flash("Compte créé. Vous pouvez vous connecter.", "success")
            return redirect(url_for("auth.login"))
        for error in errors:
            flash(error, "error")
    return render_template("auth/register.html", form=form)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if g.user is not None:
        return redirect(url_for("core.index"))

    form = LoginForm()
    if form.validate_on_submit():
        user = service.authenticate(form.identifier.data, form.password.data)
        if user is not None:
            service.login_user(user, form.password.data)
            target = request.args.get("next")
            return redirect(target if service.is_safe_next(target) else url_for("core.index"))
        flash(service.LOGIN_REFUSED, "error")
    return render_template("auth/login.html", form=form)


@bp.post("/logout")
@login_required
def logout():
    service.logout_user(g.user)
    flash("Vous êtes déconnecté.", "success")
    return redirect(url_for("auth.login"))


@bp.route("/password", methods=["GET", "POST"])
@login_required
def password():
    form = PasswordChangeForm()
    if form.validate_on_submit():
        errors = service.change_password(g.user, form.current_password.data, form.new_password.data)
        if not errors:
            flash("Mot de passe modifié.", "success")
            return redirect(url_for("core.index"))
        for error in errors:
            flash(error, "error")
    return render_template("auth/password.html", form=form)
