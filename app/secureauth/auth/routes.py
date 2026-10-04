"""Blueprint auth : squelette (plan §9). Le formulaire complet arrive à la tâche 5."""
from flask import Blueprint, render_template

bp = Blueprint("auth", __name__, url_prefix="/auth")


@bp.get("/login")
def login():
    # Remplacé à la tâche 5 : formulaire + vérification Argon2id + régénération de session.
    return render_template("auth/login.html")


@bp.post("/logout")
def logout():
    # Remplacé à la tâche 5 : session.clear() + journal LOGOUT. CSRF déjà actif globalement.
    from flask import redirect, session, url_for

    session.clear()
    return redirect(url_for("auth.login"))
