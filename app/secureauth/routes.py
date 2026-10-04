from flask import Blueprint, current_app, g, jsonify, redirect, render_template, url_for
from sqlalchemy import text

from .extensions import db

bp = Blueprint("core", __name__)


@bp.get("/")
def index():
    # Plan §9 : anonyme → connexion. (La redirection vers /documents arrivera en semaine 3.)
    if g.user is None:
        return redirect(url_for("auth.login"))
    return render_template("home.html")


@bp.get("/health")
def health():
    """Vérifie les dépendances sans jamais exposer le détail des erreurs."""
    checks = {}
    try:
        db.session.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception:
        db.session.rollback()
        checks["database"] = "down"
    try:
        current_app.config["SESSION_REDIS"].ping()
        checks["redis"] = "ok"
    except Exception:
        checks["redis"] = "down"

    healthy = all(state == "ok" for state in checks.values())
    return jsonify(status="ok" if healthy else "degraded", checks=checks), 200 if healthy else 503
