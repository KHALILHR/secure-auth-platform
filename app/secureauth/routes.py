from flask import Blueprint, current_app, jsonify
from sqlalchemy import text

from .extensions import db

bp = Blueprint("core", __name__)


@bp.get("/")
def index():
    return (
        "<!doctype html><html lang='fr'><head><meta charset='utf-8'>"
        "<title>SecureAuth</title></head><body>"
        "<h1>SecureAuth : infrastructure en ligne</h1>"
        "<p>Nginx (TLS) &rarr; Flask &rarr; MariaDB / Redis</p>"
        "</body></html>"
    )


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
