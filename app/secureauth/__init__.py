from datetime import datetime, timedelta, timezone

from flask import Flask, g, render_template, session
from werkzeug.middleware.proxy_fix import ProxyFix

from .config import load_config
from .extensions import csrf, db, server_session

# Durée de vie absolue d'une session, peu importe l'activité (plan §8)
ABSOLUTE_SESSION_LIFETIME = timedelta(hours=8)


def create_app(config_overrides: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(load_config())
    if config_overrides:
        app.config.update(config_overrides)

    # Derrière Nginx : récupérer la vraie IP client et le schéma https
    # (indispensable pour les journaux d'audit et la limitation de tentatives)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    db.init_app(app)
    server_session.init_app(app)
    csrf.init_app(app)

    from . import models  # noqa: F401  (enregistre les tables)
    from .auth.routes import bp as auth_bp
    from .cli import create_admin_command, init_db_command, verify_audit_command
    from .routes import bp as core_bp

    app.register_blueprint(core_bp)
    app.register_blueprint(auth_bp)
    app.cli.add_command(init_db_command)
    app.cli.add_command(verify_audit_command)
    app.cli.add_command(create_admin_command)

    @app.before_request
    def load_logged_in_user():
        """Recharge g.user DEPUIS LA BASE à chaque requête (plan §5.2).

        On ne fait jamais confiance à ce que le cookie « sait » : seul
        l'identifiant numérique y est stocké. Tout le reste (rôle, habilitation,
        statut actif) est relu en base à chaque requête, donc une désactivation
        ou un changement d'habilitation par l'admin prend effet immédiatement,
        même si la victime a déjà une session ouverte.
        """
        from .models import User  # import tardif : évite un cycle au chargement du module

        g.user = None
        user_id = session.get("user_id")
        if user_id is None:
            return

        auth_time = session.get("auth_time")
        if auth_time is None or datetime.now(timezone.utc) - auth_time > ABSOLUTE_SESSION_LIFETIME:
            session.clear()  # durée absolue dépassée : session détruite même si "active"
            return

        user = db.session.get(User, user_id)
        if user is None or not user.is_active:
            session.clear()  # compte supprimé ou désactivé entre-temps
            return

        g.user = user

    @app.context_processor
    def inject_classification_labels():
        from .models import CLASSIFICATION_LABELS

        return {"classification_labels": CLASSIFICATION_LABELS}

    @app.errorhandler(403)
    def forbidden(_error):
        return render_template("errors/403.html"), 403

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def server_error(_error):
        # Le détail reste dans les journaux Gunicorn ; jamais dans la réponse HTTP.
        return render_template("errors/500.html"), 500

    return app
