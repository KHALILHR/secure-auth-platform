from datetime import datetime, timedelta, timezone

from flask import Flask, flash, g, redirect, render_template, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

from .config import load_config
from .documents.uploads import REQUEST_MAX_BYTES
from .extensions import csrf, db, limiter, server_session

# Durée de vie absolue d'une session, peu importe l'activité (plan §8)
ABSOLUTE_SESSION_LIFETIME = timedelta(hours=8)

# Seules pages ouvertes à un agent dont le mot de passe est provisoire : changer de mot de passe, se déconnecter
PASSWORD_CHANGE_ENDPOINTS = {None, "auth.password", "auth.logout", "static", "core.health"}


def create_app(config_overrides: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(load_config())
    if config_overrides:
        app.config.update(config_overrides)

    # Derrière Nginx : récupérer la vraie IP client et le schéma https
    # (indispensable pour les journaux d'audit et la limitation de tentatives)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    @app.before_request
    def allow_larger_body_for_upload_only():
        """2 Mo partout (formulaires), sauf la page de dépôt de fichier. Doit être enregistré AVANT la
        protection CSRF : elle lit le formulaire, et c'est cette lecture qui applique la limite."""
        if request.endpoint == "documents.upload":
            request.max_content_length = REQUEST_MAX_BYTES

    db.init_app(app)
    server_session.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    from . import models  # noqa: F401  (enregistre les tables)
    from .admin.routes import bp as admin_bp
    from .auth.routes import bp as auth_bp
    from .cli import create_admin_command, init_db_command, seed_demo_command, verify_audit_command
    from .documents.routes import bp as documents_bp
    from .routes import bp as core_bp

    app.register_blueprint(core_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(documents_bp)
    app.register_blueprint(admin_bp)
    app.cli.add_command(init_db_command)
    app.cli.add_command(verify_audit_command)
    app.cli.add_command(create_admin_command)
    app.cli.add_command(seed_demo_command)

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

        # Mot de passe provisoire (compte créé par un administrateur) : rien d'autre n'est accessible
        # tant qu'il n'est pas remplacé. request.endpoint est None pour une URL inconnue (page 404).
        if user.must_change_password and request.endpoint not in PASSWORD_CHANGE_ENDPOINTS:
            flash("Choisissez un nouveau mot de passe avant de continuer.", "error")
            return redirect(url_for("auth.password"))

    @app.after_request
    def no_cache_for_authenticated_pages(response):
        """Une page affichée à un agent connecté (donc potentiellement un document) ne doit jamais
        rester dans le cache du navigateur ni d'un proxy : sinon le bouton « Précédent » la rouvrirait
        après la déconnexion."""
        if g.get("user") is not None:
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
        return response

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

    @app.errorhandler(413)
    def too_large(_error):
        return render_template("errors/413.html"), 413

    @app.errorhandler(429)
    def too_many_requests(_error):
        return render_template("errors/429.html"), 429

    @app.errorhandler(500)
    def server_error(_error):
        # Le détail reste dans les journaux Gunicorn ; jamais dans la réponse HTTP.
        return render_template("errors/500.html"), 500

    return app
