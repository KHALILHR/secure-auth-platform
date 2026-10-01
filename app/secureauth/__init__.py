from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix

from .config import load_config
from .extensions import csrf, db, server_session


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
    from .cli import init_db_command
    from .routes import bp as core_bp

    app.register_blueprint(core_bp)
    app.cli.add_command(init_db_command)
    return app
