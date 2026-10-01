import click
from flask.cli import with_appcontext

from . import models  # noqa: F401
from .extensions import db


@click.command("init-db")
@with_appcontext
def init_db_command():
    """Crée les tables manquantes (sans toucher aux tables existantes)."""
    db.create_all()
    click.echo("Tables présentes : " + ", ".join(sorted(db.metadata.tables)))
