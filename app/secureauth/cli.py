import click
from flask.cli import with_appcontext

from . import models  # noqa: F401
from .extensions import db
from .security import audit


@click.command("init-db")
@with_appcontext
def init_db_command():
    """Crée les tables manquantes (sans toucher aux tables existantes)."""
    db.create_all()
    audit.ensure_chain_head()
    click.echo("Tables présentes : " + ", ".join(sorted(db.metadata.tables)))


@click.command("verify-audit")
@with_appcontext
def verify_audit_command():
    """Recalcule la chaîne HMAC du journal d'audit et signale la première anomalie."""
    report = audit.verify_chain()
    if report.ok:
        click.echo(f"Chaîne intègre : {report.checked} ligne(s) vérifiée(s).")
    else:
        click.echo(
            f"CHAÎNE CORROMPUE à la ligne {report.first_bad_id} : {report.reason} "
            f"({report.checked} ligne(s) valide(s) avant l'anomalie).",
            err=True,
        )
    # La vérification est elle-même tracée (ajoutée APRÈS le contrôle)
    audit.log_event(
        "AUDIT_VERIFY",
        "SUCCESS" if report.ok else "FAILURE",
        details=f"cli, lignes valides={report.checked}, premiere_anomalie={report.first_bad_id}",
    )
    if not report.ok:
        raise SystemExit(1)
