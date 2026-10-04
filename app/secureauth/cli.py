import re

import click
from flask.cli import with_appcontext
from sqlalchemy import func

from . import models  # noqa: F401
from .auth.forms import EMAIL_PATTERN, USERNAME_PATTERN
from .auth.service import normalize_email
from .extensions import db
from .models import User
from .security import audit
from .security.passwords import hash_password, validate_password


@click.command("init-db")
@with_appcontext
def init_db_command():
    """Crée les tables manquantes (sans toucher aux tables existantes)."""
    db.create_all()
    audit.ensure_chain_head()
    click.echo("Tables présentes : " + ", ".join(sorted(db.metadata.tables)))


@click.command("create-admin")
@click.option("--username", prompt="Nom d'utilisateur")
@click.option("--email", prompt="Adresse e-mail")
@with_appcontext
def create_admin_command(username, email):
    """Crée un administrateur. Seul moyen d'en créer un (plan §8).

    Le mot de passe est TOUJOURS demandé de façon interactive et masquée : un
    argument en ligne de commande resterait dans l'historique du terminal et
    serait visible dans la liste des processus.
    """
    username, email = username.strip(), normalize_email(email)
    if not re.fullmatch(USERNAME_PATTERN, username):
        raise click.ClickException("Nom d'utilisateur invalide (3 à 32 caractères : lettres, chiffres, _ . -).")
    if not re.fullmatch(EMAIL_PATTERN, email):
        raise click.ClickException("Adresse e-mail invalide.")
    if User.query.filter((func.lower(User.username) == username.lower()) | (User.email == email)).first():
        raise click.ClickException("Ce nom d'utilisateur ou cette adresse existe déjà.")

    password = click.prompt("Mot de passe", hide_input=True, confirmation_prompt="Confirmer le mot de passe")
    errors = validate_password(password, username)
    if errors:
        raise click.ClickException(" ".join(errors))

    admin = User(username=username, email=email, password_hash=hash_password(password),
                 role="admin", clearance_level=0)  # un admin gère, il ne lit pas (plan §2)
    db.session.add(admin)
    db.session.flush()
    audit.log_event("REGISTER", "SUCCESS", actor_id=admin.id, target_type="user",
                    target_id=admin.id, details="administrateur créé via la CLI")
    click.echo(f"Administrateur « {username} » créé.")


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
