import re

import click
from flask.cli import with_appcontext
from sqlalchemy import func, inspect, text
from sqlalchemy.schema import CreateColumn

from . import models  # noqa: F401
from .auth.forms import EMAIL_PATTERN, USERNAME_PATTERN
from .auth.service import normalize_email
from .extensions import db
from .models import SecureDocument, User
from .security import audit
from .security.passwords import hash_password, validate_password


def add_missing_columns() -> list[str]:
    """Ajoute à une base existante les colonnes apparues depuis sa création (create_all n'en fait rien).

    Uniquement des ajouts : jamais de suppression ni de modification, donc sans risque pour les données.
    Retourne la liste des colonnes ajoutées (« table.colonne »).
    """
    inspector = inspect(db.engine)
    added = []
    for table in db.metadata.sorted_tables:
        existing = {column["name"] for column in inspector.get_columns(table.name)}
        for column in table.columns:
            if column.name in existing:
                continue
            ddl = CreateColumn(column).compile(dialect=db.engine.dialect)
            db.session.execute(text(f"ALTER TABLE {table.name} ADD COLUMN {ddl}"))
            added.append(f"{table.name}.{column.name}")
    db.session.commit()
    return added


@click.command("init-db")
@with_appcontext
def init_db_command():
    """Crée les tables manquantes et ajoute les colonnes manquantes (sans toucher aux données)."""
    db.create_all()
    for name in add_missing_columns():
        click.echo(f"Colonne ajoutée : {name}")
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


# Jeu de données de la démonstration finale (cahier des charges, section 13).
# Les documents sont créés par le même service que l'interface : chiffrés, journalisés.
DEMO_USERS = (("alice", "alice@agence.example", 3), ("bob", "bob@agence.example", 2))
DEMO_DOCUMENTS = (
    # (référence, propriétaire, classification, titre, contenu, agents supplémentaires)
    ("TS-001", "alice", 3, "Opération Aurore : plan général",
     "Plan d'ensemble de l'opération. Diffusion limitée aux seuls agents habilités TRÈS SECRET.", ()),
    ("SEC-001", "alice", 2, "Note de synthèse trimestrielle",
     "Synthèse des activités du trimestre. Partagée avec bob pour relecture.", ("bob",)),
    ("SEC-002", "bob", 2, "Rapport de mission n°14",
     "Compte rendu de la mission 14, rédigé par bob.", ()),
    ("PUB-001", "alice", 0, "Charte d'utilisation du système",
     "Règles de bon usage du système d'information de l'agence.", ("bob",)),
)


@click.command("seed-demo")
@click.option("--password", prompt="Mot de passe commun aux comptes de démonstration", hide_input=True,
              confirmation_prompt=True, help="Appliqué à alice et bob (jamais passé en clair dans l'historique : saisie masquée).")
@with_appcontext
def seed_demo_command(password):
    """Crée les comptes alice (TRÈS SECRET) et bob (SECRET) et quatre documents de démonstration.

    Idempotent : ce qui existe déjà est conservé. Le premier administrateur se crée avec
    `flask create-admin` (jamais ici : un compte administrateur ne s'obtient que par la ligne de commande).
    """
    from .documents import service as documents

    errors = validate_password(password, "alice")
    if errors:
        raise click.ClickException(" ".join(errors))

    users = {}
    for username, email, level in DEMO_USERS:
        user = User.query.filter(func.lower(User.username) == username).first()
        if user is None:
            user = User(username=username, email=email, password_hash=hash_password(password), clearance_level=level)
            db.session.add(user)
            db.session.flush()
            audit.log_event("REGISTER", "SUCCESS", actor_id=user.id, target_type="user", target_id=user.id,
                            details="compte de démonstration (seed-demo)")
            click.echo(f"Compte créé : {username} (habilitation {level})")
        users[username] = user

    for reference, owner, level, title, content, extra in DEMO_DOCUMENTS:
        if SecureDocument.query.filter_by(reference=reference).first() is not None:
            continue
        doc = documents.create_document(users[owner], title, content, level, reference=reference)
        for name in extra:
            ok, message = documents.grant_access(users[owner], users[name], doc)
            if not ok:
                raise click.ClickException(f"{reference} : {message}")
        click.echo(f"Document créé : {reference} (propriétaire {owner})")
    click.echo("Jeu de démonstration prêt. Créez l'administrateur avec : flask create-admin")
