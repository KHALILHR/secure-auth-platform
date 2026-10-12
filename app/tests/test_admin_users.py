"""Création de comptes par l'administrateur, mot de passe provisoire, migration de schéma, politique de dépôt."""
import pytest
from sqlalchemy import inspect, text

from helpers import PASSWORD, csrf_token, events, logged_in, login, make_user, post

from secureauth.cli import add_missing_columns
from secureauth.extensions import db
from secureauth.models import AuditLog, User
from secureauth.security import policy
from secureauth.security.passwords import verify_password

TEMP_PASSWORD = "Provisoire-Zebre-Nuage-77"


def create(client, **overrides):
    data = {"username": "carole", "email": "Carole@Agence.example", "clearance": 2,
            "password": TEMP_PASSWORD, "confirm": TEMP_PASSWORD}
    data.update(overrides)
    return post(client, "/admin/users/new", data, token_page="/admin/users/new")


# --- Création -------------------------------------------------------------------------------------------

def test_admin_creates_an_agent_with_the_chosen_clearance(app):
    admin, root = logged_in(app, "root", role="admin")
    assert admin.get("/admin/users/new").status_code == 200
    resp = create(admin, clearance=3)
    assert resp.status_code == 302 and resp.headers["Location"].endswith("/admin/users")
    carole = User.query.filter_by(username="carole").one()
    assert carole.role == "user" and carole.clearance_level == 3 and carole.is_active
    assert carole.email == "carole@agence.example"           # normalisé en minuscules
    assert carole.must_change_password is True
    assert carole.password_hash.startswith("$argon2id$") and verify_password(carole.password_hash, TEMP_PASSWORD)


def test_creation_is_audited_without_the_password(app):
    admin, root = logged_in(app, "root", role="admin")
    create(admin, clearance=2)
    entry = events("USER_CREATE")[0]
    assert entry.actor_id == root.id and entry.outcome == "SUCCESS" and entry.target_type == "user"
    assert "carole" in entry.details and "SECRET" in entry.details
    assert all(TEMP_PASSWORD not in (row.details or "") for row in AuditLog.query.all())


def test_every_clearance_level_can_be_chosen(app):
    admin, _ = logged_in(app, "root", role="admin")
    for level in range(4):
        create(admin, username=f"agent{level}", email=f"agent{level}@agence.example", clearance=level)
    assert sorted(u.clearance_level for u in User.query.filter(User.username.like("agent%"))) == [0, 1, 2, 3]


def test_the_form_shows_the_four_levels_and_the_users_page_links_to_it(app):
    admin, _ = logged_in(app, "root", role="admin")
    page = admin.get("/admin/users/new").data.decode()
    for label in ("PUBLIC", "CONFIDENTIEL", "SECRET", "TRÈS SECRET"):
        assert label in page
    assert "/admin/users/new" in admin.get("/admin/users").data.decode()
    assert "Mot de passe provisoire" in (create(admin) and admin.get("/admin/users").data.decode())


# --- Refus ----------------------------------------------------------------------------------------------

def test_agent_cannot_create_accounts(app):
    alice, _ = logged_in(app, "alice", clearance=3)
    assert alice.get("/admin/users/new").status_code == 403
    assert create(alice).status_code == 403
    assert User.query.filter_by(username="carole").first() is None


def test_anonymous_is_sent_to_login(app):
    resp = app.test_client().get("/admin/users/new")
    assert resp.status_code == 302 and "/auth/login" in resp.headers["Location"]


def test_creation_without_csrf_token_is_rejected(app):
    admin, _ = logged_in(app, "root", role="admin")
    resp = admin.post("/admin/users/new", data={"username": "carole", "email": "c@a.example", "clearance": 1,
                                                "password": TEMP_PASSWORD, "confirm": TEMP_PASSWORD})
    assert resp.status_code == 400 and User.query.filter_by(username="carole").first() is None


def test_disabled_admin_cannot_create(app):
    admin_user = make_user("root", role="admin", active=False)
    assert not policy.can_create_user(admin_user)


@pytest.mark.parametrize("overrides", [
    {"username": "ab"},                                   # trop court
    {"username": "avec espace"},
    {"email": "pas-une-adresse"},
    {"password": "court", "confirm": "court"},            # politique de mot de passe
    {"password": "Provisoire-Zebre-Nuage-77", "confirm": "autre-chose"},
    {"username": "carole-carole-12", "password": "carole-carole-12", "confirm": "carole-carole-12"},  # = le nom
    {"clearance": 4},                                      # niveau inexistant
    {"clearance": -1},
])
def test_invalid_input_creates_nothing(app, overrides):
    admin, _ = logged_in(app, "root", role="admin")
    resp = create(admin, **overrides)
    assert resp.status_code == 200
    assert User.query.filter_by(role="user").count() == 0 and not events("USER_CREATE")


def test_duplicate_username_or_email_is_refused(app):
    admin, _ = logged_in(app, "root", role="admin")
    make_user("carole")
    assert "déjà utilisé" in create(admin).data.decode()
    assert "déjà utilisé" in create(admin, username="autre", email="CAROLE@example.com").data.decode()
    assert User.query.count() == 2   # root + carole d'origine


def test_a_forged_role_field_is_ignored(app):
    admin, _ = logged_in(app, "root", role="admin")
    create(admin, role="admin", is_active="", must_change_password="")
    carole = User.query.filter_by(username="carole").one()
    assert carole.role == "user" and carole.must_change_password is True


# --- Mot de passe provisoire -----------------------------------------------------------------------------

def test_new_agent_must_change_the_password_before_anything_else(app):
    admin, _ = logged_in(app, "root", role="admin")
    create(admin, clearance=2)
    carole = app.test_client()
    assert login(carole, "carole", TEMP_PASSWORD).status_code == 302

    for url in ("/", "/documents/", "/documents/new", "/documents/upload", "/admin/users"):
        resp = carole.get(url)
        assert resp.status_code == 302 and resp.headers["Location"].endswith("/auth/password"), url
    assert carole.get("/auth/password").status_code == 200
    assert carole.get("/health").status_code in (200, 503)   # sonde technique, sans donnée


def test_changing_the_password_unlocks_the_account(app):
    admin, _ = logged_in(app, "root", role="admin")
    create(admin, clearance=2)
    carole = app.test_client()
    login(carole, "carole", TEMP_PASSWORD)
    new_password = "Nouveau-Secret-Colibri-91"
    resp = post(carole, "/auth/password", {"current_password": TEMP_PASSWORD, "new_password": new_password,
                                           "confirm": new_password}, token_page="/auth/password")
    assert resp.status_code == 302
    assert User.query.filter_by(username="carole").one().must_change_password is False
    assert carole.get("/documents/").status_code == 200
    # l'ancien mot de passe provisoire ne fonctionne plus
    assert login(app.test_client(), "carole", TEMP_PASSWORD).status_code == 200
    assert login(app.test_client(), "carole", new_password).status_code == 302


def test_wrong_current_password_keeps_the_restriction(app):
    admin, _ = logged_in(app, "root", role="admin")
    create(admin)
    carole = app.test_client()
    login(carole, "carole", TEMP_PASSWORD)
    post(carole, "/auth/password", {"current_password": "mauvais", "new_password": "Nouveau-Secret-Colibri-91",
                                    "confirm": "Nouveau-Secret-Colibri-91"}, token_page="/auth/password")
    assert User.query.filter_by(username="carole").one().must_change_password is True
    assert carole.get("/documents/").status_code == 302


def test_logout_stays_possible_while_the_password_is_provisional(app):
    admin, _ = logged_in(app, "root", role="admin")
    create(admin)
    carole = app.test_client()
    login(carole, "carole", TEMP_PASSWORD)
    assert post(carole, "/auth/logout", token_page="/auth/password").status_code == 302
    assert carole.get("/documents/").headers["Location"].startswith("/auth/login")


def test_ordinary_registration_is_not_affected(app):
    alice, user = logged_in(app, "alice")
    assert user.must_change_password is False and alice.get("/documents/").status_code == 200


# --- Migration de schéma ------------------------------------------------------------------------------------

def test_add_missing_columns_upgrades_an_old_database_without_losing_data(app):
    from helpers import new_document

    owner = make_user("alice", clearance=1)
    doc = new_document(owner, level=1)
    db.session.commit()
    for table, column in (("users", "must_change_password"), ("secure_documents", "file_size"),
                          ("secure_documents", "file_nonce"), ("secure_documents", "file_ciphertext")):
        db.session.execute(text(f"ALTER TABLE {table} DROP COLUMN {column}"))
    db.session.commit()
    assert "file_size" not in {c["name"] for c in inspect(db.engine).get_columns("secure_documents")}

    added = add_missing_columns()
    assert sorted(added) == ["secure_documents.file_ciphertext", "secure_documents.file_nonce",
                             "secure_documents.file_size", "users.must_change_password"]
    assert add_missing_columns() == []                      # idempotent
    db.session.expire_all()
    assert User.query.one().must_change_password is False   # valeur par défaut des lignes existantes
    assert db.session.get(type(doc), doc.id).has_file is False


# --- Politique de dépôt -----------------------------------------------------------------------------------

def test_creation_levels_per_role(app):
    admin = make_user("root", role="admin", clearance=0)
    agent = make_user("bob", clearance=2)
    assert policy.max_creation_level(admin) == 3 and policy.max_creation_level(agent) == 2
    assert all(policy.can_create(admin, level) for level in range(4))
    assert not policy.can_create(admin, 4) and not policy.can_create(admin, -1)
    assert not policy.can_create(agent, 3)
    assert not policy.can_read(admin, _doc_owned_by(admin, 3))   # classer ≠ pouvoir lire


def _doc_owned_by(owner, level):
    from secureauth.documents import service
    doc = service.create_document(owner, "t", "c", level)
    db.session.commit()
    return doc


def test_admin_clearance_never_changes_by_uploading(app):
    admin, root = logged_in(app, "root", role="admin")
    _doc_owned_by(root, 3)
    assert db.session.get(User, root.id).clearance_level == 0
