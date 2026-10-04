"""Configuration des tests : jamais de vrais secrets, base SQLite mémoire, Redis simulé."""
import base64
import os

# Ces variables doivent exister AVANT l'import de l'application (load_config les exige).
# On les force : les tests ne dépendent jamais du .env de l'étudiant.
os.environ["SECRET_KEY"] = "cle-de-test-non-secrete"
os.environ["DATABASE_URL"] = "sqlite://"
os.environ["REDIS_URL"] = "redis://localhost:6379/0"  # jamais contacté : remplacé par fakeredis
os.environ["ENCRYPTION_KEY"] = base64.b64encode(b"E" * 32).decode()
os.environ["HMAC_KEY"] = base64.b64encode(b"H" * 32).decode()

import fakeredis  # noqa: E402
import pytest  # noqa: E402

from secureauth import create_app  # noqa: E402
from secureauth.extensions import db  # noqa: E402
from secureauth.security.audit import ensure_chain_head  # noqa: E402


@pytest.fixture
def app():
    app = create_app(
        {
            "TESTING": True,
            "SESSION_REDIS": fakeredis.FakeRedis(),
            "SQLALCHEMY_ENGINE_OPTIONS": {},  # pool_recycle / pre_ping inutiles en mémoire
        }
    )
    with app.app_context():
        db.create_all()
        ensure_chain_head()  # comme `flask init-db`
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()
