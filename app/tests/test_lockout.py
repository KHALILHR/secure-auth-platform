"""Verrouillage du compte après 5 échecs consécutifs pendant 15 minutes (EF-06, T02)."""
from datetime import timedelta

from helpers import PASSWORD, events, login, make_user

from secureauth.auth.service import LOCK_DURATION, LOGIN_REFUSED, MAX_FAILED_ATTEMPTS
from secureauth.extensions import db
from secureauth.models import User, utcnow


def fail(client, username="alice", times=1):
    for _ in range(times):
        resp = login(client, username, password="mauvais-mot-de-passe-1")
        assert resp.status_code == 200  # reste sur la page de connexion


def test_five_failures_lock_the_account(app):
    make_user("alice")
    client = app.test_client()
    fail(client, times=MAX_FAILED_ATTEMPTS)
    user = db.session.query(User).filter_by(username="alice").one()
    assert user.is_locked()
    assert user.locked_until - utcnow() > LOCK_DURATION - timedelta(seconds=30)
    assert len(events("LOGIN_LOCKED")) == 1


def test_four_failures_do_not_lock(app):
    make_user("alice")
    client = app.test_client()
    fail(client, times=MAX_FAILED_ATTEMPTS - 1)
    user = db.session.query(User).filter_by(username="alice").one()
    assert not user.is_locked() and user.failed_attempts == MAX_FAILED_ATTEMPTS - 1
    assert login(client, "alice").status_code == 302  # le bon mot de passe passe encore


def test_sixth_attempt_refused_even_with_correct_password(app):
    """T02 : 6 échecs consécutifs, puis même le BON mot de passe est refusé, avec le même message."""
    make_user("alice")
    client = app.test_client()
    fail(client, times=MAX_FAILED_ATTEMPTS)
    resp = login(client, "alice", PASSWORD)
    assert resp.status_code == 200
    assert LOGIN_REFUSED.encode() in resp.data
    assert client.get("/").status_code == 302  # pas de session ouverte


def test_locked_message_is_identical_to_wrong_password(app):
    """Un compte verrouillé ne se distingue pas d'un mot de passe faux (pas d'énumération)."""
    make_user("alice")
    client = app.test_client()
    wrong = login(client, "alice", "mauvais-mot-de-passe-1")
    fail(client, times=MAX_FAILED_ATTEMPTS)
    locked = login(client, "alice", PASSWORD)
    assert LOGIN_REFUSED.encode() in wrong.data and LOGIN_REFUSED.encode() in locked.data


def test_lock_expires_after_fifteen_minutes(app):
    make_user("alice")
    client = app.test_client()
    fail(client, times=MAX_FAILED_ATTEMPTS)
    user = db.session.query(User).filter_by(username="alice").one()
    user.locked_until = utcnow() - timedelta(minutes=1)  # le verrou est échu
    db.session.commit()
    assert login(client, "alice").status_code == 302
    db.session.refresh(user)
    assert user.locked_until is None and user.failed_attempts == 0


def test_success_resets_the_counter(app):
    make_user("alice")
    client = app.test_client()
    fail(client, times=3)
    assert login(client, "alice").status_code == 302
    user = db.session.query(User).filter_by(username="alice").one()
    assert user.failed_attempts == 0


def test_attempts_on_locked_account_are_logged_and_do_not_extend_the_lock(app):
    make_user("alice")
    client = app.test_client()
    fail(client, times=MAX_FAILED_ATTEMPTS)
    user = db.session.query(User).filter_by(username="alice").one()
    first_lock = user.locked_until
    fail(client, times=2)
    db.session.refresh(user)
    assert user.locked_until == first_lock and user.failed_attempts == 0
    assert any("verrouillé" in (e.details or "") for e in events("LOGIN_FAILURE"))
