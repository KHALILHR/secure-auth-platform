import time
from statistics import median

from argon2 import PasswordHasher

from secureauth.security import passwords

GOOD = "Cheval-Agrafe-Lune-42"


def test_hash_is_argon2id():
    assert passwords.hash_password(GOOD).startswith("$argon2id$")


def test_same_password_gives_different_hashes():
    # sel aléatoire : deux comptes avec le même mot de passe n'ont pas la même empreinte
    assert passwords.hash_password(GOOD) != passwords.hash_password(GOOD)


def test_hash_does_not_contain_password():
    assert GOOD not in passwords.hash_password(GOOD)


def test_verify_correct_and_wrong_password():
    h = passwords.hash_password(GOOD)
    assert passwords.verify_password(h, GOOD) is True
    assert passwords.verify_password(h, GOOD + "x") is False


def test_verify_corrupted_hash_is_refused_without_exception():
    assert passwords.verify_password("pas-un-hash", GOOD) is False


def test_fresh_hash_does_not_need_rehash():
    assert passwords.needs_rehash(passwords.hash_password(GOOD)) is False


def test_weak_hash_needs_rehash():
    weak = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash(GOOD)
    assert passwords.needs_rehash(weak) is True


def test_dummy_hash_is_argon2id():
    assert passwords.DUMMY_HASH.startswith("$argon2id$")


def test_unknown_account_is_always_refused():
    assert passwords.verify_or_dummy(None, GOOD) is False


def test_known_account_verified_normally():
    h = passwords.hash_password(GOOD)
    assert passwords.verify_or_dummy(h, GOOD) is True
    assert passwords.verify_or_dummy(h, "mauvais") is False


def test_unknown_account_costs_similar_time():
    """Preuve T01 : temps comparable qu'un compte existe ou non (médiane, marge large)."""
    h = passwords.hash_password(GOOD)

    def measure(stored_hash):
        samples = []
        for _ in range(5):
            start = time.perf_counter()
            passwords.verify_or_dummy(stored_hash, "mauvais-mot-de-passe")
            samples.append(time.perf_counter() - start)
        return median(samples)

    known, unknown = measure(h), measure(None)
    assert 0.5 < unknown / known < 2.0, f"connu={known:.3f}s inconnu={unknown:.3f}s"


def test_valid_password_has_no_error():
    assert passwords.validate_password(GOOD, "alice") == []


def test_too_short():
    assert passwords.validate_password("Court1!", "alice")


def test_min_length_boundary():
    assert passwords.validate_password("x" * 11 + "Z", "alice") == []
    assert passwords.validate_password("x" * 11, "alice")


def test_max_length_boundary():
    assert passwords.validate_password("a1" * 64, "alice") == []
    assert passwords.validate_password("a" * 129, "alice")


def test_equal_to_username_is_refused_case_insensitive():
    assert passwords.validate_password("Administrateur99", "administrateur99")


def test_common_password_is_refused_case_insensitive():
    assert passwords.validate_password("PassWord1234", "alice")


def test_several_errors_are_all_reported():
    errors = passwords.validate_password("password", "password")
    assert len(errors) >= 2


def test_common_list_is_loaded_lowercase():
    common = passwords._common_passwords()
    assert "password1234" in common
    assert all(p == p.lower() for p in common)


def test_app_fixture_smoke(app):
    # vérifie que l'environnement de test (SQLite + fakeredis) démarre
    assert app.config["SESSION_COOKIE_NAME"] == "__Host-sid"
