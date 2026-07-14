import pytest

from backend import users


@pytest.fixture(autouse=True)
def temp_user_store(tmp_path, monkeypatch):
    """Point the user store at a temp file so tests never touch data/users.json."""
    monkeypatch.setattr(users, "_USERS_FILE", tmp_path / "users.json")
    # The real cost (600k PBKDF2 rounds) is ~0.4s per hash, which would make this
    # module take minutes. The KDF is identical, just cheaper.
    monkeypatch.setattr(users, "_ITERATIONS", 1000)


def test_no_users_initially():
    assert users.user_count() == 0
    assert users.list_users() == []


def test_create_and_verify_user():
    users.create_user("alice", "correct-horse")

    assert users.user_count() == 1
    assert users.verify_user("alice", "correct-horse") == "alice"


def test_wrong_password_is_rejected():
    users.create_user("alice", "correct-horse")

    assert users.verify_user("alice", "wrong-horse") is None


def test_unknown_user_is_rejected():
    users.create_user("alice", "correct-horse")

    assert users.verify_user("bob", "correct-horse") is None


def test_username_check_is_case_insensitive():
    users.create_user("Alice", "correct-horse")

    # Login shouldn't hinge on capitalisation...
    assert users.verify_user("alice", "correct-horse") == "Alice"
    # ...and neither should uniqueness, or "alice" and "Alice" become two accounts.
    with pytest.raises(ValueError, match="already taken"):
        users.create_user("ALICE", "another-pw")


def test_short_password_is_rejected():
    with pytest.raises(ValueError, match="at least 8"):
        users.create_user("alice", "short")


def test_empty_username_is_rejected():
    with pytest.raises(ValueError, match="required"):
        users.create_user("   ", "correct-horse")


def test_password_is_never_stored_in_plaintext(tmp_path):
    users.create_user("alice", "correct-horse")

    stored = (users._USERS_FILE).read_text()

    assert "correct-horse" not in stored
    assert "alice" in stored  # the username is fine to store


def test_same_password_gets_a_different_hash_per_user():
    users.create_user("alice", "same-password")
    users.create_user("bob", "same-password")

    records = users._read_all()

    # Distinct salts mean identical passwords must not produce identical hashes --
    # otherwise the store leaks which users share a password.
    assert records[0]["salt"] != records[1]["salt"]
    assert records[0]["hash"] != records[1]["hash"]
