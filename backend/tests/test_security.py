import os

os.environ["APP_ENV"] = "test"
os.environ["SECRET_KEY"] = "test-secret-key-that-is-at-least-32-chars"

from app.core.security import create_access_token, decode_access_token, hash_password, verify_password


def test_password_hash_round_trip():
    hashed = hash_password("StrongPassword123!")
    assert hashed != "StrongPassword123!"
    assert verify_password("StrongPassword123!", hashed)
    assert not verify_password("wrong-password", hashed)


def test_jwt_round_trip():
    token = create_access_token("42", "analyst")
    payload = decode_access_token(token)
    assert payload["sub"] == "42"
    assert payload["role"] == "analyst"
    assert payload["type"] == "access"
