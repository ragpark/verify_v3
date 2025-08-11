import jwt
from datetime import datetime, timedelta
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from app import create_app, db
from app.models import Platform, State, Nonce


@pytest.fixture()
def app():
    app = create_app()
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


def test_resource_link_launch_redirects_to_original_target(client, app, monkeypatch):
    with app.app_context():
        platform = Platform(
            issuer="https://lms.example.com",
            client_id="client123",
            auth_login_url="https://lms.example.com/auth",
            auth_token_url="https://lms.example.com/token",
            jwks_uri="https://lms.example.com/jwks",
        )
        db.session.add(platform)
        db.session.add(
            Nonce(value="nonce123", expires_at=datetime.utcnow() + timedelta(minutes=5))
        )
        db.session.add(
            State(
                value="state123",
                redirect_after="/resource",
                expires_at=datetime.utcnow() + timedelta(minutes=5),
            )
        )
        db.session.commit()

    payload = {
        "iss": "https://lms.example.com",
        "aud": "client123",
        "nonce": "nonce123",
        "https://purl.imsglobal.org/spec/lti/claim/message_type": "LtiResourceLinkRequest",
    }

    class DummyJWKClient:
        def __init__(self, *args, **kwargs):
            pass

        def get_signing_key_from_jwt(self, token):
            class Key:
                key = "secret"

            return Key()

    monkeypatch.setattr(jwt, "PyJWKClient", lambda url: DummyJWKClient())
    monkeypatch.setattr(jwt, "decode", lambda *args, **kwargs: payload)

    res = client.post("/lti/launch", data={"id_token": "token", "state": "state123"})
    assert res.status_code == 302
    assert res.headers["Location"].endswith("/resource")


def test_resource_link_launch_avoids_login_redirect(client, app, monkeypatch):
    with app.app_context():
        platform = Platform(
            issuer="https://lms.example.com",
            client_id="client123",
            auth_login_url="https://lms.example.com/auth",
            auth_token_url="https://lms.example.com/token",
            jwks_uri="https://lms.example.com/jwks",
        )
        db.session.add(platform)
        db.session.add(
            Nonce(value="nonce123", expires_at=datetime.utcnow() + timedelta(minutes=5))
        )
        db.session.add(
            State(
                value="state123",
                redirect_after="/lti/launch",
                expires_at=datetime.utcnow() + timedelta(minutes=5),
            )
        )
        db.session.commit()

    payload = {
        "iss": "https://lms.example.com",
        "aud": "client123",
        "nonce": "nonce123",
        "https://purl.imsglobal.org/spec/lti/claim/message_type": "LtiResourceLinkRequest",
    }

    class DummyJWKClient:
        def __init__(self, *args, **kwargs):
            pass

        def get_signing_key_from_jwt(self, token):
            class Key:
                key = "secret"

            return Key()

    monkeypatch.setattr(jwt, "PyJWKClient", lambda url: DummyJWKClient())
    monkeypatch.setattr(jwt, "decode", lambda *args, **kwargs: payload)

    res = client.post("/lti/launch", data={"id_token": "token", "state": "state123"})
    assert res.status_code == 302
    assert res.headers["Location"].endswith("/lti/success")
