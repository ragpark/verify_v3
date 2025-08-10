import jwt
import requests
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


def test_deep_link_launch_stores_return_url(client, app, monkeypatch):
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
                redirect_after="/lti/deep_link",
                expires_at=datetime.utcnow() + timedelta(minutes=5),
            )
        )
        db.session.commit()

    payload = {
        "iss": "https://lms.example.com",
        "aud": "client123",
        "nonce": "nonce123",
        "https://purl.imsglobal.org/spec/lti/claim/message_type": "LtiDeepLinkingRequest",
        "https://purl.imsglobal.org/spec/lti-dl/claim/deep_linking_settings": {
            "deep_link_return_url": "https://lms.example.com/return"
        },
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
    assert res.headers["Location"].endswith("/lti/deep_link")
    with client.session_transaction() as sess:
        assert sess["deep_link_return_url"] == "https://lms.example.com/return"


def test_deep_link_return_posts_response(client, monkeypatch):
    with client.session_transaction() as sess:
        sess["deep_link_return_url"] = "https://lms.example.com/return"

    called = {}

    class DummyResp:
        def raise_for_status(self):
            return None

    def fake_post(url, data=None, timeout=10):
        called["url"] = url
        called["data"] = data
        return DummyResp()

    monkeypatch.setattr(requests, "post", fake_post)

    res = client.post("/lti/deep_link/return")
    assert res.status_code == 200
    assert called["url"] == "https://lms.example.com/return"


# --- Additional method-acceptance tests from feature branch ---


def test_lti_launch_accepts_get(client, app, monkeypatch):
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
                redirect_after="/lti/deep_link",
                expires_at=datetime.utcnow() + timedelta(minutes=5),
            )
        )
        db.session.commit()

    payload = {
        "iss": "https://lms.example.com",
        "aud": "client123",
        "nonce": "nonce123",
        "https://purl.imsglobal.org/spec/lti/claim/message_type": "LtiDeepLinkingRequest",
        "https://purl.imsglobal.org/spec/lti-dl/claim/deep_linking_settings": {
            "deep_link_return_url": "https://lms.example.com/return"
        },
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

    res = client.get("/lti/launch", query_string={"id_token": "token", "state": "state123"})
    assert res.status_code == 302
    assert res.headers["Location"].endswith("/lti/deep_link")
    with client.session_transaction() as sess:
        assert sess["deep_link_return_url"] == "https://lms.example.com/return"


def test_deep_link_accepts_post(client):
    res = client.post("/lti/deep_link")
    assert res.status_code == 200


def test_deep_link_return_accepts_get(client, monkeypatch):
    with client.session_transaction() as sess:
        sess["deep_link_return_url"] = "https://lms.example.com/return"

    called = {}

    class DummyResp:
        def raise_for_status(self):
            return None

    def fake_post(url, data=None, timeout=10):
        called["url"] = url
        called["data"] = data
        return DummyResp()

    monkeypatch.setattr(requests, "post", fake_post)

    res = client.get("/lti/deep_link/return")
    assert res.status_code == 200
    assert called["url"] == "https://lms.example.com/return"
