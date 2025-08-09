import json
from datetime import datetime, timedelta

import pytest

from app import create_app, db
from app.models import Platform, State


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


def test_tool_configuration(client):
    res = client.get("/.well-known/tool-configuration")
    assert res.status_code == 200
    data = res.get_json()
    assert data["jwks_uri"].endswith("/.well-known/jwks.json")
    assert "initiate_login_uri" in data
    assert "https://purl.imsglobal.org/spec/lti-tool-configuration" in data


def test_jwks_endpoint_returns_key(client, app):
    res = client.get("/.well-known/jwks.json")
    data = res.get_json()
    assert res.status_code == 200
    assert "keys" in data and data["keys"]
    assert data["keys"][0]["kid"]


def test_dynamic_registration_rejects_missing_state(client):
    res = client.get(
        "/lti/dynamic-registration/callback",
        query_string={
            "openid_configuration": "https://lms.example.com/.well-known/openid-configuration",
            "registration_token": "tok",
        },
    )
    assert res.status_code == 400


def test_dynamic_registration_persists_platform(client, monkeypatch, app):
    # Pre-create state
    with app.app_context():
        state = State(value="state123", expires_at=datetime.utcnow() + timedelta(minutes=5))
        db.session.add(state)
        db.session.commit()

    oidc_config = {
        "issuer": "https://lms.example.com",
        "authorization_endpoint": "https://lms.example.com/auth",
        "token_endpoint": "https://lms.example.com/token",
        "jwks_uri": "https://lms.example.com/jwks",
        "registration_endpoint": "https://lms.example.com/register",
    }

    class DummyResp:
        def __init__(self, data):
            self._data = data

        def json(self):
            return self._data

        def raise_for_status(self):
            return None

    def fake_get(url, timeout=10):
        assert url == "https://lms.example.com/.well-known/openid-configuration"
        return DummyResp(oidc_config)

    def fake_post(url, json=None, headers=None, timeout=10):
        assert url == "https://lms.example.com/register"
        return DummyResp({"client_id": "abc123"})

    monkeypatch.setattr("requests.get", fake_get)
    monkeypatch.setattr("requests.post", fake_post)

    res = client.get(
        "/lti/dynamic-registration/callback",
        query_string={
            "openid_configuration": "https://lms.example.com/.well-known/openid-configuration",
            "registration_token": "tok",
            "state": "state123",
        },
    )
    assert res.status_code == 200

    with app.app_context():
        platform = Platform.query.filter_by(issuer="https://lms.example.com").first()
        assert platform is not None
        assert platform.client_id == "abc123"
