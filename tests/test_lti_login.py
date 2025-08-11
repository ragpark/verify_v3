import os
import sys
from urllib.parse import urlparse, parse_qs

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from app import create_app, db
from app.models import Platform


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


def test_login_omits_login_hint_when_absent(client, app):
    with app.app_context():
        platform = Platform(
            issuer="https://lms.example.com",
            client_id="client123",
            auth_login_url="https://lms.example.com/auth",
            auth_token_url="https://lms.example.com/token",
            jwks_uri="https://lms.example.com/jwks",
        )
        db.session.add(platform)
        db.session.commit()

    res = client.get(
        "/lti/login",
        query_string={
            "iss": "https://lms.example.com",
            "target_link_uri": "https://tool.example.com/launch",
            "client_id": "client123",
        },
    )
    assert res.status_code == 302
    qs = urlparse(res.headers["Location"]).query
    params = parse_qs(qs)
    assert "login_hint" not in params
