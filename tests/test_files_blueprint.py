import os
import sys
from urllib.parse import parse_qs, urlparse


import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from app import create_app, db
from app.models import Platform



@pytest.fixture()
def app():
    app = create_app()
    with app.app_context():
        db.create_all()
        db.session.add(
            Platform(
                issuer="https://lms.example.com",
                client_id="client_id",
                auth_login_url="https://lms.example.com/login",
                auth_token_url="https://lms.example.com/token",
                jwks_uri="https://lms.example.com/jwks",
            )
        )
        db.session.commit()

        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


def test_require_session_redirects_to_login(client):
    resp = client.get("/files/file_browser")
    assert resp.status_code == 302
    location = resp.headers.get("Location", "")
    assert "/lti/login" in location
    qs = parse_qs(urlparse(location).query)
    assert qs.get("iss") == ["https://lms.example.com"]



def test_require_session_returns_html_error(client):
    resp = client.get("/files/get_user_files/1", headers={"Accept": "application/json"})
    assert resp.status_code == 401
    assert "text/html" in resp.headers.get("Content-Type", "")
    assert b"Unauthorized" in resp.data
