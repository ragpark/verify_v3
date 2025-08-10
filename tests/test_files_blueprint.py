import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from app import create_app, db


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


def test_require_session_redirects_to_login(client):
    resp = client.get("/files/file_browser")
    assert resp.status_code == 302
    assert "/lti/login" in resp.headers.get("Location", "")


def test_require_session_returns_html_error(client):
    resp = client.get("/files/get_user_files/1", headers={"Accept": "application/json"})
    assert resp.status_code == 401
    assert "text/html" in resp.headers.get("Content-Type", "")
    assert b"Unauthorized" in resp.data
