import os
import sys
from urllib.parse import parse_qs, urlparse
import io

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from app import create_app, db
from app.models import Platform
from app.files.blueprint import FILE_METADATA



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


def test_require_session_redirects_to_login_with_hint(client):
    resp = client.get("/files/file_browser?login_hint=test-user")
    assert resp.status_code == 302
    location = resp.headers.get("Location", "")
    assert "/lti/login" in location
    qs = parse_qs(urlparse(location).query)
    assert qs.get("iss") == ["https://lms.example.com"]
    assert qs.get("login_hint") == ["test-user"]


def test_require_session_returns_html_error_without_hint(client):
    resp = client.get("/files/file_browser")
    assert resp.status_code == 401
    assert "text/html" in resp.headers.get("Content-Type", "")
    assert b"Unauthorized" in resp.data


def test_require_session_redirects_with_placeholder_hint(client, monkeypatch):
    monkeypatch.setenv("MOODLE_PLACEHOLDER_HINT", "placeholder")
    resp = client.get("/files/file_browser")
    assert resp.status_code == 302
    location = resp.headers.get("Location", "")
    qs = parse_qs(urlparse(location).query)
    assert qs.get("login_hint") == ["placeholder"]
    assert qs.get("iss") == ["https://lms.example.com"]


def test_require_session_returns_html_error(client):
    resp = client.get("/files/get_user_files/1", headers={"Accept": "application/json"})
    assert resp.status_code == 401
    assert "application/json" in resp.headers.get("Content-Type", "")
    assert b"No active LTI session" in resp.data


def test_admin_file_browser_lists_students(client, monkeypatch):
    FILE_METADATA.clear()
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["roles"] = ["urn:lti:role:ims/lis/Instructor"]
        sess["context_id"] = 1


    monkeypatch.setattr(
        "app.files.blueprint.get_enrolled_users",
        lambda course_id: [
            {"id": 10, "fullname": "Alice"},
            {"id": 11, "fullname": "Bob"},
        ],
    )

    resp = client.get("/files/file_browser")
    assert resp.status_code == 200
    assert b"Alice" in resp.data
    assert b"Bob" in resp.data


def test_admin_select_user_lists_files(client):
    FILE_METADATA.clear()
    FILE_METADATA["f1"] = {
        "id": "f1",
        "filename": "sample.txt",
        "owner": 10,
        "path": "/tmp/sample.txt",
    }

    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["roles"] = ["urn:lti:role:ims/lis/Instructor"]


    resp = client.get("/files/file_browser?user_id=10")
    assert resp.status_code == 200
    body = resp.data.decode()
    assert "Uploaded to SV Service" in body
    assert "sample.txt" in body.split("Uploaded to SV Service", 1)[1]


def test_admin_sees_user_uploads(client):
    FILE_METADATA.clear()

    # Simulate student upload with string user_id
    with client.session_transaction() as sess:
        sess["user_id"] = "10"
        sess["roles"] = ["urn:lti:role:ims/lis/Learner"]

    data = {"file": (io.BytesIO(b"hello"), "hello.txt")}
    upload_resp = client.post(
        "/files/upload_files", data=data, content_type="multipart/form-data"
    )
    assert upload_resp.status_code == 200

    # Switch to admin session to view user files
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["roles"] = ["urn:lti:role:ims/lis/Instructor"]

    resp = client.get("/files/file_browser?user_id=10")
    assert resp.status_code == 200
    body = resp.data.decode()
    assert "Uploaded to SV Service" in body
    assert "hello.txt" in body.split("Uploaded to SV Service", 1)[1]


def test_admin_can_upload_selected_files(client, tmp_path, monkeypatch):
    """Admin selects remote files and they are saved locally."""
    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["roles"] = ["urn:lti:role:ims/lis/Instructor"]

    # Ensure uploads go to temporary directory
    client.application.config["UPLOAD_FOLDER"] = str(tmp_path)

    # Stub Moodle file listing
    monkeypatch.setattr(
        "app.files.blueprint.get_user_files",
        lambda user_id, course_id=None: [
            {
                "filename": "remote.txt",
                "fileurl": "http://example.com/remote.txt",
                "filesize": 5,
                "source": "Assignment",
            }
        ],
    )

    class FakeResp:
        def __init__(self):
            self.content = b"hello"

        def raise_for_status(self):
            return None

    monkeypatch.setattr("app.files.blueprint.requests.get", lambda url, timeout=10: FakeResp())

    resp = client.post(
        "/files/file_browser?user_id=10",
        data={"files": ["http://example.com/remote.txt"]},
    )
    assert resp.status_code == 200
    assert (tmp_path / "remote.txt").exists()
    body = resp.data.decode()
    assert "Uploaded to SV Service" in body
    assert "remote.txt" in body.split("Uploaded to SV Service", 1)[1]


def test_student_files_shows_uploaded_list(client, tmp_path, monkeypatch):
    client.application.config["UPLOAD_FOLDER"] = str(tmp_path)

    monkeypatch.setattr("app.lti.launch._fetch_moodle_students_and_files", lambda: [])

    class FakeResp:
        def __init__(self):
            self.content = b"data"

        def raise_for_status(self):
            return None

    monkeypatch.setattr("app.lti.launch.requests.get", lambda url, timeout=10: FakeResp())

    resp = client.post(
        "/lti/student_files",
        data={"files": ["http://example.com/loaded.txt"]},
    )
    assert resp.status_code == 200
    assert (tmp_path / "loaded.txt").exists()
    assert b"loaded.txt" in resp.data

