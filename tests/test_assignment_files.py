import os
import sys
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from app import create_app, db
from app.models import Platform
from app.files.blueprint import get_assignment_files


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


def _assignment_response():
    return {
        "courses": [
            {
                "assignments": [
                    {"id": 5, "name": "Essay"},
                ]
            }
        ]
    }


def test_get_assignment_files_returns_files(app, monkeypatch):
    def fake_call(function, params=None):
        if function == "mod_assign_get_assignments":
            return _assignment_response()
        if function == "mod_assign_get_submission_status":
            assert params == {"assignid": 5, "userid": 42}
            return {
                "lastattempt": {
                    "submission": {
                        "status": "submitted",
                        "plugins": [
                            {
                                "type": "file",
                                "fileareas": [
                                    {
                                        "files": [
                                            {
                                                "filename": "a.txt",
                                                "fileurl": "url",
                                                "filesize": 1,
                                            }
                                        ]
                                    }
                                ],
                            }
                        ],
                    }
                }
            }
        return None

        with app.app_context():
            monkeypatch.setattr("app.files.blueprint.moodle_api_call", fake_call)
            files = get_assignment_files(42, 99)
            assert len(files) == 1
            file = files[0]
            assert file["filename"] == "a.txt"
            assert file["fileurl"] == "url"
            assert file["filesize"] == 1
            assert file["source"] == "Assignment: Essay"


def test_get_assignment_files_skips_draft(app, monkeypatch):
    def fake_call(function, params=None):
        if function == "mod_assign_get_assignments":
            return _assignment_response()
        if function == "mod_assign_get_submission_status":
            return {
                "lastattempt": {
                    "submission": {
                        "status": "draft",
                        "plugins": [],
                    }
                }
            }
        return None

    with app.app_context():
        monkeypatch.setattr("app.files.blueprint.moodle_api_call", fake_call)
        assert get_assignment_files(42, 99) == []


def test_get_assignment_files_logs_permission_error(app, monkeypatch, caplog):
    def fake_call(function, params=None):
        if function == "mod_assign_get_assignments":
            return _assignment_response()
        if function == "mod_assign_get_submission_status":
            return {"errorcode": "nopermissions", "message": "no permission"}
        return None

    with app.app_context():
        monkeypatch.setattr("app.files.blueprint.moodle_api_call", fake_call)
        with caplog.at_level("ERROR"):
            assert get_assignment_files(42, 99) == []
            assert any("nopermissions" in rec.message for rec in caplog.records)
