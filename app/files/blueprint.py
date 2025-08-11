import os
import uuid
from flask import (
    Blueprint,
    current_app,
    g,
    jsonify,
    request,
    session,
    send_from_directory,
    render_template_string,
    redirect,
    url_for,
)
from werkzeug.utils import secure_filename
import requests
from ..models import Platform
import jwt

files_bp = Blueprint("files", __name__)

# In-memory storage for file metadata {file_id: {filename, owner, path}}
FILE_METADATA: dict[str, dict] = {}

ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "gif"}

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def is_admin_user(roles: list[str]) -> bool:
    """Return True if any role grants admin privileges."""
    admin_indicators = {
        "administrator",
        "instructor",
        "contentdeveloper",
        "teachingassistant",
    }
    for role in roles:
        token = role.split("#")[-1].split("/")[-1].lower()
        if token in admin_indicators:
            return True
    return False


def _moodle_config():
    """Resolve Moodle configuration with fallbacks and light validation."""
    base_url = os.getenv("MOODLE_URL") or os.getenv("MOODLE_BASE_URL")
    token = os.getenv("MOODLE_API_TOKEN") or os.getenv("MOODLE_TOKEN")
    course_id = (
        request.args.get("course_id")
        or current_app.config.get("MOODLE_COURSE_ID")
        or os.getenv("MOODLE_COURSE_ID")
    )
    # Normalise course_id to int when possible
    try:
        course_id_int = int(course_id) if course_id is not None else None
    except (TypeError, ValueError):
        course_id_int = None
    return base_url, token, course_id_int


def moodle_api_call(function: str, params: dict | None = None):
    """Generic Moodle REST API wrapper."""
    base_url, token, _ = _moodle_config()
    if not base_url or not token:
        current_app.logger.error("Moodle configuration missing (base_url or token).")
        return None
    params = params or {}
    params.update({
        "wstoken": token,
        "wsfunction": function,
        "moodlewsrestformat": "json",
    })
    try:
        resp = requests.get(f"{base_url}/webservice/rest/server.php", params=params, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:  # pragma: no cover - network errors
        current_app.logger.error("Moodle API call failed: %s", exc)
        return None


def get_user_files(user_id: int, course_id: int | None = None):
    params: dict[str, int] = {"userid": user_id}
    if course_id:
        params["courseid"] = course_id
    data = moodle_api_call("core_files_get_user_files", params)
    return data.get("files", []) if data else []


def get_learners_in_course(course_id: int):
    data = moodle_api_call("core_enrol_get_enrolled_users", {"courseid": course_id})
    if not data:
        return []
    return [
        u for u in data
        if any((r.get("shortname") or "").lower() == "student" for r in u.get("roles", []))
    ]


def download_moodle_file(file_url: str, token: str | None = None):
    _, fallback_token, _ = _moodle_config()
    token = token or fallback_token
    if not token:
        current_app.logger.error("Cannot download Moodle file: missing token.")
        return None
    try:
        resp = reque
