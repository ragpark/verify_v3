import os
import uuid
from flask import (
    Blueprint,
    current_app,
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
        "Administrator",
        "Instructor",
        "ContentDeveloper",
        "TeachingAssistant",
    }
    return any(r.split("#")[-1] in admin_indicators for r in roles)


def moodle_api_call(function: str, params: dict | None = None):
    """Generic Moodle REST API wrapper."""
    base_url = os.getenv("MOODLE_URL")
    token = os.getenv("MOODLE_API_TOKEN")
    if not base_url or not token:
        current_app.logger.error("Moodle configuration missing")
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
        u
        for u in data
        if any(r.get("shortname") == "student" for r in u.get("roles", []))
    ]


def download_moodle_file(file_url: str, token: str | None = None):
    token = token or os.getenv("MOODLE_API_TOKEN")
    try:
        resp = requests.get(f"{file_url}?token={token}", timeout=10)
        resp.raise_for_status()
        return resp.content
    except Exception as exc:  # pragma: no cover - network errors
        current_app.logger.error("Failed downloading Moodle file: %s", exc)
        return None


def save_file_metadata(info: dict):
    FILE_METADATA[info["id"]] = info


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _ensure_lti_session():
    if "user_id" not in session:
        return False
    return True


def _current_upload_folder() -> str:
    folder = os.getenv("UPLOAD_FOLDER", "/tmp/lti_files")
    os.makedirs(folder, exist_ok=True)
    return folder


def _validate_file(file_storage) -> tuple[bool, str]:
    filename = secure_filename(file_storage.filename)
    if not filename:
        return False, "invalid filename"
    ext = filename.rsplit(".", 1)[-1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return False, "file type not allowed"
    max_size = int(os.getenv("MAX_FILE_SIZE", 16 * 1024 * 1024))
    file_storage.seek(0, os.SEEK_END)
    size = file_storage.tell()
    file_storage.seek(0)
    if size > max_size:
        return False, "file too large"
    return True, filename


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@files_bp.before_request
def _require_session():
    if _ensure_lti_session():
        return None

    # API clients that explicitly request JSON get an HTML error page
    # instead of a JSON payload so the response is more user-friendly.
    if request.headers.get("Accept") == "application/json":
        html = """
        <h1>Unauthorized</h1>
        <p>No active LTI session. Please launch this tool from your LMS.</p>
        """
        return render_template_string(html), 401

    # Otherwise redirect to the LTI login endpoint to re-establish session
    # before hitting the requested URL.
    return redirect(url_for("lti.login", target_link_uri=request.url))


@files_bp.route("/get_user_files/<int:user_id>")
def get_user_files_route(user_id: int):
    course_id = request.args.get("course_id", type=int)
    files = get_user_files(user_id, course_id)
    return jsonify(files)


@files_bp.route("/copy_moodle_files", methods=["POST"])
def copy_moodle_files():
    roles = session.get("roles", [])
    if not is_admin_user(roles):
        return jsonify({"error": "forbidden"}), 403
    data = request.get_json(silent=True) or {}
    file_urls = data.get("files", [])
    saved = []
    folder = _current_upload_folder()
    for url in file_urls:
        content = download_moodle_file(url)
        if not content:
            continue
        filename = secure_filename(url.rsplit("/", 1)[-1].split("?")[0])
        file_id = uuid.uuid4().hex
        path = os.path.join(folder, filename)
        with open(path, "wb") as handle:
            handle.write(content)
        info = {"id": file_id, "filename": filename, "path": path, "owner": session.get("user_id")}
        save_file_metadata(info)
        saved.append(file_id)
    return jsonify({"saved": saved})


@files_bp.route("/upload_files", methods=["POST"])
def upload_files():
    if "file" not in request.files:
        return jsonify({"error": "no file"}), 400
    file = request.files["file"]
    ok, filename = _validate_file(file)
    if not ok:
        return jsonify({"error": filename}), 400
    folder = _current_upload_folder()
    file_id = uuid.uuid4().hex
    path = os.path.join(folder, filename)
    file.save(path)
    info = {"id": file_id, "filename": filename, "path": path, "owner": session.get("user_id")}
    save_file_metadata(info)
    return jsonify(info)


@files_bp.route("/download_file/<file_id>")
def download_file(file_id: str):
    info = FILE_METADATA.get(file_id)
    if not info:
        return jsonify({"error": "not found"}), 404
    directory, filename = os.path.split(info["path"])
    return send_from_directory(directory, filename, as_attachment=True)


@files_bp.route("/delete_file/<file_id>", methods=["DELETE"])
def delete_file(file_id: str):
    roles = session.get("roles", [])
    if not is_admin_user(roles):
        return jsonify({"error": "forbidden"}), 403
    info = FILE_METADATA.pop(file_id, None)
    if not info:
        return jsonify({"deleted": False}), 404
    try:
        os.remove(info["path"])
    except OSError:
        pass
    return jsonify({"deleted": True})


@files_bp.route("/list_uploaded_files")
def list_uploaded_files():
    roles = session.get("roles", [])
    user_id = session.get("user_id")
    if is_admin_user(roles):
        files = list(FILE_METADATA.values())
    else:
        files = [f for f in FILE_METADATA.values() if f.get("owner") == user_id]
    return jsonify(files)


@files_bp.route("/file_browser")
def file_browser():
    roles = session.get("roles", [])
    user_id = session.get("user_id")
    admin = is_admin_user(roles)
    files = [f for f in FILE_METADATA.values() if admin or f.get("owner") == user_id]
    html = """
    <html>
    <head>
        <title>File Browser</title>
    </head>
    <body>
        <h1>File Browser</h1>
        {% if admin %}
        <p>Admin interface</p>
        {% else %}
        <p>Student interface</p>
        {% endif %}
        <ul>
        {% for f in files %}
            <li>{{f.filename}} - <a href="{{ url_for('files.download_file', file_id=f.id) }}">Download</a></li>
        {% endfor %}
        </ul>
        <form action="{{ url_for('files.upload_files') }}" method="post" enctype="multipart/form-data">
            <input type="file" name="file"/>
            <button type="submit">Upload</button>
        </form>
    </body>
    </html>
    """
    return render_template_string(html, files=files, admin=admin)
