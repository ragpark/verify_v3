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
    return base_url, token


def moodle_api_call(function: str, params: dict | None = None):
    """Generic Moodle REST API wrapper."""
    base_url, token = _moodle_config()
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


def get_user_files(user_id: int):
    """Return all files for a user (no course constraint)."""
    data = moodle_api_call("core_files_get_user_files", {"userid": user_id})
    return data.get("files", []) if data else []


def get_all_users(limit=200, offset=0):
    criteria = []
    data = moodle_api_call("core_enrol_get_enrolled_users", {"courseid": '101'})
    
    # Add debugging
    current_app.logger.info(f"Moodle API response: {data}")
    
    if not data:
        current_app.logger.warning("No data returned from core_user_get_users")
        return []
    
    if "users" not in data:
        current_app.logger.warning(f"No 'users' key in response: {data}")
        return []
    
    return [
        {
            "id": u.get("id"),
            "fullname": f"{u.get('fullname') or (u.get('firstname','') + ' ' + u.get('lastname','')).strip()}".strip()
        }
        for u in data.get("users", [])
    ]

def download_moodle_file(file_url: str, token: str | None = None):
    base_url, fallback_token = _moodle_config()
    token = token or fallback_token
    if not token:
        current_app.logger.error("Cannot download Moodle file: missing token.")
        return None
    # file_url already contains pluginfile path; append token
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
    return "user_id" in session


def _try_hydrate_from_ltik():
    token = (
        request.args.get("ltik")
        or (request.headers.get("Authorization", "").removeprefix("Bearer ").strip() or None)
        or (request.form.get("ltik") if request.method == "POST" else None)
    )
    if not token:
        return False
    try:
        data = jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=["HS256"])
    except Exception:
        return False

    session.setdefault("user_id", data.get("sub"))
    session.setdefault("roles", data.get("roles", []))
    session.setdefault("platform_id", data.get("platform_id"))
    session.setdefault("platform_issuer", data.get("platform_issuer"))
    session.setdefault("deployment_id", data.get("deployment_id"))
    session.setdefault("context_id", data.get("context_id"))
    session.setdefault("context_title", data.get("context_title"))
    g.ltik = token
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
    # Try ltik first (cookieless)
    if "user_id" not in session and _try_hydrate_from_ltik():
        return None

    if "user_id" in session:
        return None

    html = """
    <h1>Unauthorized</h1>
    <p>No active LTI session. Please launch this tool from your LMS.</p>
    """

    if request.headers.get("Accept") == "application/json":
        return render_template_string(html), 401

    login_hint = request.args.get("login_hint") or os.getenv("MOODLE_PLACEHOLDER_HINT")
    if not login_hint:
        return render_template_string(html), 401

    platform = Platform.query.first()
    if platform:
        return redirect(
            url_for(
                "lti.login",
                target_link_uri=request.url,
                iss=platform.issuer,
                login_hint=login_hint,
            )
        )
    return redirect(
        url_for("lti.login", target_link_uri=request.url, login_hint=login_hint)
    )


@files_bp.route("/get_user_files/<int:user_id>")
def get_user_files_route(user_id: int):
    files = get_user_files(user_id)
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
    session_user = session.get("user_id")
    admin = is_admin_user(roles)
    selected_user = request.args.get("user_id", type=int)
    ltik = getattr(g, "ltik", request.args.get("ltik"))

    base_url, token = _moodle_config()

    # Admin with no user selected: list all Moodle users
    if admin and not selected_user:
        users = get_all_users()
        html = """
        <html>
        <head><title>File Browser</title></head>
        <body>
            <h1>File Browser</h1>
            {% if not (base_url and token) %}
              <p><strong>Note:</strong> Moodle configuration incomplete.
              Set MOODLE_URL (or MOODLE_BASE_URL) and MOODLE_API_TOKEN (or MOODLE_TOKEN).</p>
            {% endif %}
            <p>Select a user to view Moodle files.</p>
            <ul>
            {% for u in users %}
                <li>
                  <a href="{{ url_for('files.file_browser') }}?user_id={{ u.id }}&ltik={{ ltik }}">
                    {{ u.fullname or ('User ' ~ u.id) }}
                  </a>
                </li>
            {% endfor %}
            </ul>
        </body>
        </html>
        """
        html = html.replace("&ltik=", "ltik=")
        return render_template_string(
            html, users=users, admin=admin, ltik=ltik, base_url=base_url, token=token
        )

    # Admin + user selected: show that user's Moodle files and local uploads
    if admin and selected_user:
        moodle_files = get_user_files(selected_user)
        local_files = [f for f in FILE_METADATA.values() if f.get("owner") == selected_user]
        html = """
        <html>
        <head><title>User Files</title></head>
        <body>
            <h1>User {{ selected_user }} Files</h1>
            <p><a href="{{ url_for('files.file_browser') }}?ltik={{ ltik }}">Back to users</a></p>

            <h2>Moodle files</h2>
            {% if not moodle_files %}
              <p>No Moodle files found for this user.</p>
            {% else %}
              <ul>
                {% for f in moodle_files if not f.isdir %}
                  <li>
                    {{ f.filename }}
                    {% if f.fileurl %}
                      - <a href="{{ f.fileurl }}?token={{ token }}" target="_blank" rel="noopener">Open</a>
                    {% endif %}
                  </li>
                {% endfor %}
              </ul>
            {% endif %}

            <h2>Local uploads</h2>
            {% if not local_files %}
              <p>No local uploads for this user.</p>
            {% else %}
              <ul>
                {% for f in local_files %}
                  <li>{{ f.filename }} - <a href="{{ url_for('files.download_file', file_id=f.id) }}?ltik={{ ltik }}">Download</a></li>
                {% endfor %}
              </ul>
            {% endif %}
        </body>
        </html>
        """
        return render_template_string(
            html,
            selected_user=selected_user,
            moodle_files=moodle_files,
            local_files=local_files,
            ltik=ltik,
            token=token,
        )

    # Non-admin: show own local uploads (unchanged)
    target_user = session_user
    files = [f for f in FILE_METADATA.values() if f.get("owner") == target_user]
    html = """
    <html>
    <head>
        <title>File Browser</title>
    </head>
    <body>
        <h1>File Browser</h1>
        <p>Student interface</p>

        <ul>
        {% for f in files %}
            <li>{{ f.filename }} - <a href="{{ url_for('files.download_file', file_id=f.id) }}?ltik={{ ltik }}">Download</a></li>
        {% endfor %}
        </ul>

        <form action="{{ url_for('files.upload_files') }}?ltik={{ ltik }}" method="post" enctype="multipart/form-data">
            <input type="hidden" name="ltik" value="{{ ltik }}"/>
            <input type="file" name="file"/>
            <button type="submit">Upload</button>
        </form>
    </body>
    </html>
    """
    return render_template_string(html, files=files, ltik=ltik)
