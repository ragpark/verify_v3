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
    """Generic Moodle REST API wrapper with debug logging."""
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

    log_params = {k: v for k, v in params.items() if k != "wstoken"}
    current_app.logger.info("Moodle API call %s with params %s", function, log_params)

    try:
        resp = requests.get(
            f"{base_url}/webservice/rest/server.php", params=params, timeout=10
        )
        resp.raise_for_status()
        data = resp.json()
        current_app.logger.info("Moodle API response %s: %s", function, data)
        return data
    except Exception as exc:  # pragma: no cover - network errors
        current_app.logger.error("Moodle API call %s failed: %s", function, exc)
        return None


def get_user_files(user_id: int, course_id: int = None):
    """
    Return all files for a user across different contexts.
    Uses available APIs based on your Moodle setup.
    """
    all_files = []
    
    # 1. Try to get user's private files using available API
    current_app.logger.info(f"Getting private files for user {user_id}")
    try:
        # Try the API that's actually available
        private_files_info = moodle_api_call("core_user_get_private_files_info", {"userid": user_id})
        if private_files_info and "errorcode" not in private_files_info:
            current_app.logger.info(f"Private files info: {private_files_info}")
            
        # Try to get actual files using core_files_get_files
        user_files = moodle_api_call("core_files_get_files", {
            "contextlevel": 30,  # CONTEXT_USER
            "instanceid": user_id,
            "component": "user",
            "filearea": "private"
        })
        
        if user_files and isinstance(user_files, dict) and "files" in user_files:
            for file_info in user_files["files"]:
                file_info['source'] = 'user_private_area'
                all_files.append(file_info)
            current_app.logger.info(f"Found {len(user_files['files'])} private files")
        
    except Exception as e:
        current_app.logger.error(f"Error getting private files for user {user_id}: {e}")
    
    # 2. Get course module files
    if course_id:
        course_files = get_course_module_files(course_id)
        all_files.extend(course_files)
    
    # 3. Get assignment submission files
    if course_id:
        assignment_files = get_assignment_files(user_id, course_id)
        all_files.extend(assignment_files)
    
    # 4. Get files from enrolled courses
    enrolled_courses = get_user_courses(user_id)
    for course in enrolled_courses:
        if course.get('id') != course_id:  # Avoid duplicates
            course_files = get_course_module_files(course.get('id'))
            all_files.extend(course_files)
            
            assignment_files = get_assignment_files(user_id, course.get('id'))
            all_files.extend(assignment_files)
    
    # Remove duplicates
    seen_files = set()
    unique_files = []
    for file_info in all_files:
        file_key = file_info.get('fileurl') or f"{file_info.get('filename', '')}-{file_info.get('filesize', 0)}"
        if file_key not in seen_files:
            seen_files.add(file_key)
            unique_files.append(file_info)
    
    current_app.logger.info(f"Total files for user {user_id}: {len(unique_files)}")
    return unique_files


def get_course_module_files(course_id: int):
    """Get files from course modules."""
    files = []
    try:
        course_content = moodle_api_call("core_course_get_contents", {"courseid": course_id})
        if course_content:
            for section in course_content:
                for module in section.get('modules', []):
                    for file_info in module.get('contents', []):
                        file_info['source'] = f"Course module: {module.get('name', 'Unknown')}"
                        files.append(file_info)
    except Exception as e:
        current_app.logger.error(f"Error getting course files: {e}")
    return files


def get_assignment_files(user_id: int, course_id: int):
    """Get assignment submission files for a user."""
    files = []
    try:
        assignments = moodle_api_call("mod_assign_get_assignments", {"courseids": [course_id]})
        if assignments and "courses" in assignments:
            for course_data in assignments["courses"]:
                for assignment in course_data.get("assignments", []):
                    assignment_id = assignment.get("id")
                    status = moodle_api_call(
                        "mod_assign_get_submission_status",
                        {"assignid": assignment_id, "userid": user_id},
                    )

                    if not status or "errorcode" in status:
                        # Permission or other error
                        if status and status.get("errorcode"):
                            current_app.logger.error(
                                "Error getting submission status for assignment %s: %s",
                                assignment_id,
                                status,
                            )
                        continue

                    lastattempt = status.get("lastattempt", {})
                    submission = lastattempt.get("submission", {})

                    if not submission or submission.get("status") == "draft":
                        continue

                    for plugin in submission.get("plugins", []):
                        if plugin.get("type") != "file":
                            continue
                        for file_area in plugin.get("fileareas", []):
                            for file_info in file_area.get("files", []):
                                file_info["source"] = f"Assignment: {assignment.get('name')}"
                                files.append(file_info)
    except Exception as e:
        current_app.logger.error(f"Error getting assignment files: {e}")
    return files


def get_user_courses(user_id: int):
    """Get courses where user is enrolled."""
    try:
        data = moodle_api_call("core_enrol_get_users_courses", {"userid": user_id})
        return data if data else []
    except Exception:
        return []


def get_enrolled_users(course_id=None):
    """Return users enrolled in a specific course."""
    if not course_id:
        course_id = session.get("context_id")
        
    if not course_id:
        return []
    
    data = moodle_api_call("core_enrol_get_enrolled_users", {"courseid": course_id})
    if not data:
        return []
    
    filtered_users = []
    for u in data:
        username = u.get("username", "")
        if username in ["guest", "apiuser"]:
            continue
            
        user_info = {
            "id": u.get("id"),
            "username": username,
            "fullname": u.get("fullname", "").strip(),
            "email": u.get("email", ""),
            "roles": u.get("roles", [])
        }
        filtered_users.append(user_info)
    
    return filtered_users


def get_all_users(limit=200, offset=0):
    """Get enrolled users (renamed for compatibility)"""
    return get_enrolled_users()


def get_courses():
    """Get available courses for course selection."""
    data = moodle_api_call("core_course_get_courses")
    if not data:
        return []
    
    # Filter out the site course (usually id=1)
    courses = [course for course in data if course.get("id", 0) > 1]
    return courses


def download_moodle_file(file_url: str, token: str | None = None):
    base_url, fallback_token = _moodle_config()
    token = token or fallback_token
    if not token:
        current_app.logger.error("Cannot download Moodle file: missing token.")
        return None
    # file_url already contains pluginfile path; append token
    try:
        current_app.logger.info("Downloading Moodle file %s", file_url)
        resp = requests.get(f"{file_url}?token={token}", timeout=10)
        resp.raise_for_status()
        content = resp.content
        current_app.logger.info(
            "Downloaded Moodle file %s (%d bytes)", file_url, len(content)
        )
        return content
    except Exception as exc:  # pragma: no cover - network errors
        current_app.logger.error("Failed downloading Moodle file %s: %s", file_url, exc)
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
        info = {
            "id": file_id,
            "filename": filename,
            "path": path,
            "owner": int(session.get("user_id")),
        }
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
    info = {
        "id": file_id,
        "filename": filename,
        "path": path,
        "owner": int(session.get("user_id")),
    }
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
    user_id = int(session.get("user_id"))
    if is_admin_user(roles):
        files = list(FILE_METADATA.values())
    else:
        files = [f for f in FILE_METADATA.values() if f.get("owner") == user_id]
    return jsonify(files)


@files_bp.route("/file_browser")
def file_browser():
    roles = session.get("roles", [])
    session_user = int(session.get("user_id"))
    admin = is_admin_user(roles)
    selected_user = request.args.get("user_id", type=int)
    selected_course = request.args.get("course_id", type=int)
    ltik = getattr(g, "ltik", request.args.get("ltik"))

    base_url, token = _moodle_config()

    # Admin with no user selected
    if admin and not selected_user:
        # Get course ID from session, URL parameter, or show course selector
        course_id = selected_course or session.get("context_id")
        
        if not course_id:
            # Show course selector
            courses = get_courses()
            html = """
            <html>
            <head>
                <title>File Browser - Select Course</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; }
                    .course-card { 
                        border: 1px solid #ddd; 
                        margin: 10px 0; 
                        padding: 15px; 
                        border-radius: 5px;
                        background: #f9f9f9;
                        display: block;
                        text-decoration: none;
                        color: inherit;
                    }
                    .course-card:hover { background: #f0f0f0; }
                    .course-name { font-weight: bold; font-size: 16px; margin-bottom: 5px; }
                    .course-details { color: #666; font-size: 14px; }
                </style>
            </head>
            <body>
                <h1>File Browser - Select Course</h1>
                <p>First, select a course to view enrolled users.</p>
                
                {% for course in courses %}
                <a href="{{ url_for('files.file_browser') }}?course_id={{ course.id }}&ltik={{ ltik }}" class="course-card">
                    <div class="course-name">{{ course.fullname }}</div>
                    <div class="course-details">
                        <strong>Short name:</strong> {{ course.shortname }}
                    </div>
                </a>
                {% endfor %}
                
                {% if not courses %}
                <p>No courses found.</p>
                {% endif %}
            </body>
            </html>
            """
            return render_template_string(html, courses=courses, ltik=ltik)
        
        # Get users enrolled in the selected course
        users = get_enrolled_users(course_id)
        context_title = session.get("context_title", f"Course {course_id}")
        
        html = """
        <html>
        <head>
            <title>File Browser - Select User</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .user-card { 
                    border: 1px solid #ddd; 
                    margin: 10px 0; 
                    padding: 15px; 
                    border-radius: 5px;
                    background: #f9f9f9;
                    display: block;
                    text-decoration: none;
                    color: inherit;
                }
                .user-card:hover { background: #f0f0f0; }
                .user-name { font-weight: bold; font-size: 16px; margin-bottom: 5px; }
                .user-details { color: #666; font-size: 14px; }
                .user-roles { margin-top: 5px; }
                .role-tag { 
                    display: inline-block; 
                    background: #28a745; 
                    color: white; 
                    padding: 2px 8px; 
                    border-radius: 3px; 
                    font-size: 11px; 
                    margin-right: 5px;
                }
                .warning { 
                    background: #fff3cd; 
                    border: 1px solid #ffeaa7; 
                    padding: 10px; 
                    border-radius: 5px;
                    margin-bottom: 20px;
                }
                .back-link { margin-bottom: 15px; }
            </style>
        </head>
        <body>
            <h1>File Browser - Select User</h1>
            
            {% if not (base_url and token) %}
            <div class="warning">
                <strong>Note:</strong> Moodle configuration incomplete.
                Set MOODLE_URL and MOODLE_API_TOKEN.
            </div>
            {% endif %}
            
            {% if selected_course %}
            <div class="back-link">
                <a href="{{ url_for('files.file_browser') }}?ltik={{ ltik }}">&larr; Back to course selection</a>
            </div>
            {% endif %}
            
            {% if context_title %}
            <p><strong>Course:</strong> {{ context_title }}</p>
            {% endif %}
            
            <p>Select a user to view their files. Showing {{ users|length }} enrolled users.</p>
            
            {% for u in users %}
            <a href="{{ url_for('files.file_browser') }}?user_id={{ u.id }}&course_id={{ selected_course }}&ltik={{ ltik }}" class="user-card">
                <div class="user-name">{{ u.fullname or ('User ' ~ u.id) }}</div>
                <div class="user-details">
                    <strong>Username:</strong> {{ u.username }} | 
                    <strong>Email:</strong> {{ u.email }}
                </div>
                {% if u.roles %}
                <div class="user-roles">
                    {% for role in u.roles %}
                        <span class="role-tag">{{ role.shortname or role.name }}</span>
                    {% endfor %}
                </div>
                {% endif %}
            </a>
            {% endfor %}
            
            {% if not users %}
            <p>No users found in this course.</p>
            {% endif %}
        </body>
        </html>
        """
        return render_template_string(
            html, 
            users=users, 
            admin=admin, 
            ltik=ltik, 
            base_url=base_url, 
            token=token,
            context_title=context_title,
            selected_course=course_id
        )

    # Admin + user selected: show that user's Moodle files and local uploads
    if admin and selected_user:
        course_id = selected_course or session.get("context_id")
        
        moodle_files = get_user_files(selected_user, course_id)
        local_files = [f for f in FILE_METADATA.values() if f.get("owner") == selected_user]
        
        back_url = url_for('files.file_browser')
        if selected_course:
            back_url += f"?course_id={selected_course}"
        back_url += f"&ltik={ltik}"
        
        html = """
        <html>
        <head>
            <title>User Files</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .file-section { margin: 20px 0; }
                .file-item { 
                    border: 1px solid #ddd; 
                    padding: 10px; 
                    margin: 5px 0; 
                    border-radius: 3px;
                    background: #f9f9f9;
                }
                .file-details { font-size: 12px; color: #666; margin-top: 5px; }
            </style>
        </head>
        <body>
            <h1>User {{ selected_user }} Files</h1>
            <p><a href="{{ back_url }}">&larr; Back to user list</a></p>

            <div class="file-section">
                <h2>Moodle Files ({{ moodle_files|length }})</h2>
                {% if not moodle_files %}
                    <p>No Moodle files found for this user.</p>
                {% else %}
                    {% for f in moodle_files %}
                    <div class="file-item">
                        <strong>{{ f.filename or 'Unnamed file' }}</strong>
                        {% if f.fileurl %}
                            - <a href="{{ f.fileurl }}?token={{ token }}" target="_blank" rel="noopener">Open</a>
                        {% endif %}
                        <div class="file-details">
                            Size: {{ f.filesize or 'Unknown' }} bytes | 
                            Source: {{ f.source or 'Unknown' }}
                        </div>
                    </div>
                    {% endfor %}
                {% endif %}
            </div>

            <div class="file-section">
                <h2>Local Uploads ({{ local_files|length }})</h2>
                {% if not local_files %}
                    <p>No local uploads for this user.</p>
                {% else %}
                    {% for f in local_files %}
                    <div class="file-item">
                        <strong>{{ f.filename }}</strong>
                        - <a href="{{ url_for('files.download_file', file_id=f.id) }}?ltik={{ ltik }}">Download</a>
                    </div>
                    {% endfor %}
                {% endif %}
            </div>
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
            back_url=back_url,
            course_id=course_id
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
