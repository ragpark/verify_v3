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
    Note: Moodle doesn't have a generic "get all user files" API,
    so we need to check specific contexts where files can exist.
    """
    all_files = []
    
    # 1. Get assignment submission files (most common for student files)
    if course_id:
        assignment_files = get_assignment_files(user_id, course_id)
        all_files.extend(assignment_files)
    
    # 2. Get files from enrolled courses (if no specific course provided)
    if not course_id:
        enrolled_courses = get_user_courses(user_id)
        for course in enrolled_courses:
            # Get assignment files for each course
            assignment_files = get_assignment_files(user_id, course.get('id'))
            all_files.extend(assignment_files)
            
            # Get course resources (if user has access)
            course_files = get_course_module_files(course.get('id'), user_id)
            all_files.extend(course_files)
    else:
        # Get course resources for specific course
        course_files = get_course_module_files(course_id, user_id)
        all_files.extend(course_files)
    
    # 3. Get forum attachment files (if needed)
    if course_id:
        forum_files = get_forum_files(user_id, course_id)
        all_files.extend(forum_files)
    
    # 4. Get workshop submission files (if using workshops)
    if course_id:
        workshop_files = get_workshop_files(user_id, course_id)
        all_files.extend(workshop_files)
    
    # Remove duplicates based on filename and filesize
    seen_files = set()
    unique_files = []
    for file_info in all_files:
        # Create a unique key for each file
        file_key = f"{file_info.get('filename', '')}-{file_info.get('filesize', 0)}-{file_info.get('timemodified', 0)}"
        if file_key not in seen_files:
            seen_files.add(file_key)
            unique_files.append(file_info)
    
    current_app.logger.info(f"Total unique files for user {user_id}: {len(unique_files)}")
    return unique_files


def get_course_module_files(course_id: int, user_id: int = None):
    """
    Get files from course modules (resources, folders, etc.).
    This includes PDFs, documents, and other resources uploaded by instructors.
    """
    files = []
    try:
        # Get course contents with options to include files
        params = {
            "courseid": course_id,
            "options": [
                {"name": "includestealthmodules", "value": "1"},
                {"name": "sectionid", "value": "0"},  # All sections
                {"name": "sectionnumber", "value": "0"},
                {"name": "cmid", "value": "0"},
                {"name": "modname", "value": ""},
                {"name": "modid", "value": "0"}
            ]
        }
        
        course_content = moodle_api_call("core_course_get_contents", params)
        
        if course_content and not isinstance(course_content, dict):  # Should be a list
            for section in course_content:
                for module in section.get('modules', []):
                    # Check if module is visible to user
                    if module.get('uservisible', False) or module.get('visible', 1) == 1:
                        # Process different module types
                        modname = module.get('modname', '')
                        
                        if modname in ['resource', 'folder', 'url', 'page']:
                            # These modules can contain files
                            for content in module.get('contents', []):
                                if content.get('type') == 'file':
                                    file_info = {
                                        'filename': content.get('filename', 'Unknown'),
                                        'filesize': content.get('filesize', 0),
                                        'fileurl': content.get('fileurl', ''),
                                        'timemodified': content.get('timemodified', 0),
                                        'mimetype': content.get('mimetype', ''),
                                        'source': f"Course: {module.get('name', 'Unknown module')}",
                                        'module_type': modname,
                                        'module_id': module.get('id', 0)
                                    }
                                    files.append(file_info)
                        
                        elif modname == 'label':
                            # Labels might contain embedded files in description
                            # These are typically inline and not downloadable
                            pass
                            
    except Exception as e:
        current_app.logger.error(f"Error getting course module files for course {course_id}: {e}")
    
    return files


def get_assignment_files(user_id: int, course_id: int):
    """
    Get assignment submission files for a user.
    This is the most reliable way to get student-submitted files.
    """
    files = []
    try:
        # First, get all assignments in the course
        assignments_response = moodle_api_call(
            "mod_assign_get_assignments", 
            {"courseids": [course_id]}
        )
        
        if not assignments_response or "courses" not in assignments_response:
            current_app.logger.warning(f"No assignments found for course {course_id}")
            return files
        
        for course_data in assignments_response["courses"]:
            for assignment in course_data.get("assignments", []):
                assignment_id = assignment.get("id")
                assignment_name = assignment.get("name", "Unknown Assignment")
                
                try:
                    # Get the user's submission for this assignment
                    submissions_response = moodle_api_call(
                        "mod_assign_get_submissions",
                        {"assignmentids": [assignment_id], "status": "submitted"}
                    )
                    
                    if submissions_response and "assignments" in submissions_response:
                        for assign_data in submissions_response["assignments"]:
                            for submission in assign_data.get("submissions", []):
                                if submission.get("userid") != user_id:
                                    continue
                                
                                # Process submission plugins
                                for plugin in submission.get("plugins", []):
                                    if plugin.get("type") == "file":
                                        # File submission plugin
                                        for filearea in plugin.get("fileareas", []):
                                            for file_info in filearea.get("files", []):
                                                if file_info.get('filename', '') != '.':  # Skip directory entries
                                                    file_data = {
                                                        'filename': file_info.get('filename', 'Unknown'),
                                                        'filesize': file_info.get('filesize', 0),
                                                        'fileurl': file_info.get('fileurl', ''),
                                                        'timemodified': file_info.get('timemodified', 0),
                                                        'mimetype': file_info.get('mimetype', ''),
                                                        'source': f"Assignment: {assignment_name}",
                                                        'submission_status': submission.get('status', ''),
                                                        'assignment_id': assignment_id
                                                    }
                                                    files.append(file_data)
                                    
                                    elif plugin.get("type") == "onlinetext":
                                        # Online text might contain embedded images
                                        # These would need special handling
                                        pass
                
                except Exception as e:
                    # Try alternative method using submission status
                    try:
                        status_response = moodle_api_call(
                            "mod_assign_get_submission_status",
                            {"assignid": assignment_id, "userid": user_id}
                        )
                        
                        if status_response and "lastattempt" in status_response:
                            submission = status_response["lastattempt"].get("submission", {})
                            
                            if submission and submission.get("status") != "new":
                                for plugin in submission.get("plugins", []):
                                    if plugin.get("type") == "file":
                                        for filearea in plugin.get("fileareas", []):
                                            for file_info in filearea.get("files", []):
                                                if file_info.get('filename', '') != '.':
                                                    file_data = {
                                                        'filename': file_info.get('filename', 'Unknown'),
                                                        'filesize': file_info.get('filesize', 0),
                                                        'fileurl': file_info.get('fileurl', ''),
                                                        'timemodified': file_info.get('timemodified', 0),
                                                        'mimetype': file_info.get('mimetype', ''),
                                                        'source': f"Assignment: {assignment_name}",
                                                        'submission_status': submission.get('status', ''),
                                                        'assignment_id': assignment_id
                                                    }
                                                    files.append(file_data)
                    except Exception as e2:
                        current_app.logger.debug(f"Could not get submission status for assignment {assignment_id}, user {user_id}: {e2}")
                        
    except Exception as e:
        current_app.logger.error(f"Error getting assignment files for user {user_id} in course {course_id}: {e}")
    
    return files


def get_forum_files(user_id: int, course_id: int):
    """
    Get files attached to forum posts by a user.
    """
    files = []
    try:
        # Get forums in the course
        forums_response = moodle_api_call(
            "mod_forum_get_forums_by_courses",
            {"courseids": [course_id]}
        )
        
        if forums_response:
            for forum in forums_response:
                forum_id = forum.get("id")
                forum_name = forum.get("name", "Unknown Forum")
                
                # Get discussions in the forum
                discussions_response = moodle_api_call(
                    "mod_forum_get_forum_discussions",
                    {"forumid": forum_id}
                )
                
                if discussions_response and "discussions" in discussions_response:
                    for discussion in discussions_response["discussions"]:
                        # Check if discussion was started by our user
                        if discussion.get("userid") == user_id:
                            # Check for attachments in the discussion
                            if discussion.get("attachment"):
                                file_data = {
                                    'filename': discussion.get('attachment', 'Unknown'),
                                    'filesize': 0,  # Not provided by API
                                    'fileurl': '',  # Would need to construct
                                    'timemodified': discussion.get('timemodified', 0),
                                    'source': f"Forum: {forum_name}",
                                    'forum_id': forum_id
                                }
                                files.append(file_data)
                        
                        # Get posts in the discussion to find user's replies with attachments
                        posts_response = moodle_api_call(
                            "mod_forum_get_discussion_posts",
                            {"discussionid": discussion.get("discussion")}
                        )
                        
                        if posts_response and "posts" in posts_response:
                            for post in posts_response["posts"]:
                                if post.get("userid") == user_id and post.get("attachments"):
                                    for attachment in post["attachments"]:
                                        file_data = {
                                            'filename': attachment.get('filename', 'Unknown'),
                                            'filesize': attachment.get('filesize', 0),
                                            'fileurl': attachment.get('fileurl', ''),
                                            'timemodified': attachment.get('timemodified', 0),
                                            'mimetype': attachment.get('mimetype', ''),
                                            'source': f"Forum: {forum_name}",
                                            'forum_id': forum_id
                                        }
                                        files.append(file_data)
                                        
    except Exception as e:
        current_app.logger.error(f"Error getting forum files for user {user_id} in course {course_id}: {e}")
    
    return files


def get_workshop_files(user_id: int, course_id: int):
    """
    Get files from workshop submissions.
    """
    files = []
    try:
        # Get workshops in the course
        # Note: There's no direct API to list workshops, so we'd need to get them from course modules
        course_content = moodle_api_call("core_course_get_contents", {"courseid": course_id})
        
        if course_content:
            for section in course_content:
                for module in section.get('modules', []):
                    if module.get('modname') == 'workshop':
                        workshop_id = module.get('instance')
                        workshop_name = module.get('name', 'Unknown Workshop')
                        
                        # Get workshop submissions
                        submissions_response = moodle_api_call(
                            "mod_workshop_get_submissions",
                            {"workshopid": workshop_id}
                        )
                        
                        if submissions_response and "submissions" in submissions_response:
                            for submission in submissions_response["submissions"]:
                                if submission.get("authorid") == user_id:
                                    # Check for attachment files
                                    for attachment in submission.get("attachments", []):
                                        file_data = {
                                            'filename': attachment.get('filename', 'Unknown'),
                                            'filesize': attachment.get('filesize', 0),
                                            'fileurl': attachment.get('fileurl', ''),
                                            'timemodified': submission.get('timemodified', 0),
                                            'mimetype': attachment.get('mimetype', ''),
                                            'source': f"Workshop: {workshop_name}",
                                            'workshop_id': workshop_id
                                        }
                                        files.append(file_data)
                                        
    except Exception as e:
        current_app.logger.error(f"Error getting workshop files for user {user_id} in course {course_id}: {e}")
    
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


def download_moodle_file(file_url: str, token: str = None):
    """
    Download a file from Moodle using the webservice token.
    File URLs from Moodle typically require token authentication.
    """
    base_url, fallback_token = _moodle_config()
    token = token or fallback_token
    
    if not token:
        current_app.logger.error("Cannot download Moodle file: missing token.")
        return None
    
    try:
        # Moodle file URLs might already have parameters, so check for ? in URL
        separator = '&' if '?' in file_url else '?'
        authenticated_url = f"{file_url}{separator}token={token}"
        
        current_app.logger.info(f"Downloading Moodle file from: {file_url}")
        
        resp = requests.get(authenticated_url, timeout=30)  # Increased timeout for larger files
        resp.raise_for_status()
        
        content = resp.content
        current_app.logger.info(f"Downloaded Moodle file: {len(content)} bytes")
        
        return content
        
    except requests.exceptions.RequestException as exc:
        current_app.logger.error(f"Failed downloading Moodle file {file_url}: {exc}")
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
