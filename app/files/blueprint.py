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


def get_user_files(user_id: int, course_id: int = None):
    """
    Return all files for a user across different contexts.
    Searches private files, course files, and submission areas.
    """
    all_files = []
    
    # 1. Try to get user's private files (handle API errors gracefully)
    current_app.logger.info(f"Getting private files for user {user_id}")
    try:
        private_files = moodle_api_call("core_files_get_user_files", {"userid": user_id})
        if private_files and isinstance(private_files, dict):
            if "files" in private_files:
                files_list = private_files.get("files", [])
                current_app.logger.info(f"Private files for user {user_id}: {len(files_list)} files")
                all_files.extend(files_list)
            elif "errorcode" in private_files:
                current_app.logger.warning(f"Private files API error for user {user_id}: {private_files.get('message', 'Unknown error')}")
        else:
            current_app.logger.warning(f"No private files response for user {user_id}")
    except Exception as e:
        current_app.logger.error(f"Exception getting private files for user {user_id}: {e}")
    
    # 2. Try alternative method for private files if main method failed
    try:
        # Try using a different approach to get user files
        user_context_files = get_user_context_files(user_id)
        all_files.extend(user_context_files)
    except Exception as e:
        current_app.logger.debug(f"Alternative user context files failed: {e}")
    
    # 3. If we have a course context, get course-related files
    if course_id:
        current_app.logger.info(f"Getting course files for user {user_id} in course {course_id}")
        course_files = get_course_user_files(user_id, course_id)
        all_files.extend(course_files)
    
    # 4. Get files from all courses the user is enrolled in (avoid duplicate if same course)
    enrolled_courses = get_user_courses(user_id)
    current_app.logger.info(f"User {user_id} enrolled in {len(enrolled_courses)} courses")
    for course in enrolled_courses:
        course_id_enrolled = course.get('id')
        # Skip if this is the same course we already processed
        if course_id_enrolled != course_id:
            course_files = get_course_user_files(user_id, course_id_enrolled)
            all_files.extend(course_files)
    
    # Remove duplicates based on file ID
    seen_files = set()
    unique_files = []
    for file_info in all_files:
        # Create a unique identifier for the file
        file_id = file_info.get('id') or f"{file_info.get('filename', '')}-{file_info.get('filesize', 0)}-{file_info.get('contextid', '')}"
        if file_id not in seen_files:
            seen_files.add(file_id)
            unique_files.append(file_info)
    
    current_app.logger.info(f"Total unique files for user {user_id}: {len(unique_files)}")
    return unique_files


def get_user_context_files(user_id: int):
    """Try alternative methods to get user files."""
    files = []
    
    try:
        # Try to get user context ID first
        user_info = moodle_api_call("core_user_get_users_by_field", {
            "field": "id",
            "values": [user_id]
        })
        
        if user_info and len(user_info) > 0:
            # Try to get files from user context
            user_context = moodle_api_call("core_files_get_files", {
                "contextid": f"user_{user_id}",  # This might need adjustment
                "component": "user",
                "filearea": "private"
            })
            
            if user_context and isinstance(user_context, dict) and "files" in user_context:
                for file_info in user_context["files"]:
                    file_info['source'] = 'user_private_area'
                    files.append(file_info)
    
    except Exception as e:
        current_app.logger.debug(f"Alternative user context method failed: {e}")
    
    return files


def get_user_courses(user_id: int):
    """Get courses where user is enrolled."""
    data = moodle_api_call("core_enrol_get_users_courses", {"userid": user_id})
    if data:
        current_app.logger.info(f"User {user_id} courses: {len(data)} courses found")
        return data
    else:
        current_app.logger.warning(f"No courses found for user {user_id}")
        return []


def get_course_user_files(user_id: int, course_id: int):
    """Get files from a specific course context for a user."""
    files = []
    
    try:
        current_app.logger.info(f"Getting course content for course {course_id}")
        
        # Method 1: Get all course files from modules
        course_content = moodle_api_call("core_course_get_contents", {"courseid": course_id})
        if course_content and isinstance(course_content, list):
            current_app.logger.info(f"Course {course_id} has {len(course_content)} sections")
            for section in course_content:
                for module in section.get('modules', []):
                    # Look for files in course modules
                    module_files = module.get('contents', [])
                    for file_info in module_files:
                        # Add some context to help identify the file
                        file_info['course_context'] = f"Course {course_id}, Module: {module.get('name', 'Unknown')}"
                        files.append(file_info)
                    
                    # If this is an assignment, try to get user submissions
                    if module.get('modname') == 'assign':
                        assignment_id = module.get('instance')
                        if assignment_id:
                            assignment_files = get_assignment_user_files(user_id, assignment_id, module.get('name', 'Unknown'))
                            files.extend(assignment_files)
        
        # Method 2: Try to get general assignment submissions for the course
        try:
            current_app.logger.info(f"Getting assignment submissions for user {user_id} in course {course_id}")
            # Get all assignments in the course first
            assignments = moodle_api_call("mod_assign_get_assignments", {"courseids": [course_id]})
            if assignments and isinstance(assignments, dict) and "courses" in assignments:
                for course_data in assignments['courses']:
                    for assignment in course_data.get('assignments', []):
                        assignment_files = get_assignment_user_files(user_id, assignment['id'], assignment.get('name', 'Unknown'))
                        files.extend(assignment_files)
            elif assignments and isinstance(assignments, dict) and "errorcode" in assignments:
                current_app.logger.warning(f"Assignment API error: {assignments.get('message', 'Unknown error')}")
        except Exception as e:
            current_app.logger.error(f"Error getting assignments for course {course_id}: {e}")
        
        # Method 3: Try to get course files using different APIs
        try:
            # Get course files using the files API
            course_files = moodle_api_call("core_files_get_files", {
                "contextid": course_id,
                "component": "course",
                "filearea": "content"
            })
            if course_files and isinstance(course_files, dict) and "files" in course_files:
                for file_info in course_files["files"]:
                    file_info['course_context'] = f"Course {course_id} content"
                    files.append(file_info)
        except Exception as e:
            current_app.logger.debug(f"Course files API not available or error: {e}")
    
    except Exception as e:
        current_app.logger.error(f"Error getting course files for user {user_id} in course {course_id}: {e}")
    
    current_app.logger.info(f"Found {len(files)} course files for user {user_id} in course {course_id}")
    return files


def get_assignment_user_files(user_id: int, assignment_id: int, assignment_name: str):
    """Get files from a specific assignment for a user."""
    files = []
    
    try:
        current_app.logger.info(f"Getting submissions for assignment {assignment_id}, user {user_id}")
        
        # Get user submissions for this assignment
        submissions = moodle_api_call("mod_assign_get_submissions", {
            "assignmentids": [assignment_id]
        })
        
        if submissions and isinstance(submissions, dict) and 'assignments' in submissions:
            for assign in submissions['assignments']:
                for submission in assign.get('submissions', []):
                    if submission.get('userid') == user_id:
                        current_app.logger.info(f"Found submission for user {user_id} in assignment {assignment_id}")
                        # Process submission files
                        for plugin in submission.get('plugins', []):
                            if plugin.get('type') == 'file':
                                for file_area in plugin.get('fileareas', []):
                                    for file_info in file_area.get('files', []):
                                        file_info['assignment_context'] = f"Assignment: {assignment_name}"
                                        files.append(file_info)
        elif submissions and isinstance(submissions, dict) and "errorcode" in submissions:
            current_app.logger.warning(f"Submission API error for assignment {assignment_id}: {submissions.get('message', 'Unknown error')}")
            
    except Exception as e:
        current_app.logger.error(f"Error getting assignment files for user {user_id}, assignment {assignment_id}: {e}")
    
    return files


def get_courses():
    """Get available courses for course selection."""
    data = moodle_api_call("core_course_get_courses")
    if not data:
        return []
    
    # Filter out the site course (usually id=1)
    courses = [course for course in data if course.get("id", 0) > 1]
    current_app.logger.info(f"Found {len(courses)} available courses")
    return courses


def get_enrolled_users(course_id=None):
    """
    Return users enrolled in a specific course.
    If no course_id provided, try to get it from LTI session context.
    """
    if not course_id:
        # Try to get course ID from LTI session context
        course_id = session.get("context_id")
        
    if not course_id:
        current_app.logger.warning("No course ID available for getting enrolled users")
        return []
    
    data = moodle_api_call(
        "core_enrol_get_enrolled_users", 
        {"courseid": course_id}
    )
    
    if not data:
        current_app.logger.warning(f"No data returned from core_enrol_get_enrolled_users for course {course_id}")
        return []
    
    # Filter and normalize the user data
    filtered_users = []
    for u in data:
        # Skip system users if needed
        username = u.get("username", "")
        if username in ["guest", "apiuser"]:
            continue
            
        user_info = {
            "id": u.get("id"),
            "username": username,
            "fullname": u.get("fullname", "").strip(),
            "email": u.get("email", ""),
            "firstaccess": u.get("firstaccess", 0),
            "lastaccess": u.get("lastaccess", 0),
            "roles": u.get("roles", [])
        }
        filtered_users.append(user_info)
    
    current_app.logger.info(f"Found {len(filtered_users)} enrolled users in course {course_id}")
    return filtered_users

# Keep the old function name for compatibility, but use the new implementation
def get_all_users(limit=200, offset=0):
    """Get enrolled users (renamed for compatibility)"""
    return get_enrolled_users()


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
    course_id = request.args.get("course_id", type=int)
    files = get_user_files(user_id, course_id)
    return jsonify(files)


@files_bp.route("/debug_user_files/<int:user_id>")
def debug_user_files(user_id: int):
    """Debug route to see raw API responses."""
    if not is_admin_user(session.get("roles", [])):
        return jsonify({"error": "forbidden"}), 403
    
    results = {}
    course_id = request.args.get("course_id", type=int) or session.get("context_id")
    
    # Test different API calls with error handling
    try:
        results["private_files"] = moodle_api_call("core_files_get_user_files", {"userid": user_id})
    except Exception as e:
        results["private_files"] = {"error": str(e)}
    
    try:
        results["user_courses"] = moodle_api_call("core_enrol_get_users_courses", {"userid": user_id})
    except Exception as e:
        results["user_courses"] = {"error": str(e)}
    
    # Try getting files from user's courses
    if course_id:
        try:
            results["course_contents"] = moodle_api_call("core_course_get_contents", {"courseid": course_id})
        except Exception as e:
            results["course_contents"] = {"error": str(e)}
        
        try:
            results["assignments"] = moodle_api_call("mod_assign_get_assignments", {"courseids": [course_id]})
        except Exception as e:
            results["assignments"] = {"error": str(e)}
        
        # Try getting specific assignment submissions
        if results.get("assignments") and isinstance(results["assignments"], dict) and "courses" in results["assignments"]:
            assignment_submissions = {}
            for course_data in results["assignments"]["courses"]:
                for assignment in course_data.get("assignments", []):
                    try:
                        assignment_submissions[assignment["id"]] = moodle_api_call("mod_assign_get_submissions", {
                            "assignmentids": [assignment["id"]]
                        })
                    except Exception as e:
                        assignment_submissions[assignment["id"]] = {"error": str(e)}
            results["assignment_submissions"] = assignment_submissions
        
        # Try direct assignment submission check based on course content
        if results.get("course_contents"):
            direct_assignment_checks = {}
            for section in results["course_contents"]:
                if isinstance(section, dict):
                    for module in section.get('modules', []):
                        if module.get('modname') == 'assign':
                            assignment_instance = module.get('instance')
                            if assignment_instance:
                                try:
                                    # Try multiple approaches to get assignment data
                                    direct_assignment_checks[f"assign_{assignment_instance}"] = {
                                        "assignment_info": moodle_api_call("mod_assign_get_assignments", {"assignmentids": [assignment_instance]}),
                                        "submissions": moodle_api_call("mod_assign_get_submissions", {"assignmentids": [assignment_instance]}),
                                        "user_status": moodle_api_call("mod_assign_get_user_flags", {"assignmentids": [assignment_instance]})
                                    }
                                except Exception as e:
                                    direct_assignment_checks[f"assign_{assignment_instance}"] = {"error": str(e)}
            results["direct_assignment_checks"] = direct_assignment_checks
    
    # Try alternative file APIs
    try:
        results["available_functions"] = moodle_api_call("core_webservice_get_site_info")
    except Exception as e:
        results["available_functions"] = {"error": str(e)}
    
    # Show what our enhanced function finds
    try:
        results["enhanced_search_results"] = get_user_files(user_id, course_id)
    except Exception as e:
        results["enhanced_search_results"] = {"error": str(e)}
    
    return jsonify(results)


@files_bp.route("/check_assignment_submissions/<int:user_id>/<int:course_id>")
def check_assignment_submissions(user_id: int, course_id: int):
    """Specific route to check assignment submissions for a user."""
    if not is_admin_user(session.get("roles", [])):
        return jsonify({"error": "forbidden"}), 403
    
    results = {"submissions": [], "errors": []}
    
    try:
        # Get course content to find assignments
        course_content = moodle_api_call("core_course_get_contents", {"courseid": course_id})
        if course_content:
            for section in course_content:
                for module in section.get('modules', []):
                    if module.get('modname') == 'assign':
                        assignment_instance = module.get('instance')
                        assignment_name = module.get('name', 'Unknown Assignment')
                        
                        try:
                            # Get submissions for this specific assignment
                            submissions = moodle_api_call("mod_assign_get_submissions", {
                                "assignmentids": [assignment_instance]
                            })
                            
                            if submissions and 'assignments' in submissions:
                                for assign in submissions['assignments']:
                                    for submission in assign.get('submissions', []):
                                        if submission.get('userid') == user_id:
                                            submission_info = {
                                                "assignment_name": assignment_name,
                                                "assignment_id": assignment_instance,
                                                "submission_id": submission.get('id'),
                                                "status": submission.get('status'),
                                                "plugins": submission.get('plugins', []),
                                                "timemodified": submission.get('timemodified'),
                                            }
                                            results["submissions"].append(submission_info)
                        except Exception as e:
                            results["errors"].append(f"Error checking assignment {assignment_instance}: {str(e)}")
    
    except Exception as e:
        results["errors"].append(f"Error getting course content: {str(e)}")
    
    return jsonify(results)


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
        
        # Add debugging
        current_app.logger.info(f"Getting files for user {selected_user}, course {course_id}")
        
        moodle_files = get_user_files(selected_user, course_id)
        local_files = [f for f in FILE_METADATA.values() if f.get("owner") == selected_user]
        
        # Log what we found
        current_app.logger.info(f"Found {len(moodle_files)} Moodle files, {len(local_files)} local files")
        if moodle_files:
            current_app.logger.info(f"Sample Moodle file: {moodle_files[0]}")
        
        back_url = url_for('files.file_browser')
        if selected_course:
            back_url += f"?course_id={selected_course}"
        back_url += f"&ltik={ltik}"
        
        # Enhanced HTML template with debugging info
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
                .debug-info { 
                    background: #e7f3ff; 
                    border: 1px solid #b3d9ff; 
                    padding: 10px; 
                    margin: 10px 0; 
                    border-radius: 3px;
                    font-family: monospace;
                    font-size: 12px;
                }
                .debug-link { 
                    background: #f0f0f0; 
                    border: 1px solid #ccc; 
                    padding: 10px; 
                    margin: 5px 0; 
                    border-radius: 3px;
                }
                .debug-link a {
                    color: #007cba;
                    text-decoration: none;
                    margin-right: 10px;
                }
                .debug-link a:hover {
                    text-decoration: underline;
                }
            </style>
        </head>
        <body>
            <h1>User {{ selected_user }} Files</h1>
            <p><a href="{{ back_url }}">&larr; Back to user list</a></p>

            <div class="debug-info">
                <strong>Debug Info:</strong><br>
                Moodle files found: {{ moodle_files|length }}<br>
                Local files found: {{ local_files|length }}<br>
                Course ID: {{ course_id }}<br>
                User ID: {{ selected_user }}
            </div>
            
            <div class="debug-link">
                <a href="{{ url_for('files.debug_user_files', user_id=selected_user) }}?course_id={{ course_id }}&ltik={{ ltik }}" target="_blank">
                    View Raw API Debug Data
                </a> | 
                <a href="{{ url_for('files.check_assignment_submissions', user_id=selected_user, course_id=course_id) }}?ltik={{ ltik }}" target="_blank">
                    Check Assignment Submissions
                </a>
            </div>

            <div class="file-section">
                <h2>Moodle Files ({{ moodle_files|length }})</h2>
                {% if not moodle_files %}
                    <p>No Moodle files found for this user.</p>
                    <p><em>This could mean: no files uploaded, permission issues, or files in different contexts.</em></p>
                {% else %}
                    {% for f in moodle_files %}
                    <div class="file-item">
                        <strong>{{ f.filename or 'Unnamed file' }}</strong>
                        {% if f.fileurl %}
                            - <a href="{{ f.fileurl }}?token={{ token }}" target="_blank" rel="noopener">Open</a>
                        {% endif %}
                        <div class="file-details">
                            Size: {{ f.filesize or 'Unknown' }} bytes | 
                            Type: {{ f.mimetype or 'Unknown' }} |
                            Component: {{ f.component or 'Unknown' }} |
                            Area: {{ f.filearea or 'Unknown' }}
                            {% if f.contextid %}| Context: {{ f.contextid }}{% endif %}
                            {% if f.course_context %}| {{ f.course_context }}{% endif %}
                            {% if f.assignment_context %}| {{ f.assignment_context }}{% endif %}
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
