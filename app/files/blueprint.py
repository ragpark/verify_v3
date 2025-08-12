"""
Moodle 4.5 File Browser Blueprint

This blueprint provides file browsing capabilities for Moodle users through LTI.
It retrieves files from various Moodle contexts including assignments, course modules,
forums, and workshops.

Configuration:
- Set MOODLE_URL and MOODLE_API_TOKEN environment variables
- Adjust FILE_SOURCE_CONFIG dictionary to enable/disable specific file sources
- Run /api_diagnostic endpoint as admin to test which APIs are available

Required Moodle Web Service Functions:
- core_course_get_contents
- core_enrol_get_users_courses
- core_enrol_get_enrolled_users
- mod_assign_get_assignments
- mod_assign_get_submission_status (preferred) or mod_assign_get_submissions

Optional Functions (enable in FILE_SOURCE_CONFIG if available):
- mod_forum_get_forums_by_courses
- mod_forum_get_forum_discussions
- mod_forum_get_discussion_posts
- mod_workshop_get_submissions
"""

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

# Configuration for which file sources to attempt
# Set these based on which Moodle web service functions are enabled for your API token
FILE_SOURCE_CONFIG = {
    "assignments": True,   # mod_assign_get_assignments, mod_assign_get_submissions
    "course_modules": True,  # core_course_get_contents
    "forums": False,       # mod_forum_* - Set to True if enabled
    "workshops": False,    # mod_workshop_get_submissions - Set to True if enabled
}

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def is_admin_user(roles) -> bool:
    """Return True if any role grants admin privileges. Accepts string, list[str], or list[dict]."""
    admin_indicators = {"administrator", "instructor", "contentdeveloper", "teachingassistant"}
    if not roles:
        return False

    # Normalise to list of strings
    if isinstance(roles, str):
        roles_list = roles.split()
    else:
        roles_list = []
        for r in roles:
            if isinstance(r, str):
                roles_list.append(r)
            elif isinstance(r, dict):
                if r.get("shortname"):
                    roles_list.append(r["shortname"])
                elif r.get("name"):
                    roles_list.append(r["name"])

    for role in roles_list:
        token = str(role).split("#")[-1].split("/")[-1].lower()
        if token in admin_indicators:
            return True
    return False


def _moodle_config():
    """Resolve Moodle configuration with fallbacks and light validation."""
    base_url = os.getenv("MOODLE_URL") or os.getenv("MOODLE_BASE_URL")
    token = os.getenv("MOODLE_API_TOKEN") or os.getenv("MOODLE_TOKEN")
    return base_url, token


def moodle_api_call(function: str, params: dict | None = None):
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

    # NEW: encode lists as Moodle expects
    encoded_params = _encode_moodle_params(params)

    log_params = {k: v for k, v in encoded_params.items() if k != "wstoken"}
    current_app.logger.info("Moodle API call %s with params %s", function, log_params)

    try:
        resp = requests.get(
            f"{base_url}/webservice/rest/server.php", params=encoded_params, timeout=10
        )
        resp.raise_for_status()
        data = resp.json()

        # Check if response is an error
        if isinstance(data, dict) and "errorcode" in data:
            current_app.logger.warning(
                "Moodle API error for %s: %s - %s",
                function,
                data.get("errorcode"),
                data.get("message", "No message")
            )
            # Return the error dict so callers can handle it
            return data

        # Log successful response (truncate if too long)
        response_str = str(data)
        if len(response_str) > 500:
            response_str = response_str[:500] + "..."
        current_app.logger.info("Moodle API response %s: %s", function, response_str)

        return data
    except Exception as exc:  # pragma: no cover - network errors
        current_app.logger.error("Moodle API call %s failed: %s", function, exc)
        return None


def get_user_files(user_id: int, course_id: int | None = None):
    """
    Return all files for a user across different contexts.
    Note: Moodle doesn't have a generic "get all user files" API,
    so we need to check specific contexts where files can exist.
    """
    all_files: list[dict] = []

    # 1. Get assignment submission files (most common for student files)
    if FILE_SOURCE_CONFIG.get("assignments", True):
        if course_id:
            current_app.logger.info(f"Getting assignment files for user {user_id} in course {course_id}")
            assignment_files = get_assignment_files(user_id, course_id)
            all_files.extend(assignment_files)
            current_app.logger.info(f"Found {len(assignment_files)} assignment files")
        else:
            # Get files from all enrolled courses
            enrolled_courses = get_user_courses(user_id)
            for course in enrolled_courses:
                assignment_files = get_assignment_files(user_id, course.get('id'))
                all_files.extend(assignment_files)

    # 2. Get course module files (resources, PDFs, etc.)
    if FILE_SOURCE_CONFIG.get("course_modules", True):
        if course_id:
            current_app.logger.info(f"Getting course module files for course {course_id}")
            course_files = get_course_module_files(course_id, user_id)
            all_files.extend(course_files)
            current_app.logger.info(f"Found {len(course_files)} course module files")
        else:
            # Get files from all enrolled courses
            enrolled_courses = get_user_courses(user_id)
            for course in enrolled_courses:
                course_files = get_course_module_files(course.get('id'), user_id)
                all_files.extend(course_files)

    # 3. Forum attachments (if enabled)
    if FILE_SOURCE_CONFIG.get("forums", False) and course_id:
        try:
            current_app.logger.info(f"Attempting to get forum files for user {user_id} in course {course_id}")
            forum_files = get_forum_files(user_id, course_id)
            all_files.extend(forum_files)
            if forum_files:
                current_app.logger.info(f"Found {len(forum_files)} forum files")
        except Exception as e:
            current_app.logger.debug(f"Error getting forum files: {e}")

    # 4. Workshop submissions (if enabled)
    if FILE_SOURCE_CONFIG.get("workshops", False) and course_id:
        try:
            current_app.logger.info(f"Attempting to get workshop files for user {user_id} in course {course_id}")
            workshop_files = get_workshop_files(user_id, course_id)
            all_files.extend(workshop_files)
            if workshop_files:
                current_app.logger.info(f"Found {len(workshop_files)} workshop files")
        except Exception as e:
            current_app.logger.debug(f"Error getting workshop files: {e}")

    # Remove duplicates based on filename, size, timestamp, and (if present) fileurl
    seen_files = set()
    unique_files = []
    for file_info in all_files:
        key_parts = [
            file_info.get('filename', ''),
            str(file_info.get('filesize', 0)),
            str(file_info.get('timemodified', 0)),
            file_info.get('fileurl', ''),
        ]
        file_key = "|".join(key_parts)
        if file_key not in seen_files:
            seen_files.add(file_key)
            unique_files.append(file_info)

    current_app.logger.info(f"Total unique files for user {user_id}: {len(unique_files)}")
    return unique_files


def get_course_module_files(course_id: int, user_id: int | None = None):
    """
    Get files from course modules (resources, folders, etc.).
    This includes PDFs, documents, and other resources uploaded by instructors.
    """
    files: list[dict] = []
    try:
        course_content = moodle_api_call("core_course_get_contents", {"courseid": course_id})

        # Check response validity
        if not course_content:
            return files

        if isinstance(course_content, str):
            current_app.logger.debug(f"Course content API returned string: {course_content}")
            return files

        if isinstance(course_content, dict) and "errorcode" in course_content:
            current_app.logger.debug(f"Course content error: {course_content.get('message', 'Unknown error')}")
            return files

        if isinstance(course_content, list):
            for section in course_content:
                if not isinstance(section, dict):
                    continue
                for module in section.get('modules', []):
                    # Check if module is visible to user
                    if module.get('uservisible', False) or module.get('visible', 1) == 1:
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
                            # Labels might contain embedded files in description (typically not downloadable)
                            pass

    except Exception as e:
        current_app.logger.error(f"Error getting course module files for course {course_id}: {e}")

    return files


def get_assignment_files(user_id: int, course_id: int):
    """
    Get assignment submission files for a user.
    This is the most reliable way to get student-submitted files.
    """
    files: list[dict] = []
    try:
        # First, get all assignments in the course
        assignments_response = moodle_api_call(
            "mod_assign_get_assignments",
            {"courseids": [course_id]}
        )

        # Check for error response
        if not assignments_response:
            return files

        if isinstance(assignments_response, dict) and "errorcode" in assignments_response:
            current_app.logger.warning(f"API error getting assignments: {assignments_response.get('message', 'Unknown error')}")
            return files

        if not isinstance(assignments_response, dict) or "courses" not in assignments_response:
            current_app.logger.warning(f"Unexpected assignments response format for course {course_id}")
            return files

        for course_data in assignments_response["courses"]:
            for assignment in course_data.get("assignments", []):
                assignment_id = assignment.get("id")
                assignment_name = assignment.get("name", "Unknown Assignment")

                try:
                    # Method 1: Get submission status (preferred)
                    status_response = moodle_api_call(
                        "mod_assign_get_submission_status",
                        {"assignid": assignment_id, "userid": user_id}
                    )

                    if status_response and not isinstance(status_response, str):
                        if isinstance(status_response, dict) and "errorcode" in status_response:
                            current_app.logger.error(
                                f"Error getting submission status for assignment {assignment_id}: {status_response.get('errorcode')}"
                            )
                        elif isinstance(status_response, dict) and "errorcode" not in status_response:
                            if "lastattempt" in status_response:
                                submission = status_response["lastattempt"].get("submission", {})

                                if submission and submission.get("status") not in ["new", None]:
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
                                                        # continue to next assignment
                                                        # (we still also try method 2 below in case of partial data)

                    # Method 2: Get submissions
                    submissions_response = moodle_api_call(
                        "mod_assign_get_submissions",
                        {"assignmentids": [assignment_id]}
                    )

                    if submissions_response and isinstance(submissions_response, dict):
                        if "assignments" in submissions_response:
                            for assign_data in submissions_response["assignments"]:
                                for submission in assign_data.get("submissions", []):
                                    if submission.get("userid") != user_id:
                                        continue

                                    if submission.get("status") in ["submitted", "graded"]:
                                        # Process submission plugins
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

                except Exception as e:
                    current_app.logger.debug(f"Could not get files for assignment {assignment_id}, user {user_id}: {e}")

    except Exception as e:
        current_app.logger.error(f"Error getting assignment files for user {user_id} in course {course_id}: {e}")

    return files


def get_forum_files(user_id: int, course_id: int):
    """
    Get files attached to forum posts by a user.
    """
    files: list[dict] = []
    try:
        # Get forums in the course
        forums_response = moodle_api_call(
            "mod_forum_get_forums_by_courses",
            {"courseids": [course_id]}
        )

        # Check for error response or invalid format
        if not forums_response:
            return files

        if isinstance(forums_response, str):
            current_app.logger.debug(f"Forum API returned string: {forums_response}")
            return files

        if isinstance(forums_response, dict) and "errorcode" in forums_response:
            current_app.logger.debug(f"Forum API error: {forums_response.get('message', 'Unknown error')}")
            return files

        # Ensure we have a list to iterate over
        if isinstance(forums_response, list):
            for forum in forums_response:
                forum_id = forum.get("id")
                forum_name = forum.get("name", "Unknown Forum")

                # Get discussions in the forum
                discussions_response = moodle_api_call(
                    "mod_forum_get_forum_discussions",
                    {"forumid": forum_id}
                )

                # Check response validity
                if not discussions_response or isinstance(discussions_response, str):
                    continue

                if isinstance(discussions_response, dict):
                    if "errorcode" in discussions_response:
                        continue

                    if "discussions" in discussions_response:
                        for discussion in discussions_response["discussions"]:
                            # Check if discussion was started by our user
                            if discussion.get("userid") == user_id:
                                # Some APIs expose 'attachment' as filename; details vary
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
                            disc_id = discussion.get("discussion") or discussion.get("id")
                            if not disc_id:
                                continue

                            posts_response = moodle_api_call(
                                "mod_forum_get_discussion_posts",
                                {"discussionid": disc_id}
                            )

                            # Check response validity
                            if posts_response and isinstance(posts_response, dict) and "posts" in posts_response:
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
    files: list[dict] = []
    try:
        # Get workshops in the course via course modules
        course_content = moodle_api_call("core_course_get_contents", {"courseid": course_id})

        # Check response validity
        if not course_content or isinstance(course_content, str):
            return files

        if isinstance(course_content, dict) and "errorcode" in course_content:
            current_app.logger.debug(f"Workshop course content error: {course_content.get('message', 'Unknown error')}")
            return files

        if isinstance(course_content, list):
            for section in course_content:
                if not isinstance(section, dict):
                    continue
                for module in section.get('modules', []):
                    if module.get('modname') == 'workshop':
                        workshop_id = module.get('instance')
                        workshop_name = module.get('name', 'Unknown Workshop')

                        # Get workshop submissions
                        submissions_response = moodle_api_call(
                            "mod_workshop_get_submissions",
                            {"workshopid": workshop_id}
                        )

                        # Check response validity
                        if not submissions_response or isinstance(submissions_response, str):
                            continue

                        if isinstance(submissions_response, dict):
                            if "errorcode" in submissions_response:
                                continue

                            if "submissions" in submissions_response:
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
            "roles": u.get("roles", []),
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

        resp = requests.get(authenticated_url, timeout=30)
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
    """
    Tries to hydrate session from an LTIK-like bearer token.
    NOTE: For true LTI 1.3, you should validate against the platform JWKS (RS256) and claims.
    This implementation assumes an HS256 app-signed token for simplicity.
    """
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
        return jsonify({"error": "No active LTI session. Please launch this tool from your LMS."}), 401

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
    try:
        user_id = int(session["user_id"])
    except (KeyError, TypeError, ValueError):
        return jsonify({"error": "unauthorized"}), 401

    if is_admin_user(roles):
        files = list(FILE_METADATA.values())
    else:
        files = [f for f in FILE_METADATA.values() if f.get("owner") == user_id]
    return jsonify(files)


@files_bp.route("/api_diagnostic")
def api_diagnostic():
    """Diagnostic endpoint to check which Moodle APIs are available."""
    roles = session.get("roles", [])
    if not is_admin_user(roles):
        return jsonify({"error": "Admin access required"}), 403

    base_url, token = _moodle_config()
    if not base_url or not token:
        return jsonify({"error": "Moodle configuration missing"}), 500

    # Test various API endpoints
    api_tests = {
        "core_webservice_get_site_info": {},
        "core_course_get_courses": {},
        "core_course_get_contents": {"courseid": 2},  # Adjust course ID as needed
        "core_enrol_get_enrolled_users": {"courseid": 2},
        "mod_assign_get_assignments": {"courseids": [2]},
        "mod_assign_get_submissions": {"assignmentids": [1]},  # Adjust assignment ID
        "mod_forum_get_forums_by_courses": {"courseids": [2]},
        "mod_workshop_get_submissions": {"workshopid": 1},      # Adjust workshop ID
    }

    results = {}
    for function, params in api_tests.items():
        response = moodle_api_call(function, params)
        if response is None:
            results[function] = "Network error or timeout"
        elif isinstance(response, dict) and "errorcode" in response:
            results[function] = f"Error: {response.get('errorcode')} - {response.get('message', 'No message')}"
        elif isinstance(response, str):
            results[function] = f"String response: {response[:100]}"
        else:
            results[function] = "Success"

    return jsonify({
        "moodle_url": base_url,
        "api_test_results": results,
        "file_source_config": FILE_SOURCE_CONFIG,
        "recommendation": "Enable forum and workshop APIs in FILE_SOURCE_CONFIG only if those tests succeed"
    })


def _encode_moodle_params(params: dict) -> dict:
    """
    Moodle REST expects list params as indexed keys:
    {"courseids": [2, 3]}  -> {"courseids[0]": 2, "courseids[1]": 3}
    Also coerces simple types to int/str as needed.
    """
    encoded = {}
    for k, v in (params or {}).items():
        if isinstance(v, list):
            for i, item in enumerate(v):
                encoded[f"{k}[{i}]"] = item
        else:
            encoded[k] = v
    return encoded


@files_bp.route("/file_browser", methods=["GET", "POST"])
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
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>File Browser - Select Course</title>
                <style>
                    * {
                        margin: 0;
                        padding: 0;
                        box-sizing: border-box;
                    }
            
                    body {
                        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                        background: linear-gradient(135deg, #1e293b 0%, #334155 50%, #475569 100%);
                        min-height: 100vh;
                        padding: 20px;
                        line-height: 1.6;
                    }
            
                    .container {
                        max-width: 800px;
                        margin: 0 auto;
                        animation: fadeIn 0.8s ease-out;
                    }
            
                    @keyframes fadeIn {
                        from {
                            opacity: 0;
                            transform: translateY(20px);
                        }
                        to {
                            opacity: 1;
                            transform: translateY(0);
                        }
                    }
            
                    .header {
                        background: white;
                        border-radius: 16px;
                        padding: 40px 30px;
                        margin-bottom: 30px;
                        box-shadow: 0 25px 50px rgba(0, 0, 0, 0.15);
                        border: 1px solid #e2e8f0;
                        text-align: center;
                    }
            
                    .header h1 {
                        font-size: 32px;
                        font-weight: 600;
                        color: #1e293b;
                        margin-bottom: 12px;
                        letter-spacing: -0.5px;
                    }
            
                    .header p {
                        font-size: 16px;
                        color: #64748b;
                        font-weight: 400;
                    }
            
                    .courses-grid {
                        display: grid;
                        gap: 20px;
                        grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
                    }
            
                    .course-card {
                        background: white;
                        border-radius: 12px;
                        padding: 24px;
                        text-decoration: none;
                        color: inherit;
                        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
                        border: 1px solid #e2e8f0;
                        transition: all 0.2s ease;
                        position: relative;
                        overflow: hidden;
                    }
            
                    .course-card::before {
                        content: '';
                        position: absolute;
                        top: 0;
                        left: 0;
                        width: 4px;
                        height: 100%;
                        background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
                        transform: scaleY(0);
                        transition: transform 0.2s ease;
                    }
            
                    .course-card:hover {
                        transform: translateY(-2px);
                        box-shadow: 0 12px 24px rgba(0, 0, 0, 0.1);
                        border-color: #6366f1;
                    }
            
                    .course-card:hover::before {
                        transform: scaleY(1);
                    }
            
                    .course-name {
                        font-size: 18px;
                        font-weight: 600;
                        color: #1e293b;
                        margin-bottom: 12px;
                        line-height: 1.4;
                        display: -webkit-box;
                        -webkit-line-clamp: 2;
                        -webkit-box-orient: vertical;
                        overflow: hidden;
                    }
            
                    .course-details {
                        display: flex;
                        align-items: center;
                        gap: 8px;
                        font-size: 14px;
                        color: #64748b;
                    }
            
                    .course-details strong {
                        color: #475569;
                        font-weight: 500;
                    }
            
                    .shortname {
                        background: #f1f5f9;
                        padding: 4px 8px;
                        border-radius: 6px;
                        font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, 'Courier New', monospace;
                        font-size: 13px;
                        color: #6366f1;
                        font-weight: 500;
                    }
            
                    .course-icon {
                        position: absolute;
                        top: 20px;
                        right: 20px;
                        width: 24px;
                        height: 24px;
                        background: #6366f1;
                        mask-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 24 24' stroke='currentColor'%3E%3Cpath stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.746 0 3.332.477 4.5 1.253v13C20.832 18.477 19.246 18 17.5 18c-1.746 0-3.332.477-4.5 1.253' /%3E%3C/svg%3E");
                        mask-repeat: no-repeat;
                        mask-position: center;
                        mask-size: contain;
                        opacity: 0.3;
                        transition: opacity 0.2s ease;
                    }
            
                    .course-card:hover .course-icon {
                        opacity: 0.6;
                    }
            
                    .empty-state {
                        background: white;
                        border-radius: 16px;
                        padding: 60px 40px;
                        text-align: center;
                        box-shadow: 0 25px 50px rgba(0, 0, 0, 0.15);
                        border: 1px solid #e2e8f0;
                    }
            
                    .empty-icon {
                        width: 64px;
                        height: 64px;
                        background: #e2e8f0;
                        mask-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 24 24' stroke='currentColor'%3E%3Cpath stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z' /%3E%3C/svg%3E");
                        mask-repeat: no-repeat;
                        mask-position: center;
                        mask-size: contain;
                        margin: 0 auto 20px;
                    }
            
                    .empty-title {
                        font-size: 20px;
                        font-weight: 600;
                        color: #1e293b;
                        margin-bottom: 8px;
                    }
            
                    .empty-description {
                        font-size: 16px;
                        color: #64748b;
                    }
            
                    @media (max-width: 768px) {
                        body {
                            padding: 15px;
                        }
            
                        .header {
                            padding: 30px 20px;
                        }
            
                        .header h1 {
                            font-size: 28px;
                        }
            
                        .courses-grid {
                            grid-template-columns: 1fr;
                            gap: 16px;
                        }
            
                        .course-card {
                            padding: 20px;
                        }
            
                        .empty-state {
                            padding: 40px 20px;
                        }
                    }
            
                    @media (max-width: 480px) {
                        .header h1 {
                            font-size: 24px;
                        }
            
                        .header p {
                            font-size: 15px;
                        }
            
                        .course-name {
                            font-size: 16px;
                        }
            
                        .course-details {
                            flex-direction: column;
                            align-items: flex-start;
                            gap: 4px;
                        }
                    }
            
                    /* Focus accessibility */
                    .course-card:focus {
                        outline: 2px solid #6366f1;
                        outline-offset: 2px;
                    }
            
                    /* Dark mode support */
                    @media (prefers-color-scheme: dark) {
                        .header,
                        .course-card,
                        .empty-state {
                            background: #1e293b;
                            border-color: #374151;
                        }
            
                        .header h1,
                        .course-name,
                        .empty-title {
                            color: #f1f5f9;
                        }
            
                        .header p,
                        .course-details,
                        .empty-description {
                            color: #94a3b8;
                        }
            
                        .course-details strong {
                            color: #cbd5e1;
                        }
            
                        .shortname {
                            background: #374151;
                            color: #a5b4fc;
                        }
            
                        .empty-icon {
                            background: #374151;
                        }
                    }
            
                    @media (prefers-reduced-motion: reduce) {
                        *, *::before, *::after {
                            animation-duration: 0.01ms !important;
                            animation-iteration-count: 1 !important;
                            transition-duration: 0.01ms !important;
                        }
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>File Browser</h1>
                        <p>Select a course to view enrolled users and access files</p>
                    </div>
                    
                    {% if courses %}
                    <div class="courses-grid">
                        {% for course in courses %}
                        <a href="{{ url_for('files.file_browser', course_id=course.id, ltik=ltik) }}" class="course-card">
                            <div class="course-icon"></div>
                            <div class="course-name">{{ course.fullname }}</div>
                            <div class="course-details">
                                <strong>Course ID:</strong>
                                <span class="shortname">{{ course.shortname }}</span>
                            </div>
                        </a>
                        {% endfor %}
                    </div>
                    {% else %}
                    <div class="empty-state">
                        <div class="empty-icon"></div>
                        <div class="empty-title">No courses found</div>
                        <div class="empty-description">There are currently no courses available for this user.</div>
                    </div>
                    {% endif %}
                </div>
            </body>
            </html>
            """
            return render_template_string(html, courses=courses, ltik=ltik)

        # Get users enrolled in the selected course
        users = get_enrolled_users(course_id)
        context_title = session.get("context_title", f"Course {course_id}")

        html = """
        <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>File Browser - Select User</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #1e293b 0%, #334155 50%, #475569 100%);
            min-height: 100vh;
            padding: 20px;
            line-height: 1.6;
        }

        .container {
            max-width: 900px;
            margin: 0 auto;
            animation: fadeIn 0.8s ease-out;
        }

        @keyframes fadeIn {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .header {
            background: white;
            border-radius: 16px;
            padding: 40px 30px;
            margin-bottom: 30px;
            box-shadow: 0 25px 50px rgba(0, 0, 0, 0.15);
            border: 1px solid #e2e8f0;
            text-align: center;
        }

        .header h1 {
            font-size: 32px;
            font-weight: 600;
            color: #1e293b;
            margin-bottom: 12px;
            letter-spacing: -0.5px;
        }

        .warning {
            background: linear-gradient(135deg, #fef3c7 0%, #fde68a 100%);
            border: 1px solid #f59e0b;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 30px;
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .warning-icon {
            width: 24px;
            height: 24px;
            background: #f59e0b;
            mask-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 24 24' stroke='currentColor'%3E%3Cpath stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z' /%3E%3C/svg%3E");
            mask-repeat: no-repeat;
            mask-position: center;
            mask-size: contain;
            flex-shrink: 0;
        }

        .warning-content {
            color: #92400e;
            font-size: 15px;
        }

        .warning-content strong {
            color: #78350f;
            font-weight: 600;
        }

        .navigation {
            margin-bottom: 30px;
        }

        .back-link {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: white;
            color: #6366f1;
            text-decoration: none;
            padding: 12px 20px;
            border-radius: 8px;
            font-weight: 500;
            font-size: 14px;
            border: 1px solid #e2e8f0;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
            transition: all 0.2s ease;
        }

        .back-link:hover {
            background: #f8fafc;
            transform: translateX(-2px);
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        }

        .back-arrow {
            font-size: 16px;
        }

        .context-info {
            background: white;
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
            border: 1px solid #e2e8f0;
        }

        .course-title {
            font-size: 18px;
            font-weight: 600;
            color: #1e293b;
            margin-bottom: 8px;
        }

        .user-count {
            font-size: 15px;
            color: #64748b;
        }

        .user-count strong {
            color: #6366f1;
            font-weight: 600;
        }

        .users-grid {
            display: grid;
            gap: 16px;
            grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
        }

        .user-card {
            background: white;
            border-radius: 12px;
            padding: 24px;
            text-decoration: none;
            color: inherit;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
            border: 1px solid #e2e8f0;
            transition: all 0.2s ease;
            position: relative;
            overflow: hidden;
        }

        .user-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 4px;
            height: 100%;
            background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
            transform: scaleY(0);
            transition: transform 0.2s ease;
        }

        .user-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 12px 24px rgba(0, 0, 0, 0.1);
            border-color: #6366f1;
        }

        .user-card:hover::before {
            transform: scaleY(1);
        }

        .user-name {
            font-size: 18px;
            font-weight: 600;
            color: #1e293b;
            margin-bottom: 12px;
            line-height: 1.4;
        }

        .user-details {
            display: flex;
            flex-direction: column;
            gap: 6px;
            margin-bottom: 16px;
        }

        .user-detail-row {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 14px;
            color: #64748b;
        }

        .user-detail-row strong {
            color: #475569;
            font-weight: 500;
            min-width: 70px;
        }

        .user-detail-value {
            background: #f1f5f9;
            padding: 4px 8px;
            border-radius: 6px;
            font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, 'Courier New', monospace;
            font-size: 13px;
            color: #475569;
        }

        .user-roles {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }

        .role-tag {
            display: inline-flex;
            align-items: center;
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
            color: white;
            padding: 4px 12px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 500;
            letter-spacing: 0.5px;
            text-transform: uppercase;
        }

        .role-tag:nth-child(2n) {
            background: linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%);
        }

        .role-tag:nth-child(3n) {
            background: linear-gradient(135deg, #06b6d4 0%, #0891b2 100%);
        }

        .user-icon {
            position: absolute;
            top: 20px;
            right: 20px;
            width: 24px;
            height: 24px;
            background: #6366f1;
            mask-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 24 24' stroke='currentColor'%3E%3Cpath stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z' /%3E%3C/svg%3E");
            mask-repeat: no-repeat;
            mask-position: center;
            mask-size: contain;
            opacity: 0.3;
            transition: opacity 0.2s ease;
        }

        .user-card:hover .user-icon {
            opacity: 0.6;
        }

        .empty-state {
            background: white;
            border-radius: 16px;
            padding: 60px 40px;
            text-align: center;
            box-shadow: 0 25px 50px rgba(0, 0, 0, 0.15);
            border: 1px solid #e2e8f0;
        }

        .empty-icon {
            width: 64px;
            height: 64px;
            background: #e2e8f0;
            mask-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 24 24' stroke='currentColor'%3E%3Cpath stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z' /%3E%3C/svg%3E");
            mask-repeat: no-repeat;
            mask-position: center;
            mask-size: contain;
            margin: 0 auto 20px;
        }

        .empty-title {
            font-size: 20px;
            font-weight: 600;
            color: #1e293b;
            margin-bottom: 8px;
        }

        .empty-description {
            font-size: 16px;
            color: #64748b;
        }

        @media (max-width: 768px) {
            body {
                padding: 15px;
            }

            .header {
                padding: 30px 20px;
            }

            .header h1 {
                font-size: 28px;
            }

            .users-grid {
                grid-template-columns: 1fr;
                gap: 16px;
            }

            .user-card {
                padding: 20px;
            }

            .context-info {
                padding: 20px;
            }

            .warning {
                padding: 16px;
                flex-direction: column;
                text-align: center;
            }

            .empty-state {
                padding: 40px 20px;
            }
        }

        @media (max-width: 480px) {
            .header h1 {
                font-size: 24px;
            }

            .user-name {
                font-size: 16px;
            }

            .user-detail-row {
                flex-direction: column;
                align-items: flex-start;
                gap: 4px;
            }

            .back-link {
                padding: 10px 16px;
                font-size: 13px;
            }
        }

        /* Focus accessibility */
        .user-card:focus,
        .back-link:focus {
            outline: 2px solid #6366f1;
            outline-offset: 2px;
        }

        /* Dark mode support */
        @media (prefers-color-scheme: dark) {
            .header,
            .context-info,
            .user-card,
            .empty-state,
            .back-link {
                background: #1e293b;
                border-color: #374151;
            }

            .header h1,
            .course-title,
            .user-name,
            .empty-title {
                color: #f1f5f9;
            }

            .user-count,
            .user-detail-row,
            .empty-description {
                color: #94a3b8;
            }

            .user-detail-row strong {
                color: #cbd5e1;
            }

            .user-detail-value {
                background: #374151;
                color: #e2e8f0;
            }

            .empty-icon {
                background: #374151;
            }

            .back-link {
                color: #a5b4fc;
            }

            .back-link:hover {
                background: #334155;
            }
        }

        @media (prefers-reduced-motion: reduce) {
            *, *::before, *::after {
                animation-duration: 0.01ms !important;
                animation-iteration-count: 1 !important;
                transition-duration: 0.01ms !important;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>File Browser</h1>
        </div>
        
        {% if not (base_url and token) %}
        <div class="warning">
            <div class="warning-icon"></div>
            <div class="warning-content">
                <strong>Configuration Required:</strong> Moodle configuration incomplete. Please set MOODLE_URL and MOODLE_API_TOKEN environment variables.
            </div>
        </div>
        {% endif %}
        
        {% if selected_course %}
        <div class="navigation">
            <a href="{{ url_for('files.file_browser', ltik=ltik) }}" class="back-link">
                <span class="back-arrow">←</span>
                Back to course selection
            </a>
        </div>
        {% endif %}
        
        <div class="context-info">
            {% if context_title %}
            <div class="course-title">Course: {{ context_title }}</div>
            {% endif %}
            <div class="user-count">Select a user to view their files • Showing <strong>{{ users|length }}</strong> enrolled users</div>
        </div>
        
        {% if users %}
        <div class="users-grid">
            {% for u in users %}
            <a href="{{ url_for('files.file_browser', user_id=u.id, course_id=selected_course, ltik=ltik) }}" class="user-card">
                <div class="user-icon"></div>
                <div class="user-name">{{ u.fullname or ('User ' ~ u.id) }}</div>
                <div class="user-details">
                    <div class="user-detail-row">
                        <strong>Username:</strong>
                        <span class="user-detail-value">{{ u.username }}</span>
                    </div>
                    <div class="user-detail-row">
                        <strong>Email:</strong>
                        <span class="user-detail-value">{{ u.email }}</span>
                    </div>
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
        </div>
        {% else %}
        <div class="empty-state">
            <div class="empty-icon"></div>
            <div class="empty-title">No users found</div>
            <div class="empty-description">There are currently no enrolled users in this course.</div>
        </div>
        {% endif %}
    </div>
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

        upload_dir = current_app.config.get("UPLOAD_FOLDER", "/tmp/lti_files")
        uploaded = None
        if request.method == "POST":
            selected = request.form.getlist("files")
            os.makedirs(upload_dir, exist_ok=True)
            uploaded = 0
            for url in selected:
                try:
                    resp = requests.get(url, timeout=10)
                    resp.raise_for_status()
                    filename = url.rsplit("/", 1)[-1].split("?")[0]
                    with open(os.path.join(upload_dir, filename), "wb") as handle:
                        handle.write(resp.content)
                    uploaded += 1
                except Exception as err:  # pragma: no cover - network errors
                    current_app.logger.error(f"Failed to download {url}: {err}")

        uploaded_files = []
        if os.path.isdir(upload_dir):
            uploaded_files = sorted(os.listdir(upload_dir))

        back_url = url_for('files.file_browser', course_id=selected_course, ltik=ltik) if selected_course \
            else url_for('files.file_browser', ltik=ltik)

        html = """
        <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Learner Files</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #1e293b 0%, #334155 50%, #475569 100%);
            min-height: 100vh;
            padding: 20px;
            line-height: 1.6;
        }

        .container {
            max-width: 1000px;
            margin: 0 auto;
            animation: fadeIn 0.8s ease-out;
        }

        @keyframes fadeIn {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .header {
            background: white;
            border-radius: 16px;
            padding: 40px 30px;
            margin-bottom: 30px;
            box-shadow: 0 25px 50px rgba(0, 0, 0, 0.15);
            border: 1px solid #e2e8f0;
            text-align: center;
        }

        .header h1 {
            font-size: 32px;
            font-weight: 600;
            color: #1e293b;
            margin-bottom: 12px;
            letter-spacing: -0.5px;
        }

        .navigation {
            margin-bottom: 30px;
        }

        .back-link {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: white;
            color: #6366f1;
            text-decoration: none;
            padding: 12px 20px;
            border-radius: 8px;
            font-weight: 500;
            font-size: 14px;
            border: 1px solid #e2e8f0;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
            transition: all 0.2s ease;
        }

        .back-link:hover {
            background: #f8fafc;
            transform: translateX(-2px);
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        }

        .back-arrow {
            font-size: 16px;
        }

        .info-box {
            background: linear-gradient(135deg, #dbeafe 0%, #bfdbfe 100%);
            border: 1px solid #3b82f6;
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 30px;
            border-left: 4px solid #3b82f6;
        }

        .info-title {
            font-size: 16px;
            font-weight: 600;
            color: #1e40af;
            margin-bottom: 12px;
        }

        .info-sources {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 12px;
        }

        .source-item {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 14px;
            color: #1e40af;
        }

        .source-status {
            width: 16px;
            height: 16px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 10px;
            font-weight: bold;
            color: white;
        }

        .source-status.enabled {
            background: #10b981;
        }

        .source-status.disabled {
            background: #ef4444;
        }

        .file-section {
            background: white;
            border-radius: 16px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
            border: 1px solid #e2e8f0;
        }

        .section-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 24px;
            padding-bottom: 16px;
            border-bottom: 2px solid #f1f5f9;
        }

        .section-title {
            font-size: 24px;
            font-weight: 600;
            color: #1e293b;
        }

        .file-count {
            background: #6366f1;
            color: white;
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 14px;
            font-weight: 500;
        }

        .upload-status {
            background: #ecfdf5;
            border: 1px solid #10b981;
            color: #065f46;
            padding: 12px 16px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-weight: 500;
        }

        .no-files {
            text-align: center;
            padding: 40px 20px;
            color: #64748b;
            font-size: 16px;
        }

        .no-files-icon {
            width: 48px;
            height: 48px;
            background: #e2e8f0;
            mask-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 24 24' stroke='currentColor'%3E%3Cpath stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z' /%3E%3C/svg%3E");
            mask-repeat: no-repeat;
            mask-position: center;
            mask-size: contain;
            margin: 0 auto 16px;
        }

        .files-form {
            display: flex;
            flex-direction: column;
            gap: 16px;
        }

        .file-item {
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 12px;
            padding: 20px;
            transition: all 0.2s ease;
            position: relative;
        }

        .file-item:hover {
            background: #f1f5f9;
            border-color: #6366f1;
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
        }

        .file-item input[type="checkbox"] {
            appearance: none;
            width: 20px;
            height: 20px;
            border: 2px solid #d1d5db;
            border-radius: 4px;
            background: white;
            cursor: pointer;
            position: relative;
            transition: all 0.2s ease;
            flex-shrink: 0;
        }

        .file-item input[type="checkbox"]:checked {
            background: #6366f1;
            border-color: #6366f1;
        }

        .file-item input[type="checkbox"]:checked::after {
            content: '✓';
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            color: white;
            font-size: 12px;
            font-weight: bold;
        }

        .file-content {
            display: flex;
            align-items: flex-start;
            gap: 16px;
        }

        .file-info {
            flex: 1;
        }

        .file-name {
            font-size: 16px;
            font-weight: 600;
            color: #1e293b;
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .file-link {
            color: #6366f1;
            text-decoration: none;
            font-weight: 500;
            font-size: 14px;
            padding: 4px 8px;
            border-radius: 6px;
            border: 1px solid #6366f1;
            transition: all 0.2s ease;
        }

        .file-link:hover {
            background: #6366f1;
            color: white;
        }

        .file-details {
            display: flex;
            gap: 16px;
            font-size: 13px;
            color: #64748b;
            margin-top: 8px;
        }

        .file-detail {
            display: flex;
            align-items: center;
            gap: 4px;
        }

        .file-detail strong {
            color: #475569;
            font-weight: 500;
        }

        .submit-button {
            background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
            color: white;
            border: none;
            padding: 16px 32px;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            align-self: flex-start;
            margin-top: 20px;
        }

        .submit-button:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(99, 102, 241, 0.4);
        }

        .submit-button:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }

        .uploaded-list {
            list-style: none;
            display: flex;
            flex-direction: column;
            gap: 12px;
        }

        .uploaded-item {
            background: #f0fdf4;
            border: 1px solid #bbf7d0;
            padding: 16px;
            border-radius: 8px;
            display: flex;
            align-items: center;
            gap: 12px;
            color: #065f46;
        }

        .uploaded-icon {
            width: 20px;
            height: 20px;
            background: #10b981;
            mask-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 24 24' stroke='currentColor'%3E%3Cpath stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z' /%3E%3C/svg%3E");
            mask-repeat: no-repeat;
            mask-position: center;
            mask-size: contain;
            flex-shrink: 0;
        }

        @media (max-width: 768px) {
            body {
                padding: 15px;
            }

            .header {
                padding: 30px 20px;
            }

            .header h1 {
                font-size: 28px;
            }

            .file-section {
                padding: 24px 20px;
            }

            .section-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 12px;
            }

            .file-content {
                flex-direction: column;
                gap: 12px;
            }

            .file-details {
                flex-direction: column;
                gap: 8px;
            }

            .info-sources {
                grid-template-columns: 1fr;
                gap: 8px;
            }
        }

        @media (max-width: 480px) {
            .header h1 {
                font-size: 24px;
            }

            .file-name {
                flex-direction: column;
                align-items: flex-start;
                gap: 8px;
            }

            .submit-button {
                width: 100%;
                padding: 14px;
            }
        }

        /* Focus accessibility */
        .file-item input[type="checkbox"]:focus,
        .submit-button:focus,
        .back-link:focus,
        .file-link:focus {
            outline: 2px solid #6366f1;
            outline-offset: 2px;
        }

        /* Dark mode support */
        @media (prefers-color-scheme: dark) {
            .header,
            .file-section,
            .back-link {
                background: #1e293b;
                border-color: #374151;
            }

            .header h1,
            .section-title,
            .file-name {
                color: #f1f5f9;
            }

            .file-item {
                background: #334155;
                border-color: #475569;
            }

            .file-item:hover {
                background: #475569;
                border-color: #a5b4fc;
            }

            .file-details,
            .no-files {
                color: #94a3b8;
            }

            .file-detail strong {
                color: #cbd5e1;
            }

            .back-link {
                color: #a5b4fc;
            }

            .back-link:hover {
                background: #334155;
            }
        }

        @media (prefers-reduced-motion: reduce) {
            *, *::before, *::after {
                animation-duration: 0.01ms !important;
                animation-iteration-count: 1 !important;
                transition-duration: 0.01ms !important;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Learner {{ selected_user }} Files</h1>
        </div>
        
        <div class="navigation">
            <a href="{{ back_url }}" class="back-link">
                <span class="back-arrow">←</span>
                Back to user list
            </a>
        </div>

        <div class="info-box">
            <div class="info-title">File Sources Configuration</div>
            <div class="info-sources">
                <div class="source-item">
                    <div class="source-status {{ 'enabled' if FILE_SOURCE_CONFIG.get('assignments') else 'disabled' }}">
                        {{ "✓" if FILE_SOURCE_CONFIG.get("assignments") else "✗" }}
                    </div>
                    <span>Assignments</span>
                </div>
                <div class="source-item">
                    <div class="source-status {{ 'enabled' if FILE_SOURCE_CONFIG.get('course_modules') else 'disabled' }}">
                        {{ "✓" if FILE_SOURCE_CONFIG.get("course_modules") else "✗" }}
                    </div>
                    <span>Course Modules</span>
                </div>
                <div class="source-item">
                    <div class="source-status {{ 'enabled' if FILE_SOURCE_CONFIG.get('forums') else 'disabled' }}">
                        {{ "✓" if FILE_SOURCE_CONFIG.get("forums") else "✗" }}
                    </div>
                    <span>Forums</span>
                </div>
                <div class="source-item">
                    <div class="source-status {{ 'enabled' if FILE_SOURCE_CONFIG.get('workshops') else 'disabled' }}">
                        {{ "✓" if FILE_SOURCE_CONFIG.get("workshops") else "✗" }}
                    </div>
                    <span>Workshops</span>
                </div>
            </div>
        </div>

        <div class="file-section">
            <div class="section-header">
                <h2 class="section-title">Course Files</h2>
                <div class="file-count">{{ moodle_files|length }}</div>
            </div>
            
            {% if uploaded is not none %}
            <div class="upload-status">
                {{ uploaded }} file(s) uploaded successfully.
            </div>
            {% endif %}
            
            {% if not moodle_files %}
            <div class="no-files">
                <div class="no-files-icon"></div>
                No Moodle files found for this user.
            </div>
            {% else %}
            <form method="post" action="{{ url_for('files.file_browser', user_id=selected_user, course_id=course_id, ltik=ltik) }}" class="files-form">
                {% for f in moodle_files %}
                <div class="file-item">
                    <div class="file-content">
                        <input type="checkbox" name="files" value="{{ f.fileurl }}?token={{ token }}" />
                        <div class="file-info">
                            <div class="file-name">
                                <strong>{{ f.filename or 'Unnamed file' }}</strong>
                                {% if f.fileurl %}
                                <a href="{{ f.fileurl }}?token={{ token }}" target="_blank" rel="noopener" class="file-link">Open</a>
                                {% endif %}
                            </div>
                            <div class="file-details">
                                <div class="file-detail">
                                    <strong>Size:</strong> {{ f.filesize or 'Unknown' }} bytes
                                </div>
                                <div class="file-detail">
                                    <strong>Source:</strong> {{ f.source or 'Unknown' }}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                {% endfor %}
                <button type="submit" class="submit-button">Upload Selected Files</button>
            </form>
            {% endif %}
        </div>

        <div class="file-section">
            <div class="section-header">
                <h2 class="section-title">Uploaded to SV Service</h2>
                <div class="file-count">{{ uploaded_files|length }}</div>
            </div>
            
            {% if not uploaded_files %}
            <div class="no-files">
                <div class="no-files-icon"></div>
                No files uploaded to SV Storage.
            </div>
            {% else %}
            <ul class="uploaded-list">
                {% for name in uploaded_files %}
                <li class="uploaded-item">
                    <div class="uploaded-icon"></div>
                    {{ name }}
                </li>
                {% endfor %}
            </ul>
            {% endif %}
        </div>
    </div>
</body>
</html>
        """
        return render_template_string(
            html,
            selected_user=selected_user,
            moodle_files=moodle_files,
            local_files=local_files,
            uploaded_files=uploaded_files,
            ltik=ltik,
            token=token,
            back_url=back_url,
            course_id=course_id,
            uploaded=uploaded,
            FILE_SOURCE_CONFIG=FILE_SOURCE_CONFIG
        )

    # Non-admin: show own local uploads (student view)
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

        <form action="{{ url_for('files.upload_files', ltik=ltik) }}" method="post" enctype="multipart/form-data">
            <input type="hidden" name="ltik" value="{{ ltik }}"/>
            <input type="file" name="file"/>
            <button type="submit">Upload</button>
        </form>
    </body>
    </html>
    """
    return render_template_string(html, files=files, ltik=ltik)
