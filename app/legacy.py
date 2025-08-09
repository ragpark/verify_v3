"""Blueprint providing original legacy endpoints and UI."""
from __future__ import annotations

import os
from datetime import datetime

from flask import Blueprint, current_app, jsonify, render_template

bp = Blueprint("legacy", __name__)


def _get_upload_folder() -> str:
    """Return the configured upload folder, creating it if missing."""
    folder = current_app.config.get("UPLOAD_FOLDER", "/tmp/lti_files")
    os.makedirs(folder, exist_ok=True)
    return folder


@bp.route("/")
def index() -> tuple[dict, int] | tuple[str, int] | dict:
    """Return basic information about the running tool."""
    routes = [str(rule) for rule in current_app.url_map.iter_rules()]
    payload = {
        "message": "LTI Tool Server - Enhanced Debugging Version",
        "status": "running",
        "timestamp": datetime.utcnow().isoformat(),
        "endpoints": {
            "get_user_files": "/get_user_files/<user_id>",
            "copy_files": "/copy_moodle_files",
            "upload_files": "/upload_files",
            "download_file": "/download_file/<file_id>",
            "delete_file": "/delete_file/<file_id>",
            "list_uploaded_files": "/list_uploaded_files",
            "files_ui": "/files",
            "lti_launch": "/launch",
            "test_session": "/test_session",
            "debug_routes": "/debug_routes",
        },
        "total_routes": len(routes),
        "routes": routes,
    }
    return jsonify(payload)


@bp.route("/list_uploaded_files")
def list_uploaded_files():
    """Return a JSON list of files stored in the upload folder."""
    upload_folder = _get_upload_folder()
    files = []
    for name in sorted(os.listdir(upload_folder)):
        path = os.path.join(upload_folder, name)
        if os.path.isfile(path):
            stat = os.stat(path)
            files.append(
                {
                    "name": name,
                    "size": stat.st_size,
                    "uploaded_at": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                }
            )
    return jsonify({"files": files, "count": len(files)})


@bp.route("/files")
def files_ui():
    """Render a simple HTML page listing uploaded files."""
    upload_folder = _get_upload_folder()
    files = []
    for name in sorted(os.listdir(upload_folder)):
        path = os.path.join(upload_folder, name)
        if os.path.isfile(path):
            stat = os.stat(path)
            files.append(
                {
                    "name": name,
                    "size": stat.st_size,
                    "uploaded_at": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                }
            )
    return render_template("files.html", files=files)


@bp.route("/health")
def health():
    """Simple health check endpoint."""
    return jsonify({"status": "ok", "timestamp": datetime.utcnow().isoformat()})


@bp.route("/debug_routes")
def debug_routes():
    """List all registered routes for debugging purposes."""
    routes = [str(rule) for rule in current_app.url_map.iter_rules()]
    return jsonify({"routes": routes})
