"""Application configuration."""
from __future__ import annotations

import os
from datetime import timedelta


class Config:
    """Base configuration loaded from environment variables."""

    # Database configuration - default to in-memory SQLite for tests
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///:memory:")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret")

    APP_BASE_URL = os.environ.get("APP_BASE_URL", "https://localhost")
    TOOL_TITLE = os.environ.get("TOOL_TITLE", "Verify")
    TOOL_DESCRIPTION = os.environ.get("TOOL_DESCRIPTION", "LTI Tool")
    TOOL_CONTACT_EMAIL = os.environ.get("TOOL_CONTACT_EMAIL", "support@example.com")
    DEEP_LINK_RETURN_URL = os.environ.get(
        "DEEP_LINK_RETURN_URL", f"{APP_BASE_URL}/lti/deep_link/return"
    )

    UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", "/tmp/lti_files")
    MAX_FILE_SIZE = int(os.environ.get("MAX_FILE_SIZE", 16_777_216))
    MOODLE_URL = os.environ.get("MOODLE_URL")
    MOODLE_API_TOKEN = os.environ.get("MOODLE_API_TOKEN")

    # Nonce/state expiry windows
    STATE_EXPIRATION = timedelta(minutes=5)
    NONCE_EXPIRATION = timedelta(minutes=5)
