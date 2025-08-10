from flask import Flask, request, current_app
from flask_sqlalchemy import SQLAlchemy
from werkzeug.middleware.proxy_fix import ProxyFix
import os

from .config import Config

# SQLAlchemy instance
db = SQLAlchemy()


def create_app(config_class: type[Config] = Config) -> Flask:
    """Application factory for the LTI tool."""
    app = Flask(__name__, template_folder="../templates")
    app.config.from_object(config_class)

    # Trust Railway's reverse proxy so Flask sees https/host/port correctly
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

    # Ensure url_for(..., _external=True) prefers HTTPS and cookies are secure (LTI cross-site)
    app.config.setdefault("PREFERRED_URL_SCHEME", "https")
    app.config.setdefault("SESSION_COOKIE_SECURE", True)
    app.config.setdefault("REMEMBER_COOKIE_SECURE", True)
    app.config.setdefault("SESSION_COOKIE_SAMESITE", "None")

    # --- LTI request/response logging (helps spot redirects, missing form data) ---
    @app.before_request
    def _log_incoming():
        if request.path.startswith("/lti/"):
            current_app.logger.info(
                "IN %s %s ct=%s qs=%s form_keys=%s",
                request.method,
                request.url,
                request.headers.get("Content-Type"),
                dict(request.args),
                list(request.form.keys()),
            )

    @app.after_request
    def _log_outgoing(resp):
        if request.path.startswith("/lti/"):
            loc = resp.headers.get("Location")
            current_app.logger.info(
                "OUT %s %s -> %s%s",
                request.method,
                request.path,
                resp.status,
                f" loc={loc}" if 300 <= resp.status_code < 400 and loc else "",
            )
        return resp
    # ------------------------------------------------------------------------------

    db.init_app(app)

    from .lti.registration import bp as registration_bp
    from .lti.jwks import bp as jwks_bp
    from .lti.launch import bp as launch_bp
    from .legacy import bp as legacy_bp
    from .files import files_bp

    app.register_blueprint(registration_bp)
    app.register_blueprint(jwks_bp)
    app.register_blueprint(launch_bp)
    app.register_blueprint(legacy_bp)
    app.register_blueprint(files_bp, url_prefix="/files")

    # Ensure upload directory exists
    upload_dir = os.getenv("UPLOAD_FOLDER", "/tmp/lti_files")
    os.makedirs(upload_dir, exist_ok=True)

    # Useful once at startup to confirm routes/methods (look for /lti/* with POST)
    app.logger.info("URL MAP: %s", app.url_map)

    return app
