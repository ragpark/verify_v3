from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from werkzeug.middleware.proxy_fix import ProxyFix  # NEW

from .config import Config

# SQLAlchemy instance
db = SQLAlchemy()


def create_app(config_class: type[Config] = Config) -> Flask:
    """Application factory for the LTI tool."""
    app = Flask(__name__, template_folder="../templates")
    app.config.from_object(config_class)

    # Trust Railway's reverse proxy so Flask sees https/host/port correctly
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

    # Ensure url_for(..., _external=True) prefers HTTPS and cookies are secure
    app.config.setdefault("PREFERRED_URL_SCHEME", "https")
    app.config.setdefault("SESSION_COOKIE_SECURE", True)
    app.config.setdefault("REMEMBER_COOKIE_SECURE", True)
    app.config.setdefault("SESSION_COOKIE_SAMESITE", "Lax")

    db.init_app(app)

    from .lti.registration import bp as registration_bp
    from .lti.jwks import bp as jwks_bp
    from .lti.launch import bp as launch_bp
    from .legacy import bp as legacy_bp

    app.register_blueprint(registration_bp)
    app.register_blueprint(jwks_bp)
    app.register_blueprint(launch_bp)
    app.register_blueprint(legacy_bp)

    return app
