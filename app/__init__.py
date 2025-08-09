from flask import Flask
from flask_sqlalchemy import SQLAlchemy

from .config import Config

# SQLAlchemy instance

db = SQLAlchemy()


def create_app(config_class: type[Config] = Config) -> Flask:
    """Application factory for the LTI tool."""
    app = Flask(__name__, template_folder="../templates")
    app.config.from_object(config_class)

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
