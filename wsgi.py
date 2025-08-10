"""WSGI entry point for Railway deployment."""
from sqlalchemy import inspect

from app import create_app, db

# Expose application instance for WSGI servers
app = create_app()

# Verify critical tables exist so migrations aren't skipped
with app.app_context():
    inspector = inspect(db.engine)
    if not inspector.has_table("states"):
        app.logger.error(
            "Required table 'states' not found. Run database migrations before starting."
        )
