"""WSGI entry point for Railway deployment."""
from app import create_app

# Expose application instance for WSGI servers
app = create_app()
