"""
Flask extensions for the Certificate Transparency service.

Provides centralized initialization of Flask extensions including
database, rate limiting, and other security components.
"""

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Global extension instances
db = SQLAlchemy()
migrate = Migrate()
limiter = Limiter(key_func=get_remote_address)

def init_extensions(app: Flask):
    """
    Initialize Flask extensions with the application instance.

    Args:
        app: Flask application instance
    """
    # Initialize database and migrations
    db.init_app(app)
    migrate.init_app(app, db)

    # Initialize rate limiting with Redis backend
    limiter.init_app(app)