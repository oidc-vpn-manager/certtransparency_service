"""
Flask application factory for the Certificate Transparency Service.

This service provides unauthenticated access to certificate transparency logs
for compliance and audit purposes. It allows internal systems and auditors
to view all certificates issued by the OIDC VPN Manager without authentication.
"""

import logging
import os
from flask import Flask, send_from_directory
from flask_swagger_ui import get_swaggerui_blueprint

from .config import get_config

SWAGGER_URL = '/api'
API_URL = '/swagger.yaml'

swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': "OIDC VPN Manager Certificate Transparency API"
    }
)


def create_app(config_class=None):
    """
    Application factory function for creating Flask app instances.
    
    Args:
        config_class: Configuration class to use. If None, determined from environment.
        
    Returns:
        Flask: Configured Flask application instance
    """
    app = Flask(__name__)
    
    # Configure the application
    if config_class is None:
        config_class = get_config()
    if hasattr(config_class, '__call__'):
        # Config class - instantiate it
        config_instance = config_class()
        for key, value in config_instance.__dict__.items():
            if not key.startswith('_'):
                app.config[key] = value
    else:
        # Config instance
        for key, value in config_class.__dict__.items():
            if not key.startswith('_'):
                app.config[key] = value
    
    # Initialize extensions
    from .extensions import init_extensions
    init_extensions(app)
    
    # Register blueprints
    from app.routes.api import api_bp
    app.register_blueprint(api_bp, url_prefix='/api/v1')
    
    from app.routes.health import health_bp
    app.register_blueprint(health_bp)

    app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

    @app.route(API_URL)
    def swagger_spec():
        return send_from_directory(os.path.dirname(os.path.abspath(__file__)), 'swagger.yaml')
    
    # Configure structured security logging
    from app.utils.logging_config import configure_security_logging
    configure_security_logging(app)
    
    return app