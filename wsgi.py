"""
WSGI entry point for the Certificate Transparency Service.

This module provides the WSGI application instance for deployment
with WSGI servers like Gunicorn.
"""

from app import create_app

# Create the application instance
application = create_app()

if __name__ == '__main__':
    application.run(debug=True, host='0.0.0.0', port=8800)