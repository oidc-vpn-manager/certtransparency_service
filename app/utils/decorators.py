"""
Authentication decorators for the Certificate Transparency service.

Provides decorators for API endpoint authentication and authorization.
"""

from functools import wraps
from flask import request, jsonify, current_app


def api_secret_required(f):
    """
    Decorator to require API secret authentication for CT service endpoints.
    
    Expects the API secret to be provided in the X-CT-API-Secret header.
    This is used to authenticate requests from the signing service.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get the API secret from the request headers
        provided_secret = request.headers.get('X-CT-API-Secret')
        
        if not provided_secret:
            return jsonify({
                'error': 'Missing X-CT-API-Secret header'
            }), 401
        
        # Get the expected API secret from configuration
        expected_secret = current_app.config.get('CT_SERVICE_API_SECRET')
        
        if not expected_secret:
            current_app.logger.error(
                "CT_SERVICE_API_SECRET not configured - cannot authenticate requests"
            )
            return jsonify({
                'error': 'Authentication service not configured'
            }), 500
        
        # Verify the provided secret matches the expected secret using constant-time comparison
        import hmac
        if not hmac.compare_digest(provided_secret.encode('utf-8'), expected_secret.encode('utf-8')):
            current_app.logger.warning(
                f"API authentication failed - invalid secret provided from {request.remote_addr}"
            )
            return jsonify({
                'error': 'Invalid API secret'
            }), 403
        
        current_app.logger.debug(
            f"API authentication successful for request from {request.remote_addr}"
        )
        return f(*args, **kwargs)
    
    return decorated_function