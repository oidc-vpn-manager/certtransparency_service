"""
Health check endpoints for the Certificate Transparency Service.

Provides endpoints for monitoring service health and readiness.
"""

from flask import Blueprint, jsonify
from sqlalchemy import text

from app import db

health_bp = Blueprint('health', __name__)


@health_bp.route('/health')
def health_check():
    """
    Basic health check endpoint.
    
    Returns:
        JSON response indicating service health status
    """
    try:
        # Test database connection
        db.session.execute(text('SELECT 1'))
        
        return jsonify({
            'status': 'healthy',
            'service': 'certificate-transparency',
            'version': '1.0.0',
            'database': 'connected'
        }), 200
        
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'service': 'certificate-transparency',
            'version': '1.0.0',
            'database': 'disconnected',
            'error': str(e)
        }), 503


@health_bp.route('/ready')
def readiness_check():
    """
    Readiness check endpoint for Kubernetes.
    
    Returns:
        JSON response indicating if service is ready to accept traffic
    """
    try:
        # Test database connectivity and basic functionality
        db.session.execute(text('SELECT COUNT(*) FROM certificate_logs LIMIT 1'))
        
        return jsonify({
            'status': 'ready',
            'service': 'certificate-transparency',
            'database': 'ready'
        }), 200
        
    except Exception as e:
        return jsonify({
            'status': 'not_ready',
            'service': 'certificate-transparency',
            'database': 'not_ready',
            'error': str(e)
        }), 503


@health_bp.route('/live')
def liveness_check():
    """
    Liveness check endpoint for Kubernetes.
    
    Returns:
        JSON response indicating if service is alive
    """
    return jsonify({
        'status': 'alive',
        'service': 'certificate-transparency'
    }), 200