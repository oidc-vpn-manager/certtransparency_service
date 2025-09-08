"""
Unit tests for Certificate Transparency Service health check routes.
"""

import pytest
import json
from unittest.mock import patch


class TestHealthRoutes:
    """Test health check endpoints."""
    
    def test_health_check_success(self, client):
        """Test successful health check."""
        response = client.get('/health')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['status'] == 'healthy'
        assert data['service'] == 'certificate-transparency'
        assert data['version'] == '1.0.0'
        assert data['database'] == 'connected'
    
    def test_health_check_database_failure(self, client):
        """Test health check with database connection failure - lines 34-35."""
        with patch('app.routes.health.db') as mock_db:
            mock_db.session.execute.side_effect = Exception('Database connection error')
            
            response = client.get('/health')
            assert response.status_code == 503
            
            data = json.loads(response.data)
            assert data['status'] == 'unhealthy'
            assert data['service'] == 'certificate-transparency'
            assert data['version'] == '1.0.0'
            assert data['database'] == 'disconnected'
            assert 'error' in data
    
    def test_readiness_check_success(self, client):
        """Test successful readiness check."""
        response = client.get('/ready')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['status'] == 'ready'
        assert data['service'] == 'certificate-transparency'
        assert data['database'] == 'ready'
    
    def test_readiness_check_database_failure(self, client):
        """Test readiness check with database query failure - lines 62-63."""
        with patch('app.routes.health.db') as mock_db:
            mock_db.session.execute.side_effect = Exception('Database query error')
            
            response = client.get('/ready')
            assert response.status_code == 503
            
            data = json.loads(response.data)
            assert data['status'] == 'not_ready'
            assert data['service'] == 'certificate-transparency'
            assert data['database'] == 'not_ready'
            assert 'error' in data
    
    def test_liveness_check_success(self, client):
        """Test successful liveness check."""
        response = client.get('/live')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['status'] == 'alive'
        assert data['service'] == 'certificate-transparency'