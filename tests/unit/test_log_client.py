"""
Tests for CT Service log client utilities.
"""

import pytest
from unittest.mock import Mock, patch
import requests

from app.utils.log_client import CTLogClient, log_certificate_to_ct


class TestCTLogClient:
    """Tests for the CTLogClient class."""
    
    def test_init(self):
        """Test CTLogClient initialization."""
        client = CTLogClient("http://example.com/", timeout=60)
        assert client.ct_service_url == "http://example.com"
        assert client.timeout == 60
        assert isinstance(client.session, requests.Session)
    
    def test_init_strips_trailing_slash(self):
        """Test that trailing slash is stripped from URL."""
        client = CTLogClient("http://example.com/ct/")
        assert client.ct_service_url == "http://example.com/ct"
    
    def test_log_certificate_basic(self):
        """Test basic certificate logging."""
        client = CTLogClient("http://certtransparency-service:8003")
        
        result = client.log_certificate(
            certificate_pem="-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
            certificate_type="client"
        )
        
        assert result is not None
        assert result['status'] == 'logged'
        assert result['certificate_type'] == 'client'
        assert 'timestamp' in result
    
    def test_log_certificate_with_optional_params(self):
        """Test certificate logging with optional parameters."""
        client = CTLogClient("http://certtransparency-service:8003")
        
        result = client.log_certificate(
            certificate_pem="-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
            certificate_type="server",
            certificate_purpose="test-server",
            request_source="frontend_service",
            issued_by_service="signing_service"
        )
        
        assert result is not None
        assert result['status'] == 'logged'
        assert result['certificate_type'] == 'server'
    
    def test_log_certificate_exception_handling(self):
        """Test exception handling in log_certificate."""
        client = CTLogClient("http://certtransparency-service:8003")
        
        # Patch logger to cause an exception during logging
        with patch('app.utils.log_client.logger') as mock_logger:
            mock_logger.info.side_effect = Exception("Test exception")
            
            result = client.log_certificate(
                certificate_pem="test-cert",
                certificate_type="client"
            )
            
            assert result is None
            mock_logger.error.assert_called_once()
    
    def test_health_check_success(self):
        """Test successful health check."""
        client = CTLogClient("http://certtransparency-service:8003")
        
        mock_response = Mock()
        mock_response.status_code = 200
        
        with patch.object(client.session, 'get', return_value=mock_response) as mock_get:
            result = client.health_check()
            
            assert result is True
            mock_get.assert_called_once_with(
                "http://certtransparency-service:8003/health",
                timeout=30
            )
    
    def test_health_check_failure_status_code(self):
        """Test health check with non-200 status code."""
        client = CTLogClient("http://certtransparency-service:8003")
        
        mock_response = Mock()
        mock_response.status_code = 500
        
        with patch.object(client.session, 'get', return_value=mock_response):
            result = client.health_check()
            
            assert result is False
    
    def test_health_check_exception(self):
        """Test health check with request exception."""
        client = CTLogClient("http://certtransparency-service:8003")
        
        with patch.object(client.session, 'get', side_effect=requests.ConnectionError("Connection failed")):
            with patch('app.utils.log_client.logger') as mock_logger:
                result = client.health_check()
                
                assert result is False
                mock_logger.error.assert_called_once()
    
    def test_health_check_timeout(self):
        """Test health check with timeout."""
        client = CTLogClient("http://certtransparency-service:8003", timeout=5)
        
        with patch.object(client.session, 'get', side_effect=requests.Timeout("Request timeout")):
            with patch('app.utils.log_client.logger') as mock_logger:
                result = client.health_check()
                
                assert result is False
                mock_logger.error.assert_called_once()


class TestLogCertificateToCT:
    """Tests for the convenience function log_certificate_to_ct."""
    
    def test_log_certificate_to_ct_success(self):
        """Test successful certificate logging via convenience function."""
        with patch('app.utils.log_client.CTLogClient') as mock_client_class:
            mock_client = Mock()
            mock_client.log_certificate.return_value = {'status': 'logged'}
            mock_client_class.return_value = mock_client
            
            result = log_certificate_to_ct(
                certificate_pem="test-cert",
                certificate_type="client",
                ct_service_url="http://custom-ct:8003",
                certificate_purpose="test-purpose"
            )
            
            assert result is True
            mock_client_class.assert_called_once_with("http://custom-ct:8003")
            mock_client.log_certificate.assert_called_once_with(
                "test-cert",
                "client",
                certificate_purpose="test-purpose"
            )
    
    def test_log_certificate_to_ct_failure(self):
        """Test failed certificate logging via convenience function."""
        with patch('app.utils.log_client.CTLogClient') as mock_client_class:
            mock_client = Mock()
            mock_client.log_certificate.return_value = None
            mock_client_class.return_value = mock_client
            
            result = log_certificate_to_ct(
                certificate_pem="test-cert",
                certificate_type="client"
            )
            
            assert result is False
    
    def test_log_certificate_to_ct_default_url(self):
        """Test convenience function with default CT service URL."""
        with patch('app.utils.log_client.CTLogClient') as mock_client_class:
            mock_client = Mock()
            mock_client.log_certificate.return_value = {'status': 'logged'}
            mock_client_class.return_value = mock_client
            
            result = log_certificate_to_ct(
                certificate_pem="test-cert",
                certificate_type="server"
            )
            
            assert result is True
            mock_client_class.assert_called_once_with("http://certtransparency_service:8003")