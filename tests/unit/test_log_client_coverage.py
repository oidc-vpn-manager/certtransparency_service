"""
Comprehensive tests for CT Log Client module to achieve 100% coverage.
Tests all functionality including initialization, logging, health checks, and error handling.
"""

import pytest
import requests
from unittest.mock import Mock, patch, MagicMock
from app.utils.log_client import CTLogClient, log_certificate_to_ct


class TestCTLogClient:
    """Test suite for CTLogClient class."""
    
    def test_init_default_timeout(self):
        """Test CTLogClient initialization with default timeout."""
        client = CTLogClient("http://example.com")
        
        assert client.ct_service_url == "http://example.com"
        assert client.timeout == 30
        assert isinstance(client.session, requests.Session)

    def test_init_custom_timeout(self):
        """Test CTLogClient initialization with custom timeout."""
        client = CTLogClient("http://example.com", timeout=60)
        
        assert client.ct_service_url == "http://example.com"
        assert client.timeout == 60
        assert isinstance(client.session, requests.Session)

    def test_init_strips_trailing_slash(self):
        """Test that initialization strips trailing slash from URL."""
        client = CTLogClient("http://example.com/")
        
        assert client.ct_service_url == "http://example.com"

    def test_log_certificate_minimal_params(self):
        """Test certificate logging with minimal parameters."""
        client = CTLogClient("http://example.com")
        
        result = client.log_certificate(
            certificate_pem="-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
            certificate_type="client"
        )
        
        assert result is not None
        assert result['status'] == 'logged'
        assert result['certificate_type'] == 'client'
        assert 'timestamp' in result

    def test_log_certificate_full_params(self):
        """Test certificate logging with all parameters."""
        client = CTLogClient("http://example.com")
        
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
        assert 'timestamp' in result

    def test_log_certificate_optional_params(self):
        """Test certificate logging with optional parameters set to None."""
        client = CTLogClient("http://example.com")
        
        result = client.log_certificate(
            certificate_pem="-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
            certificate_type="intermediate",
            certificate_purpose=None,
            request_source=None,
            issued_by_service="custom_service"
        )
        
        assert result is not None
        assert result['status'] == 'logged'
        assert result['certificate_type'] == 'intermediate'

    @patch('app.utils.log_client.logger')
    def test_log_certificate_logs_info(self, mock_logger):
        """Test that certificate logging creates appropriate log entries."""
        client = CTLogClient("http://example.com")
        
        client.log_certificate(
            certificate_pem="-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
            certificate_type="client",
            certificate_purpose="test-purpose",
            request_source="test-source"
        )
        
        # Check that info log was called with expected message
        mock_logger.info.assert_called_once()
        log_call = mock_logger.info.call_args[0][0]
        assert "Certificate logged to CT" in log_call
        assert "type=client" in log_call
        assert "purpose=test-purpose" in log_call
        assert "source=test-source" in log_call

    @patch('app.utils.log_client.logger')
    def test_log_certificate_exception_handling(self, mock_logger):
        """Test certificate logging exception handling."""
        client = CTLogClient("http://example.com")
        
        # Mock logger.info to raise an exception
        mock_logger.info.side_effect = Exception("Test exception")
        
        result = client.log_certificate(
            certificate_pem="-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
            certificate_type="client"
        )
        
        assert result is None
        mock_logger.error.assert_called_once()
        error_call = mock_logger.error.call_args[0][0]
        assert "Failed to log certificate to CT service" in error_call

    @patch('requests.Session.get')
    def test_health_check_success(self, mock_get):
        """Test successful health check."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        client = CTLogClient("http://example.com", timeout=15)
        result = client.health_check()
        
        assert result is True
        mock_get.assert_called_once_with(
            "http://example.com/health",
            timeout=15
        )

    @patch('requests.Session.get')
    def test_health_check_failure_status_code(self, mock_get):
        """Test health check with non-200 status code."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_get.return_value = mock_response
        
        client = CTLogClient("http://example.com")
        result = client.health_check()
        
        assert result is False

    @patch('requests.Session.get')
    @patch('app.utils.log_client.logger')
    def test_health_check_exception_handling(self, mock_logger, mock_get):
        """Test health check exception handling."""
        mock_get.side_effect = requests.RequestException("Connection error")
        
        client = CTLogClient("http://example.com")
        result = client.health_check()
        
        assert result is False
        mock_logger.error.assert_called_once()
        error_call = mock_logger.error.call_args[0][0]
        assert "CT service health check failed" in error_call

    @patch('requests.Session.get')
    @patch('app.utils.log_client.logger')
    def test_health_check_generic_exception(self, mock_logger, mock_get):
        """Test health check with generic exception."""
        mock_get.side_effect = Exception("Generic error")
        
        client = CTLogClient("http://example.com")
        result = client.health_check()
        
        assert result is False
        mock_logger.error.assert_called_once()

    def test_multiple_sessions_are_independent(self):
        """Test that multiple client instances have independent sessions."""
        client1 = CTLogClient("http://example1.com")
        client2 = CTLogClient("http://example2.com")
        
        assert client1.session is not client2.session
        assert client1.ct_service_url != client2.ct_service_url

    @patch('app.utils.log_client.logger')
    def test_log_certificate_payload_construction(self, mock_logger):
        """Test that the certificate logging payload is constructed correctly."""
        client = CTLogClient("http://example.com")
        
        # Test that internal payload construction handles all fields
        result = client.log_certificate(
            certificate_pem="test-cert",
            certificate_type="client",
            certificate_purpose="test-purpose",
            request_source="test-source",
            issued_by_service="test-service"
        )
        
        # The function should complete successfully
        assert result is not None
        mock_logger.info.assert_called_once()

    @patch('app.utils.log_client.logger')
    def test_log_certificate_payload_without_optional_fields(self, mock_logger):
        """Test payload construction without optional fields."""
        client = CTLogClient("http://example.com")
        
        result = client.log_certificate(
            certificate_pem="test-cert",
            certificate_type="server"
        )
        
        assert result is not None
        mock_logger.info.assert_called_once()


class TestLogCertificateToCTFunction:
    """Test suite for the log_certificate_to_ct convenience function."""
    
    @patch('app.utils.log_client.CTLogClient')
    def test_log_certificate_to_ct_success(self, mock_client_class):
        """Test successful certificate logging with convenience function."""
        # Setup mock client
        mock_client_instance = Mock()
        mock_client_instance.log_certificate.return_value = {'status': 'logged'}
        mock_client_class.return_value = mock_client_instance
        
        result = log_certificate_to_ct(
            certificate_pem="test-cert",
            certificate_type="client"
        )
        
        assert result is True
        mock_client_class.assert_called_once_with("http://certtransparency_service:8003")
        mock_client_instance.log_certificate.assert_called_once_with(
            "test-cert",
            "client"
        )

    @patch('app.utils.log_client.CTLogClient')
    def test_log_certificate_to_ct_failure(self, mock_client_class):
        """Test certificate logging failure with convenience function."""
        # Setup mock client
        mock_client_instance = Mock()
        mock_client_instance.log_certificate.return_value = None
        mock_client_class.return_value = mock_client_instance
        
        result = log_certificate_to_ct(
            certificate_pem="test-cert",
            certificate_type="client"
        )
        
        assert result is False

    @patch('app.utils.log_client.CTLogClient')
    def test_log_certificate_to_ct_custom_url(self, mock_client_class):
        """Test convenience function with custom CT service URL."""
        mock_client_instance = Mock()
        mock_client_instance.log_certificate.return_value = {'status': 'logged'}
        mock_client_class.return_value = mock_client_instance
        
        result = log_certificate_to_ct(
            certificate_pem="test-cert",
            certificate_type="server",
            ct_service_url="http://custom-ct:9000"
        )
        
        assert result is True
        mock_client_class.assert_called_once_with("http://custom-ct:9000")

    @patch('app.utils.log_client.CTLogClient')
    def test_log_certificate_to_ct_with_kwargs(self, mock_client_class):
        """Test convenience function with additional kwargs."""
        mock_client_instance = Mock()
        mock_client_instance.log_certificate.return_value = {'status': 'logged'}
        mock_client_class.return_value = mock_client_instance
        
        result = log_certificate_to_ct(
            certificate_pem="test-cert",
            certificate_type="intermediate",
            certificate_purpose="test-ca",
            request_source="pki_service",
            issued_by_service="root_ca_service"
        )
        
        assert result is True
        mock_client_instance.log_certificate.assert_called_once_with(
            "test-cert",
            "intermediate",
            certificate_purpose="test-ca",
            request_source="pki_service",
            issued_by_service="root_ca_service"
        )

    @patch('app.utils.log_client.CTLogClient')
    def test_log_certificate_to_ct_client_creation_each_call(self, mock_client_class):
        """Test that convenience function creates new client each time."""
        mock_client_instance = Mock()
        mock_client_instance.log_certificate.return_value = {'status': 'logged'}
        mock_client_class.return_value = mock_client_instance
        
        # Make multiple calls
        log_certificate_to_ct("cert1", "client")
        log_certificate_to_ct("cert2", "server")
        
        # Should create client twice
        assert mock_client_class.call_count == 2


class TestIntegrationScenarios:
    """Test integration scenarios and edge cases."""
    
    def test_client_with_various_url_formats(self):
        """Test client initialization with various URL formats."""
        test_urls = [
            "http://example.com",
            "https://example.com",
            "http://example.com:8080",
            "https://example.com:8443/",
            "http://ct-service.local/"
        ]
        
        for url in test_urls:
            client = CTLogClient(url)
            # Should not raise exception and should normalize URL
            assert client.ct_service_url is not None
            assert not client.ct_service_url.endswith('/')

    @patch('app.utils.log_client.logger')
    def test_logging_with_empty_strings(self, mock_logger):
        """Test logging behavior with empty string parameters."""
        client = CTLogClient("http://example.com")
        
        result = client.log_certificate(
            certificate_pem="",
            certificate_type="",
            certificate_purpose="",
            request_source="",
            issued_by_service=""
        )
        
        # Should still succeed (payload construction allows empty strings)
        assert result is not None

    def test_session_reuse_across_calls(self):
        """Test that the same session is reused across multiple calls."""
        client = CTLogClient("http://example.com")
        
        session_id_1 = id(client.session)
        
        # Make some calls
        client.log_certificate("cert1", "client")
        client.log_certificate("cert2", "server")
        
        session_id_2 = id(client.session)
        
        # Session should be the same
        assert session_id_1 == session_id_2

    @patch('requests.Session.get')
    def test_health_check_respects_timeout(self, mock_get):
        """Test that health check uses the configured timeout."""
        custom_timeout = 45
        client = CTLogClient("http://example.com", timeout=custom_timeout)
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        client.health_check()
        
        # Verify timeout was passed correctly
        mock_get.assert_called_once_with(
            "http://example.com/health",
            timeout=custom_timeout
        )

    @patch('app.utils.log_client.logger')
    def test_log_certificate_large_payload(self, mock_logger):
        """Test certificate logging with large payloads."""
        client = CTLogClient("http://example.com")
        
        # Create large certificate and metadata
        large_cert = "-----BEGIN CERTIFICATE-----\n" + "A" * 10000 + "\n-----END CERTIFICATE-----"
        large_purpose = "x" * 1000
        large_source = "y" * 1000
        
        result = client.log_certificate(
            certificate_pem=large_cert,
            certificate_type="client",
            certificate_purpose=large_purpose,
            request_source=large_source
        )
        
        assert result is not None
        mock_logger.info.assert_called_once()