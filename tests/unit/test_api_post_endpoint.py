"""
Unit tests for Certificate Transparency service POST endpoint.

Tests the certificate logging endpoint with authentication and validation.
"""

import pytest
import json
from app import create_app, db
from app.models.certificate_log import CertificateLog


class TestCertificateTransparencyPostEndpoint:
    """Test suite for CT service POST endpoint."""

    @pytest.fixture
    def app(self):
        """Create application for testing."""
        import os
        # Set environment for testing
        os.environ['ENVIRONMENT'] = 'testing'
        os.environ['CT_SERVICE_API_SECRET'] = 'test-secret-key'
        
        app = create_app()
        app.config['TESTING'] = True
        app.config['CT_SERVICE_API_SECRET'] = 'test-secret-key'
        
        with app.app_context():
            db.create_all()
            yield app
            db.drop_all()
            
            # Clean up environment
            if 'ENVIRONMENT' in os.environ:
                del os.environ['ENVIRONMENT']
            if 'CT_SERVICE_API_SECRET' in os.environ:
                del os.environ['CT_SERVICE_API_SECRET']

    @pytest.fixture
    def client(self, app):
        """Create test client."""
        return app.test_client()

    @pytest.fixture
    def sample_cert_pem(self):
        """Sample certificate PEM for testing."""
        return """-----BEGIN CERTIFICATE-----
MIIByDCCAXqgAwIBAgIURPck4SWVXLwaYy4atIxbKKOqpiowBQYDK2VwMG0xCzAJ
BgNVBAYTAkdCMRAwDgYDVQQIDAdFbmdsYW5kMQ8wDQYDVQQHDAZMb25kb24xGDAW
BgNVBAoMD09wZW5WUE4gU2VydmljZTEhMB8GA1UEAwwYcm9vdC5vcGVudnBuLmV4
YW1wbGUub3JnMB4XDTI1MDgwNzIzMDAxNVoXDTM1MDgwNTIzMDAxNVowczELMAkG
A1UEBhMCR0IxEDAOBgNVBAgMB0VuZ2xhbmQxDzANBgNVBAcMBkxvbmRvbjEYMBYG
A1UECgwPT3BlblZQTiBTZXJ2aWNlMScwJQYDVQQDDB4yMDI1LTA4LTA4Lm9wZW52
cG4uZXhhbXBsZS5vcmcwKjAFBgMrZXADIQBPJTd17o9DPnCIP4DWQH/QafJPixjR
VcSYCSRe7ppcjaMmMCQwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMC
AQYwBQYDK2VwA0EADuc5sAf/zveAC0UpP7bNrjAydi2tQTivqW5Kr87H4nmQCVuQ
7oiKVdTQQtNUiV/q8cOq8XoM7kdf0s/Us1JyCg==
-----END CERTIFICATE-----"""

    def test_post_certificate_success(self, client, sample_cert_pem):
        """Test successful certificate logging."""
        headers = {
            'Content-Type': 'application/json',
            'X-CT-API-Secret': 'test-secret-key'
        }
        
        data = {
            'certificate_pem': sample_cert_pem,
            'certificate_type': 'intermediate',
            'certificate_purpose': 'Test certificate for unit tests',
            'requester_info': {
                'test_source': 'unit-test',
                'test_case': 'test_post_certificate_success'
            }
        }
        
        response = client.post('/api/v1/certificates', 
                             data=json.dumps(data), 
                             headers=headers)
        
        assert response.status_code == 201
        response_data = json.loads(response.data)
        
        assert response_data['status'] == 'logged'
        assert 'certificate' in response_data
        assert 'message' in response_data
        
        # Verify certificate was stored in database
        cert = response_data['certificate']
        assert cert['certificate_type'] == 'intermediate'
        assert cert['subject']['common_name'] == '2025-08-08.openvpn.example.org'
        assert cert['issuer']['common_name'] == 'root.openvpn.example.org'
        
        # Verify in database
        stored_cert = CertificateLog.query.filter_by(
            fingerprint_sha256=cert['fingerprint_sha256']
        ).first()
        assert stored_cert is not None
        assert stored_cert.certificate_type == 'intermediate'
        assert stored_cert.certificate_purpose == 'Test certificate for unit tests'

    def test_post_certificate_missing_auth(self, client, sample_cert_pem):
        """Test certificate logging without authentication header."""
        headers = {
            'Content-Type': 'application/json'
            # Missing X-CT-API-Secret header
        }
        
        data = {
            'certificate_pem': sample_cert_pem,
            'certificate_type': 'client'
        }
        
        response = client.post('/api/v1/certificates', 
                             data=json.dumps(data), 
                             headers=headers)
        
        assert response.status_code == 401
        response_data = json.loads(response.data)
        assert 'Missing X-CT-API-Secret header' in response_data['error']

    def test_post_certificate_invalid_auth(self, client, sample_cert_pem):
        """Test certificate logging with invalid authentication."""
        headers = {
            'Content-Type': 'application/json',
            'X-CT-API-Secret': 'wrong-secret-key'
        }
        
        data = {
            'certificate_pem': sample_cert_pem,
            'certificate_type': 'client'
        }
        
        response = client.post('/api/v1/certificates', 
                             data=json.dumps(data), 
                             headers=headers)
        
        assert response.status_code == 403
        response_data = json.loads(response.data)
        assert 'Invalid API secret' in response_data['error']

    def test_post_certificate_missing_pem(self, client):
        """Test certificate logging without PEM data."""
        headers = {
            'Content-Type': 'application/json',
            'X-CT-API-Secret': 'test-secret-key'
        }
        
        data = {
            'certificate_type': 'client'
            # Missing certificate_pem
        }
        
        response = client.post('/api/v1/certificates', 
                             data=json.dumps(data), 
                             headers=headers)
        
        assert response.status_code == 400
        response_data = json.loads(response.data)
        assert 'certificate_pem is required' in response_data['error']

    def test_post_certificate_missing_type(self, client, sample_cert_pem):
        """Test certificate logging without certificate type."""
        headers = {
            'Content-Type': 'application/json',
            'X-CT-API-Secret': 'test-secret-key'
        }
        
        data = {
            'certificate_pem': sample_cert_pem
            # Missing certificate_type
        }
        
        response = client.post('/api/v1/certificates', 
                             data=json.dumps(data), 
                             headers=headers)
        
        assert response.status_code == 400
        response_data = json.loads(response.data)
        assert 'certificate_type is required' in response_data['error']

    def test_post_certificate_invalid_type(self, client, sample_cert_pem):
        """Test certificate logging with invalid certificate type."""
        headers = {
            'Content-Type': 'application/json',
            'X-CT-API-Secret': 'test-secret-key'
        }
        
        data = {
            'certificate_pem': sample_cert_pem,
            'certificate_type': 'invalid_type'
        }
        
        response = client.post('/api/v1/certificates', 
                             data=json.dumps(data), 
                             headers=headers)
        
        assert response.status_code == 400
        response_data = json.loads(response.data)
        assert 'certificate_type must be one of: client, server, intermediate' in response_data['error']

    def test_post_certificate_invalid_pem(self, client):
        """Test certificate logging with invalid PEM data."""
        headers = {
            'Content-Type': 'application/json',
            'X-CT-API-Secret': 'test-secret-key'
        }
        
        data = {
            'certificate_pem': 'invalid-pem-data',
            'certificate_type': 'client'
        }
        
        response = client.post('/api/v1/certificates', 
                             data=json.dumps(data), 
                             headers=headers)
        
        assert response.status_code == 400
        response_data = json.loads(response.data)
        assert 'Invalid certificate data' in response_data['error']

    def test_post_certificate_with_optional_fields(self, client, sample_cert_pem):
        """Test certificate logging with all optional fields."""
        headers = {
            'Content-Type': 'application/json',
            'X-CT-API-Secret': 'test-secret-key'
        }
        
        data = {
            'certificate_pem': sample_cert_pem,
            'certificate_type': 'server',
            'certificate_purpose': 'Server certificate for test.example.com',
            'requester_info': {
                'issued_by_service': 'signing-service',
                'request_source': '192.168.1.100',
                'user_agent': 'python-requests/2.32.4'
            }
        }
        
        response = client.post('/api/v1/certificates', 
                             data=json.dumps(data), 
                             headers=headers)
        
        assert response.status_code == 201
        response_data = json.loads(response.data)
        
        cert = response_data['certificate']
        assert cert['certificate_type'] == 'server'
        assert cert['issued_by_service'] == 'signing-service'
        assert cert['request_source'] == '192.168.1.100'
        
        # Verify in database
        stored_cert = CertificateLog.query.filter_by(
            fingerprint_sha256=cert['fingerprint_sha256']
        ).first()
        assert stored_cert.certificate_purpose == 'Server certificate for test.example.com'
        assert stored_cert.issued_by_service == 'signing-service'
        assert stored_cert.request_source == '192.168.1.100'

    def test_post_certificate_no_json_body(self, client):
        """Test certificate logging without JSON body."""
        headers = {
            'X-CT-API-Secret': 'test-secret-key'
        }
        
        response = client.post('/api/v1/certificates', 
                             data='not-json', 
                             headers=headers)
        
        assert response.status_code == 415  # Unsupported Media Type
        # 415 errors return HTML, not JSON
        response_text = response.data.decode('utf-8')
        assert 'Unsupported Media Type' in response_text

    def test_post_certificate_empty_json_body(self, client):
        """Test certificate logging with empty JSON body."""
        headers = {
            'Content-Type': 'application/json',
            'X-CT-API-Secret': 'test-secret-key'
        }
        
        response = client.post('/api/v1/certificates', 
                             data='', 
                             headers=headers)
        
        assert response.status_code == 400
        # The response might be HTML or JSON depending on how Flask handles it
        response_text = response.data.decode('utf-8')
        if response.headers.get('Content-Type', '').startswith('application/json'):
            response_data = json.loads(response_text)
            assert 'Request body must be JSON' in response_data['error']
        else:
            # If it's HTML error response, it should still indicate the issue
            assert 'Bad Request' in response_text or 'JSON' in response_text

    def test_post_certificate_null_json_body(self, client):
        """Test certificate logging with null JSON body that triggers line 368."""
        headers = {
            'Content-Type': 'application/json',
            'X-CT-API-Secret': 'test-secret-key'
        }
        
        # Send 'null' JSON which should result in data=None
        response = client.post('/api/v1/certificates', 
                             data='null', 
                             headers=headers)
        
        assert response.status_code == 400
        response_data = json.loads(response.data)
        assert 'Request body must be JSON' in response_data['error']

    def test_post_certificate_duplicate_handling(self, client, sample_cert_pem):
        """Test behavior when logging the same certificate twice."""
        headers = {
            'Content-Type': 'application/json',
            'X-CT-API-Secret': 'test-secret-key'
        }
        
        data = {
            'certificate_pem': sample_cert_pem,
            'certificate_type': 'client',
            'certificate_purpose': 'First logging attempt'
        }
        
        # First request should succeed
        response1 = client.post('/api/v1/certificates', 
                              data=json.dumps(data), 
                              headers=headers)
        assert response1.status_code == 201
        
        # Second request with same certificate should succeed in append-only CT architecture
        # Each logging event is recorded as a separate entry
        data['certificate_purpose'] = 'Second logging attempt'
        response2 = client.post('/api/v1/certificates', 
                              data=json.dumps(data), 
                              headers=headers)
        assert response2.status_code == 201  # Success - duplicate logging events allowed
        response_data = json.loads(response2.data)
        assert response_data['status'] == 'logged'
        assert 'Certificate logged successfully' in response_data['message']

    def test_post_certificate_missing_api_secret_config(self, sample_cert_pem):
        """Test certificate logging when CT_SERVICE_API_SECRET is not configured."""
        import os
        from app import create_app
        
        # Set environment for testing WITHOUT CT_SERVICE_API_SECRET
        os.environ['ENVIRONMENT'] = 'testing'
        # Intentionally omit CT_SERVICE_API_SECRET
        
        app = create_app()
        app.config['TESTING'] = True
        # Don't set CT_SERVICE_API_SECRET in config
        
        with app.app_context():
            client = app.test_client()
            
            headers = {
                'Content-Type': 'application/json',
                'X-CT-API-Secret': 'any-secret'
            }
            
            data = {
                'certificate_pem': sample_cert_pem,
                'certificate_type': 'client'
            }
            
            response = client.post('/api/v1/certificates', 
                                 data=json.dumps(data), 
                                 headers=headers)
            
            assert response.status_code == 500
            response_data = json.loads(response.data)
            assert 'Authentication service not configured' in response_data['error']
            
        # Clean up environment
        if 'ENVIRONMENT' in os.environ:
            del os.environ['ENVIRONMENT']


    def test_get_next_crl_number_success(self, client):
        """Test CRL number generation success path - covers lines 693-697."""
        headers = {
            'Content-Type': 'application/json',
            'X-CT-API-Secret': 'test-secret-key'
        }
        
        data = {
            'issuer_identifier': 'test-ca.example.com'
        }
        
        response = client.post('/api/v1/crl/next-number',
                             data=json.dumps(data),
                             headers=headers)
        
        assert response.status_code == 200
        response_data = json.loads(response.data)
        assert 'crl_number' in response_data
        assert response_data['issuer_identifier'] == 'test-ca.example.com'
        assert isinstance(response_data['crl_number'], int)
        assert response_data['crl_number'] > 0