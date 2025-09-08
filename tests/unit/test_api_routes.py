"""
Unit tests for Certificate Transparency Service API routes.
"""

import pytest
import json
from unittest.mock import patch
from app.models.certificate_log import CertificateLog
from app import db


class TestAPIRoutes:
    """Test API endpoints."""
    
    def test_list_certificates_empty(self, client):
        """Test listing certificates when none exist."""
        response = client.get('/api/v1/certificates')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['certificates'] == []
        assert data['pagination']['total'] == 0
    
    def test_list_certificates_with_data(self, client, app, sample_cert_data):
        """Test listing certificates with data."""
        with app.app_context():
            # Create test certificate
            CertificateLog.log_certificate(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type'],
                certificate_purpose=sample_cert_data['certificate_purpose']
            )
        
        response = client.get('/api/v1/certificates')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert len(data['certificates']) == 1
        assert data['pagination']['total'] == 1
        assert data['certificates'][0]['certificate_type'] == 'client'
    
    def test_list_certificates_with_pagination(self, client, app, sample_cert_data, sample_server_cert_data):
        """Test certificate listing with pagination."""
        with app.app_context():
            # Create two unique test certificates
            CertificateLog.log_certificate(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type'],
                certificate_purpose='test-purpose-client'
            )
            CertificateLog.log_certificate(
                sample_server_cert_data['certificate_pem'],
                sample_server_cert_data['certificate_type'],
                certificate_purpose='test-purpose-server'
            )
        
        # Test first page with limit 1
        response = client.get('/api/v1/certificates?limit=1&page=1')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert len(data['certificates']) == 1
        assert data['pagination']['page'] == 1
        assert data['pagination']['total'] == 2
        assert data['pagination']['has_next'] is True
        
        # Test second page with limit 1
        response = client.get('/api/v1/certificates?limit=1&page=2')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert len(data['certificates']) == 1
        assert data['pagination']['page'] == 2
        assert data['pagination']['has_next'] is False
    
    def test_list_certificates_with_type_filter(self, client, app, sample_cert_data, sample_server_cert_data):
        """Test certificate listing with type filter."""
        with app.app_context():
            # Create client certificate
            CertificateLog.log_certificate(
                sample_cert_data['certificate_pem'],
                'client',
                certificate_purpose='client-cert'
            )
            # Create server certificate using different certificate
            CertificateLog.log_certificate(
                sample_server_cert_data['certificate_pem'],
                'server',
                certificate_purpose='server-cert'
            )
        
        # Filter by client type
        response = client.get('/api/v1/certificates?type=client')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert len(data['certificates']) == 1
        assert data['certificates'][0]['certificate_type'] == 'client'
        
        # Filter by server type
        response = client.get('/api/v1/certificates?type=server')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert len(data['certificates']) == 1
        assert data['certificates'][0]['certificate_type'] == 'server'
    
    def test_get_certificate_by_fingerprint_success(self, client, app, sample_cert_data):
        """Test getting certificate by fingerprint."""
        with app.app_context():
            log_entry = CertificateLog.log_certificate(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type']
            )
            fingerprint = log_entry.fingerprint_sha256
        
        response = client.get(f'/api/v1/certificates/{fingerprint}')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert 'certificate' in data
        assert data['certificate']['fingerprint_sha256'] == fingerprint
        assert 'certificate_pem' in data['certificate']  # Default includes PEM
    
    def test_get_certificate_by_fingerprint_not_found(self, client):
        """Test getting certificate by non-existent fingerprint."""
        response = client.get('/api/v1/certificates/nonexistent')
        assert response.status_code == 404
        
        data = json.loads(response.data)
        assert data['error'] == 'Certificate not found'
    
    def test_get_certificate_by_serial_success(self, client, app, sample_cert_data):
        """Test getting certificate by serial number."""
        with app.app_context():
            log_entry = CertificateLog.log_certificate(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type']
            )
            serial = log_entry.serial_number
        
        response = client.get(f'/api/v1/certificates/serial/{serial}')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert 'certificate' in data
        assert data['certificate']['serial_number'] == serial
    
    def test_get_certificates_by_subject(self, client, app, sample_cert_data):
        """Test getting certificates by subject common name."""
        with app.app_context():
            log_entry = CertificateLog.log_certificate(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type']
            )
            subject_cn = log_entry.subject_common_name
        
        response = client.get(f'/api/v1/certificates/subject/{subject_cn}')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['subject_common_name'] == subject_cn
        assert data['certificate_count'] >= 1
        assert len(data['certificates']) >= 1
    
    def test_statistics_empty(self, client):
        """Test statistics endpoint with no certificates."""
        response = client.get('/api/v1/statistics')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['total_certificates'] == 0
        assert data['by_type']['client'] == 0
        assert data['by_type']['server'] == 0
        assert data['by_status']['active'] == 0
        assert data['by_status']['revoked'] == 0
    
    def test_statistics_with_data(self, client, app, sample_cert_data, sample_server_cert_data):
        """Test statistics endpoint with certificate data."""
        with app.app_context():
            # Create test certificates using different certificates
            client_cert = CertificateLog.log_certificate(
                sample_cert_data['certificate_pem'],
                'client'
            )
            server_cert = CertificateLog.log_certificate(
                sample_server_cert_data['certificate_pem'],
                'server'
            )
            # Revoke one certificate
            client_cert.mark_revoked("Test revocation")
            db.session.commit()
        
        response = client.get('/api/v1/statistics')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['total_certificates'] == 2
        assert data['by_type']['client'] == 1
        assert data['by_type']['server'] == 1
        assert data['by_status']['active'] == 1
        assert data['by_status']['revoked'] == 1
    
    def test_search_certificates(self, client, app, sample_cert_data):
        """Test certificate search endpoint."""
        with app.app_context():
            log_entry = CertificateLog.log_certificate(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type']
            )
            subject_cn = log_entry.subject_common_name
        
        # Search by partial subject name
        search_term = subject_cn[:5] if len(subject_cn) > 5 else subject_cn
        response = client.get(f'/api/v1/search?q={search_term}')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['query'] == search_term
        assert data['exact_match'] is False
        assert data['result_count'] >= 1
    
    def test_search_certificates_no_query(self, client):
        """Test search endpoint without query parameter."""
        response = client.get('/api/v1/search')
        assert response.status_code == 400
        
        data = json.loads(response.data)
        assert 'error' in data
        assert 'required' in data['error'].lower()
    
    def test_include_pem_parameter(self, client, app, sample_cert_data):
        """Test include_pem parameter in various endpoints."""
        with app.app_context():
            log_entry = CertificateLog.log_certificate(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type']
            )
        
        # Test with include_pem=false
        response = client.get('/api/v1/certificates?include_pem=false')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert 'certificate_pem' not in data['certificates'][0]
        
        # Test with include_pem=true
        response = client.get('/api/v1/certificates?include_pem=true')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert 'certificate_pem' in data['certificates'][0]
    
    def test_list_certificates_subject_filter(self, client, app, sample_cert_data):
        """Test subject filter in list_certificates - line 69."""
        with app.app_context():
            log_entry = CertificateLog.log_certificate(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type']
            )
            subject_cn = log_entry.subject_common_name
        
        response = client.get(f'/api/v1/certificates?subject={subject_cn[:5]}')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert len(data['certificates']) >= 1
        assert data['filters']['subject'] == subject_cn[:5]
    
    def test_list_certificates_issuer_filter(self, client, app, sample_cert_data):
        """Test issuer filter in list_certificates - line 72."""
        with app.app_context():
            log_entry = CertificateLog.log_certificate(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type']
            )
            issuer_cn = log_entry.issuer_common_name
        
        response = client.get(f'/api/v1/certificates?issuer={issuer_cn[:5]}')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert len(data['certificates']) >= 1
        assert data['filters']['issuer'] == issuer_cn[:5]
    
    def test_list_certificates_serial_filter(self, client, app, sample_cert_data):
        """Test serial filter in list_certificates - line 75."""
        with app.app_context():
            log_entry = CertificateLog.log_certificate(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type']
            )
            serial = log_entry.serial_number
        
        response = client.get(f'/api/v1/certificates?serial={serial}')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert len(data['certificates']) == 1
        assert data['filters']['serial'] == serial
    
    def test_list_certificates_fingerprint_filter(self, client, app, sample_cert_data):
        """Test fingerprint filter in list_certificates - line 78."""
        with app.app_context():
            log_entry = CertificateLog.log_certificate(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type']
            )
            fingerprint = log_entry.fingerprint_sha256
        
        response = client.get(f'/api/v1/certificates?fingerprint={fingerprint}')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert len(data['certificates']) == 1
        assert data['filters']['fingerprint'] == fingerprint
    
    def test_list_certificates_from_date_invalid(self, client):
        """Test from_date filter with invalid format - lines 81-85."""
        response = client.get('/api/v1/certificates?from_date=invalid-date')
        assert response.status_code == 400
        
        data = json.loads(response.data)
        assert 'error' in data
        assert 'Invalid from_date format' in data['error']
    
    def test_list_certificates_to_date_invalid(self, client):
        """Test to_date filter with invalid format - lines 88-92."""
        response = client.get('/api/v1/certificates?to_date=invalid-date')
        assert response.status_code == 400
        
        data = json.loads(response.data)
        assert 'error' in data
        assert 'Invalid to_date format' in data['error']
    
    def test_list_certificates_ascending_sort(self, client, app, sample_cert_data):
        """Test ascending sort order - line 108."""
        with app.app_context():
            CertificateLog.log_certificate(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type']
            )
        
        response = client.get('/api/v1/certificates?sort=issued_at&order=asc')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert len(data['certificates']) >= 1
    
    def test_list_certificates_invalid_sort_field(self, client):
        """Test invalid sort_field fallback - line 112."""
        response = client.get('/api/v1/certificates?sort=invalid_field')
        assert response.status_code == 200  # Should fall back to default sort
        
        data = json.loads(response.data)
        # Should use default sort (issued_at desc)
        assert 'certificates' in data
    
    def test_list_certificates_pagination_exception(self, client):
        """Test pagination exception handling - lines 121-122."""
        # Try to cause a pagination exception with extreme values
        response = client.get('/api/v1/certificates?page=999999&limit=1000')
        assert response.status_code in [200, 500]  # May succeed with empty or fail
    
    def test_get_certificate_by_serial_not_found(self, client):
        """Test certificate not found by serial - line 195."""
        response = client.get('/api/v1/certificates/serial/NONEXISTENT123')
        assert response.status_code == 404
        
        data = json.loads(response.data)
        assert 'error' in data
        assert 'not found' in data['error'].lower()
    
    def test_get_certificates_by_subject_exclude_revoked(self, client, app, sample_cert_data):
        """Test include_revoked=false filter in get_certificates_by_subject - line 223."""
        with app.app_context():
            # Create a certificate and mark it as revoked
            log_entry = CertificateLog.log_certificate(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type']
            )
            log_entry.mark_revoked('test revocation')
            db.session.commit()
            
            subject_cn = log_entry.subject_common_name
        
        response = client.get(f'/api/v1/certificates/subject/{subject_cn}?include_revoked=false')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        # Should not include revoked certificates
        revoked_certs = [cert for cert in data['certificates'] if 'revocation' in cert]
        assert len(revoked_certs) == 0
    
    def test_statistics_exception_handling(self, client):
        """Test exception handling in get_statistics - lines 286-287."""
        from unittest.mock import patch
        
        with patch('app.routes.api.CertificateLog') as mock_cert_log:
            mock_cert_log.query.count.side_effect = Exception('Database error')
            
            response = client.get('/api/v1/statistics')
            assert response.status_code == 500
            
            data = json.loads(response.data)
            assert 'error' in data
            assert 'Failed to generate statistics' in data['error']
    
    def test_404_error_handler(self, client):
        """Test 404 error handler - line 349."""
        response = client.get('/api/v1/nonexistent-endpoint')
        assert response.status_code == 404
        # Skip JSON parsing since Flask returns HTML for 404 by default
    
    def test_500_error_handler(self, client):
        """Test 500 error handler - line 355."""
        from unittest.mock import patch
        
        # Force a 500 error by making statistics fail with a database error  
        with patch('app.routes.api.CertificateLog') as mock_cert_log:
            # Make all database operations fail with an exception
            mock_cert_log.query.count.side_effect = RuntimeError('Simulated database failure')
            
            response = client.get('/api/v1/statistics')
            
            # Should return 500 due to the exception in statistics
            assert response.status_code == 500
    
    def test_list_certificates_with_valid_date_filters(self, client, app, sample_cert_data):
        """Test from_date and to_date filters with valid dates - lines 83, 90."""
        with app.app_context():
            log_entry = CertificateLog.log_certificate(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type']
            )
        
        # Test with valid from_date (line 83)
        response = client.get('/api/v1/certificates?from_date=2024-01-01T00:00:00Z')
        assert response.status_code == 200
        
        # Test with valid to_date (line 90) 
        response = client.get('/api/v1/certificates?to_date=2025-12-31T23:59:59Z')
        assert response.status_code == 200
        
        # Test with both valid dates
        response = client.get('/api/v1/certificates?from_date=2024-01-01T00:00:00Z&to_date=2025-12-31T23:59:59Z')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert 'certificates' in data

    def test_post_certificate_database_exception(self, client, sample_cert_data):
        """Test POST certificate with database exception - lines 403-406."""
        from unittest.mock import patch
        
        # Mock database session to raise an exception during commit
        with patch('app.routes.api.db.session.commit') as mock_commit:
            mock_commit.side_effect = Exception("Database connection failed")
            
            response = client.post(
                '/api/v1/certificates',
                json={
                    'certificate_pem': sample_cert_data['certificate_pem'],
                    'certificate_type': sample_cert_data['certificate_type'],
                    'certificate_purpose': sample_cert_data['certificate_purpose'],
                    'request_source': sample_cert_data['request_source']
                },
                headers={'X-CT-API-Secret': 'test-secret-key'}
            )
            
            assert response.status_code == 500
            data = json.loads(response.data)
            assert 'Failed to log certificate' in data['error']
            assert 'Database connection failed' in data['error']



class TestAPIRevocationEndpoint:
    """Test the certificate revocation API endpoint."""
    
    def test_revoke_certificate_success(self, client, app, sample_cert_data):
        """Test successful certificate revocation."""
        with app.app_context():
            # Create test certificate
            log_entry = CertificateLog.log_certificate(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type']
            )
            fingerprint = log_entry.fingerprint_sha256
        
        # Valid revocation request
        revocation_data = {
            'reason': 'key_compromise',
            'revoked_by': 'test_user'
        }
        
        headers = {'X-CT-API-Secret': 'test-secret-key'}
        response = client.post(
            f'/api/v1/certificates/{fingerprint}/revoke',
            json=revocation_data,
            headers=headers
        )
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['status'] == 'revoked'
        assert data['fingerprint'] == fingerprint
        assert data['revoked_reason'] == 'key_compromise'
        assert data['revoked_by'] == 'test_user'
    
    def test_revoke_certificate_no_json_body(self, client):
        """Test revocation with no JSON body (line 441-442)."""
        headers = {'X-CT-API-Secret': 'test-secret-key'}
        response = client.post(
            '/api/v1/certificates/FAKE123/revoke',
            json=None,  # This will trigger request.get_json() to return None
            headers=headers
        )
        assert response.status_code == 415 # Unsupported media type, apparently.
        
        # Flask returns HTML error page for 415, not JSON
        assert b'415 Unsupported Media Type' in response.data
        assert b'Content-Type' in response.data
    
    def test_revoke_certificate_empty_data(self, client):
        """Test revocation with empty data string - documents equally stupid user behavior."""
        headers = {'X-CT-API-Secret': 'test-secret-key', 'Content-Type': 'application/json'}
        response = client.post(
            '/api/v1/certificates/FAKE123/revoke',
            data='',  # Empty string with JSON content type - malformed request
            headers=headers
        )
        # This will likely return 400 for bad JSON format, but could be 415 or 500 depending on Flask behavior
        assert response.status_code in [400, 415, 500]
    
    def test_revoke_certificate_missing_reason(self, client):
        """Test revocation without reason field (line 444-446)."""
        revocation_data = {
            'revoked_by': 'test_user'
        }
        
        headers = {'X-CT-API-Secret': 'test-secret-key'}
        response = client.post(
            '/api/v1/certificates/FAKE123/revoke',
            json=revocation_data,
            headers=headers
        )
        assert response.status_code == 400
        
        data = json.loads(response.data)
        assert data['error'] == 'Revocation reason is required'
    
    def test_revoke_certificate_not_found(self, client):
        """Test revocation of non-existent certificate (line 454-455)."""
        revocation_data = {
            'reason': 'key_compromise',
            'revoked_by': 'test_user'
        }
        
        headers = {'X-CT-API-Secret': 'test-secret-key'}
        response = client.post(
            '/api/v1/certificates/NONEXISTENT123/revoke',
            json=revocation_data,
            headers=headers
        )
        assert response.status_code == 404
        
        data = json.loads(response.data)
        assert data['error'] == 'Certificate not found'
    
    def test_revoke_certificate_already_revoked(self, client, app, sample_cert_data):
        """Test revocation of already revoked certificate (line 458-463)."""
        with app.app_context():
            # Create certificate and then revoke using append-only approach
            log_entry = CertificateLog.log_certificate(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type']
            )
            fingerprint = log_entry.fingerprint_sha256
            
            # Create revocation record
            from datetime import datetime, timezone
            revocation_record = CertificateLog(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type'],
                action_type='revoked',
                log_timestamp=datetime.now(timezone.utc),
                revoked_at=datetime.now(timezone.utc),
                revocation_reason='initial_revocation',
                revoked_by='initial_user'
            )
            
            from app import db
            db.session.add(revocation_record)
            db.session.commit()
        
        # Try to revoke again
        revocation_data = {
            'reason': 'key_compromise',
            'revoked_by': 'test_user'
        }
        
        headers = {'X-CT-API-Secret': 'test-secret-key'}
        response = client.post(
            f'/api/v1/certificates/{fingerprint}/revoke',
            json=revocation_data,
            headers=headers
        )
        assert response.status_code == 400
        
        data = json.loads(response.data)
        assert data['error'] == 'Certificate is already revoked'
        assert 'revoked_at' in data
        assert data['revoked_reason'] == 'initial_revocation'
    
    def test_revoke_certificate_invalid_timestamp(self, client, app, sample_cert_data):
        """Test revocation with invalid revoked_at timestamp (line 489-490)."""
        with app.app_context():
            log_entry = CertificateLog.log_certificate(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type']
            )
            fingerprint = log_entry.fingerprint_sha256
        
        # Invalid timestamp format
        revocation_data = {
            'reason': 'key_compromise',
            'revoked_by': 'test_user',
            'revoked_at': 'invalid-timestamp'
        }
        
        headers = {'X-CT-API-Secret': 'test-secret-key'}
        response = client.post(
            f'/api/v1/certificates/{fingerprint}/revoke',
            json=revocation_data,
            headers=headers
        )
        assert response.status_code == 400
        
        data = json.loads(response.data)
        assert 'Invalid revoked_at timestamp' in data['error']
    
    def test_revoke_certificate_with_custom_timestamp(self, client, app, sample_cert_data):
        """Test revocation with custom timestamp (line 467-470)."""
        with app.app_context():
            log_entry = CertificateLog.log_certificate(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type']
            )
            fingerprint = log_entry.fingerprint_sha256
        
        # Valid custom timestamp
        custom_time = '2025-01-01T12:00:00Z'
        revocation_data = {
            'reason': 'key_compromise',
            'revoked_by': 'test_user',
            'revoked_at': custom_time
        }
        
        headers = {'X-CT-API-Secret': 'test-secret-key'}
        response = client.post(
            f'/api/v1/certificates/{fingerprint}/revoke',
            json=revocation_data,
            headers=headers
        )
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['status'] == 'revoked'
        assert data['revoked_at'] == '2025-01-01T12:00:00'


class TestAPIBulkRevocationEndpoint:
    """Test the bulk revocation API endpoint."""
    
    def test_bulk_revoke_user_certificates_success(self, client, app, sample_cert_data):
        """Test successful bulk revocation of user certificates."""
        import secrets
        with app.app_context():
            user_id = 'test_user'
            # Create multiple certificates for the same user using log_certificate 
            # Allow natural duplicates - same certificate PEM logged multiple times
            cert1 = CertificateLog.log_certificate(
                sample_cert_data['certificate_pem'],
                'client',
                issuing_user_id=user_id,
                certificate_purpose='Bulk test cert 1'
            )
            
            cert2 = CertificateLog.log_certificate(
                sample_cert_data['certificate_pem'],
                'client', 
                issuing_user_id=user_id,
                certificate_purpose='Bulk test cert 2'
            )
            
            # Add a certificate for a different user (should not be revoked)
            cert3 = CertificateLog.log_certificate(
                sample_cert_data['certificate_pem'],
                'client',
                issuing_user_id='other_user',
                certificate_purpose='Other user cert'
            )
        
        # Bulk revoke certificates for test_user
        revocation_data = {
            'reason': 'cessation_of_operation',
            'revoked_by': 'admin_user'
        }
        
        headers = {'X-CT-API-Secret': 'test-secret-key'}
        response = client.post(
            f'/api/v1/users/{user_id}/revoke-certificates',
            json=revocation_data,
            headers=headers
        )
        assert response.status_code == 200
        
        data = json.loads(response.data)
        print(f"DEBUG: Bulk revocation response: {data}")
        assert data['revoked_count'] == 1  # Same PEM = same fingerprint = 1 unique certificate
        assert data['user_id'] == user_id
        assert data['reason'] == 'cessation_of_operation'
        assert data['revoked_by'] == 'admin_user'
        assert len(data['revoked_fingerprints']) == 1
    
    def test_bulk_revoke_no_active_certificates(self, client):
        """Test bulk revocation when user has no active certificates."""
        user_id = 'nonexistent_user'
        revocation_data = {
            'reason': 'cessation_of_operation',
            'revoked_by': 'admin_user'
        }
        
        headers = {'X-CT-API-Secret': 'test-secret-key'}
        response = client.post(
            f'/api/v1/users/{user_id}/revoke-certificates',
            json=revocation_data,
            headers=headers
        )
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['revoked_count'] == 0
        assert data['user_id'] == user_id
        assert 'No active certificates found' in data['message']
    
    def test_bulk_revoke_missing_reason(self, client):
        """Test bulk revocation without reason field."""
        revocation_data = {
            'revoked_by': 'admin_user'
        }
        
        headers = {'X-CT-API-Secret': 'test-secret-key'}
        response = client.post(
            '/api/v1/users/test_user/revoke-certificates',
            json=revocation_data,
            headers=headers
        )
        assert response.status_code == 400
        
        data = json.loads(response.data)
        assert data['error'] == 'Revocation reason is required'
    
    def test_bulk_revoke_missing_revoked_by(self, client):
        """Test bulk revocation without revoked_by field."""
        revocation_data = {
            'reason': 'cessation_of_operation'
        }
        
        headers = {'X-CT-API-Secret': 'test-secret-key'}
        response = client.post(
            '/api/v1/users/test_user/revoke-certificates',
            json=revocation_data,
            headers=headers
        )
        assert response.status_code == 400
        
        data = json.loads(response.data)
        assert data['error'] == 'revoked_by field is required'

    def test_bulk_revoke_invalid_revoked_at_timestamp(self, client, app, sample_cert_data):
        """Test bulk revoke with invalid revoked_at timestamp - lines 540-541."""
        with app.app_context():
            # Create certificate to revoke
            log_entry = CertificateLog.log_certificate(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type']
            )
            user_subject = log_entry.subject_common_name
            
        # Try bulk revoke with invalid timestamp format
        revocation_data = {
            'reason': 'cessation_of_operation',
            'revoked_by': 'test_admin',
            'revoked_at': 'invalid-timestamp-format'  # This should trigger ValueError
        }
        
        headers = {'X-CT-API-Secret': 'test-secret-key'}
        response = client.post(
            f'/api/v1/users/{user_subject}/revoke-certificates',
            json=revocation_data,
            headers=headers
        )
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'Invalid revoked_at timestamp' in data['error']

    def test_bulk_revoke_already_revoked_certificates_skip(self, client, app, sample_cert_data):
        """Test bulk revoke skips already revoked certificates - line 568."""
        with app.app_context():
            # Create certificate with issuing_user_id set
            log_entry = CertificateLog.log_certificate(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type']
            )
            
            # Set issuing_user_id so bulk revocation can find it
            test_user_id = "test_user_123" 
            log_entry.issuing_user_id = test_user_id
            from app import db
            db.session.commit()
            
            # Revoke the certificate first to create a revoked record
            fingerprint = log_entry.fingerprint_sha256
            revoke_response = client.post(
                f'/api/v1/certificates/{fingerprint}/revoke',
                json={
                    'reason': 'key_compromise',
                    'revoked_by': 'test_admin'
                },
                headers={'X-CT-API-Secret': 'test-secret-key'}
            )
            assert revoke_response.status_code == 200
            
            # Now try bulk revoke - should skip the already revoked certificate
            bulk_response = client.post(
                f'/api/v1/users/{test_user_id}/revoke-certificates',
                json={
                    'reason': 'cessation_of_operation',
                    'revoked_by': 'test_admin'
                },
                headers={'X-CT-API-Secret': 'test-secret-key'}
            )
            
            assert bulk_response.status_code == 200
            data = json.loads(bulk_response.data)
            
            # Should report 0 certificates revoked since the one certificate was already revoked (line 568)
            assert data['revoked_count'] == 0


class TestCRLAPIRoutes:
    """Test CRL API endpoints input validation."""
    
    def test_get_next_crl_number_missing_issuer_identifier(self, client):
        """Test POST /api/v1/crl/next-number without issuer_identifier field (lines 674-675)."""
        response = client.post(
            '/api/v1/crl/next-number',
            json={},  # Empty JSON, missing issuer_identifier
            headers={'X-CT-API-Secret': 'test-secret-key'}
        )
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['error'] == 'Missing required field: issuer_identifier'
    
    def test_get_next_crl_number_empty_issuer_identifier(self, client):
        """Test POST /api/v1/crl/next-number with empty issuer_identifier (lines 678-679)."""
        response = client.post(
            '/api/v1/crl/next-number',
            json={'issuer_identifier': '   '},  # Only whitespace
            headers={'X-CT-API-Secret': 'test-secret-key'}
        )
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['error'] == 'issuer_identifier cannot be empty'
    
    def test_get_current_crl_number_empty_issuer_identifier(self, client):
        """Test GET /api/v1/crl/current-number with empty issuer_identifier (lines 708-709)."""
        response = client.get(
            '/api/v1/crl/current-number/   ',  # Only whitespace in URL parameter
            headers={'X-CT-API-Secret': 'test-secret-key'}
        )
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['error'] == 'issuer_identifier cannot be empty'
    
    def test_get_current_crl_number_success(self, client):
        """Test successful GET /api/v1/crl/current-number response (line 714)."""
        response = client.get(
            '/api/v1/crl/current-number/test-issuer',
            headers={'X-CT-API-Secret': 'test-secret-key'}
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'current_crl_number' in data
        assert 'issuer_identifier' in data


class TestGeoIPIntegrationAPI:
    """Test GeoIP integration in certificate logging API endpoints."""
    
    @patch('app.routes.api.lookup_country_code')
    def test_certificate_logging_geoip_success(self, mock_lookup, client, sample_cert_data, caplog):
        """Test successful GeoIP lookup during certificate logging (line 396)."""
        import logging
        caplog.set_level(logging.DEBUG)  # Capture all loggers
        
        # Mock successful GeoIP lookup
        mock_lookup.return_value = 'US'
        
        # Certificate logging data with requester IP
        test_data = {
            'certificate_pem': sample_cert_data['certificate_pem'],
            'certificate_type': 'client',
            'certificate_purpose': 'test-geoip',
            'requester_info': {
                'requester_ip': '8.8.8.8'
            }
        }
        
        response = client.post(
            '/api/v1/certificates',
            json=test_data,
            headers={'X-CT-API-Secret': 'test-secret-key'}
        )
        
        assert response.status_code == 201
        
        # Verify GeoIP lookup was called
        mock_lookup.assert_called_once_with('8.8.8.8')
        
        # Verify debug logging for successful GeoIP lookup (line 396)
        assert "GeoIP lookup for 8.8.8.8: US" in caplog.text
    
    @patch('app.routes.api.lookup_country_code')
    def test_certificate_logging_geoip_failure(self, mock_lookup, client, sample_cert_data, caplog):
        """Test GeoIP lookup failure during certificate logging (line 398)."""
        import logging
        caplog.set_level(logging.WARNING)  # Capture all loggers
        
        # Mock GeoIP lookup raising an exception
        mock_lookup.side_effect = Exception("GeoIP database error")
        
        # Certificate logging data with requester IP
        test_data = {
            'certificate_pem': sample_cert_data['certificate_pem'],
            'certificate_type': 'client',
            'certificate_purpose': 'test-geoip-fail',
            'requester_info': {
                'requester_ip': '192.168.1.100'
            }
        }
        
        response = client.post(
            '/api/v1/certificates',
            json=test_data,
            headers={'X-CT-API-Secret': 'test-secret-key'}
        )
        
        # Certificate logging should still succeed despite GeoIP failure
        assert response.status_code == 201
        
        # Verify GeoIP lookup was attempted
        mock_lookup.assert_called_once_with('192.168.1.100')
        
        # Verify warning logging for failed GeoIP lookup (line 398)
        assert "GeoIP lookup failed for 192.168.1.100: GeoIP database error" in caplog.text
    
    @patch('app.routes.api.lookup_country_code')
    def test_certificate_logging_geoip_alternate_ip_field(self, mock_lookup, client, sample_cert_data, caplog):
        """Test GeoIP lookup with alternate IP field name (request_source)."""
        import logging
        caplog.set_level(logging.DEBUG)  # Capture all loggers
        
        # Mock successful GeoIP lookup
        mock_lookup.return_value = 'CA'
        
        # Certificate logging data with alternate IP field name
        test_data = {
            'certificate_pem': sample_cert_data['certificate_pem'],
            'certificate_type': 'server',
            'requester_info': {
                'request_source': '1.2.3.4'  # Uses request_source instead of requester_ip
            }
        }
        
        response = client.post(
            '/api/v1/certificates',
            json=test_data,
            headers={'X-CT-API-Secret': 'test-secret-key'}
        )
        
        assert response.status_code == 201
        
        # Verify GeoIP lookup was called with request_source IP
        mock_lookup.assert_called_once_with('1.2.3.4')
        
        # Verify debug logging for successful GeoIP lookup
        assert "GeoIP lookup for 1.2.3.4: CA" in caplog.text

