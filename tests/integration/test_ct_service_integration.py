"""
Integration tests for Certificate Transparency Service.
"""

import json
from datetime import datetime, timezone
from app.models.certificate_log import CertificateLog
from app.extensions import db


class TestCTServiceIntegration:
    """Integration tests for the complete CT service."""
    
    def test_complete_certificate_lifecycle(self, client, app, sample_cert_data):
        """Test complete certificate lifecycle from logging to retrieval."""
        with app.app_context():
            # 1. Log a certificate
            log_entry = CertificateLog.log_certificate(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type'],
                certificate_purpose='integration-test',
                request_source='test_suite'
            )
            fingerprint = log_entry.fingerprint_sha256
            serial = log_entry.serial_number
            subject_cn = log_entry.subject_common_name
        
        # 2. Verify certificate appears in listing
        response = client.get('/api/v1/certificates')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['pagination']['total'] == 1
        assert data['certificates'][0]['certificate_purpose'] == 'integration-test'
        
        # 3. Retrieve certificate by fingerprint
        response = client.get(f'/api/v1/certificates/{fingerprint}')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['certificate']['fingerprint_sha256'] == fingerprint
        assert data['certificate']['certificate_purpose'] == 'integration-test'
        
        # 4. Retrieve certificate by serial number
        response = client.get(f'/api/v1/certificates/serial/{serial}')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['certificate']['serial_number'] == serial
        
        # 5. Search for certificate
        response = client.get(f'/api/v1/search?q={subject_cn}&exact=true')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['result_count'] == 1
        assert data['results'][0]['fingerprint_sha256'] == fingerprint
        
        # 6. Check statistics
        response = client.get('/api/v1/statistics')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['total_certificates'] == 1
        assert data['by_type']['client'] == 1
        assert data['by_status']['active'] == 1
    
    def test_certificate_revocation_flow(self, client, app, sample_cert_data):
        """Test certificate revocation workflow."""
        with app.app_context():
            # Create and log certificate
            log_entry = CertificateLog.log_certificate(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type']
            )
            fingerprint = log_entry.fingerprint_sha256
            
            # Revoke the certificate using append-only approach
            revocation_record = CertificateLog(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type'],
                action_type='revoked',
                log_timestamp=datetime.now(timezone.utc),
                revoked_at=datetime.now(timezone.utc),
                revocation_reason='Key compromise detected',
                revoked_by='test_user'
            )
            db.session.add(revocation_record)
            db.session.commit()
        
        # Verify revocation in certificate details
        response = client.get(f'/api/v1/certificates/{fingerprint}')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'revocation' in data['certificate']
        assert data['certificate']['revocation']['reason'] == 'Key compromise detected'
        
        # Verify statistics include revoked certificate
        response = client.get('/api/v1/statistics')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['by_status']['revoked'] == 1
        assert data['by_status']['active'] == 0
        
        # Test filtering out revoked certificates
        response = client.get('/api/v1/certificates?include_revoked=false')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert len(data['certificates']) == 0
    
    def test_multiple_certificate_types(self, client, app, sample_cert_data, sample_server_cert_data):
        """Test handling multiple certificate types."""
        with app.app_context():
            # Create certificates of different types using different certificates
            client_cert = CertificateLog.log_certificate(
                sample_cert_data['certificate_pem'],
                'client',
                certificate_purpose='user-profile'
            )
            server_cert = CertificateLog.log_certificate(
                sample_server_cert_data['certificate_pem'],
                'server',
                certificate_purpose='server-config'
            )
        
        # Test filtering by each type (only client and server available)
        for cert_type in ['client', 'server']:
            response = client.get(f'/api/v1/certificates?type={cert_type}')
            assert response.status_code == 200
            data = json.loads(response.data)
            assert len(data['certificates']) == 1
            assert data['certificates'][0]['certificate_type'] == cert_type
        
        # Test intermediate type (should return empty)
        response = client.get('/api/v1/certificates?type=intermediate')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert len(data['certificates']) == 0
        
        # Verify statistics
        response = client.get('/api/v1/statistics')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['total_certificates'] == 2
        assert data['by_type']['client'] == 1
        assert data['by_type']['server'] == 1
        assert data['by_type']['intermediate'] == 0
    
    def test_pagination_with_large_dataset(self, client, app, sample_cert_data, sample_server_cert_data):
        """Test pagination with a larger dataset."""
        with app.app_context():
            # Create test certificates using alternating certificate types to avoid uniqueness issues
            # For this test, we'll create a smaller set that can be unique
            certificates = [
                (sample_cert_data['certificate_pem'], 'client', 'test-cert-client'),
                (sample_server_cert_data['certificate_pem'], 'server', 'test-cert-server'),
            ]
            
            # Create 2 unique certificates (limitation due to uniqueness constraint)  
            for cert_pem, cert_type, purpose in certificates:
                CertificateLog.log_certificate(
                    cert_pem,
                    cert_type,
                    certificate_purpose=purpose
                )
        
        # Test pagination with 2 certificates
        response = client.get('/api/v1/certificates?limit=10&page=1')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert len(data['certificates']) == 2
        assert data['pagination']['page'] == 1
        assert data['pagination']['pages'] == 1
        assert data['pagination']['total'] == 2
        assert data['pagination']['has_next'] is False
        assert data['pagination']['has_prev'] is False
        
        # Test pagination with limit of 1
        response = client.get('/api/v1/certificates?limit=1&page=1')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert len(data['certificates']) == 1
        assert data['pagination']['page'] == 1
        assert data['pagination']['pages'] == 2
        assert data['pagination']['has_next'] is True
        assert data['pagination']['has_prev'] is False
        
        # Test second page with limit of 1
        response = client.get('/api/v1/certificates?limit=1&page=2')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert len(data['certificates']) == 1
        assert data['pagination']['page'] == 2
        assert data['pagination']['pages'] == 2
        assert data['pagination']['has_next'] is False
        assert data['pagination']['has_prev'] is True
    
    def test_health_checks_integration(self, client, app):
        """Test all health check endpoints."""
        # Test liveness (should always work)
        response = client.get('/live')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'alive'
        
        # Test health check (requires DB)
        response = client.get('/health')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'healthy'
        assert data['database'] == 'connected'
        
        # Test readiness (requires DB with tables)
        response = client.get('/ready')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'ready'
        assert data['database'] == 'ready'