"""
Unit tests for Certificate Transparency Log model.
"""

import pytest
from datetime import datetime, timezone
from app.models.certificate_log import CertificateLog
from app import db


class TestCertificateLogModel:
    """Test CertificateLog model functionality."""
    
    def test_create_certificate_log(self, app, sample_cert_data):
        """Test creating a certificate log entry."""
        with app.app_context():
            log_entry = CertificateLog(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type'],
                certificate_purpose=sample_cert_data['certificate_purpose'],
                request_source=sample_cert_data['request_source']
            )
            
            assert log_entry.certificate_type == 'client'
            assert log_entry.certificate_purpose == 'test-user-profile'
            assert log_entry.request_source == 'frontend_service'
            assert log_entry.subject_common_name is not None
            assert log_entry.fingerprint_sha256 is not None
            assert log_entry.serial_number is not None
    
    def test_to_dict_without_pem(self, app, sample_cert_data):
        """Test converting certificate log to dictionary without PEM."""
        with app.app_context():
            log_entry = CertificateLog(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type']
            )
            
            result = log_entry.to_dict(include_pem=False)
            
            assert 'certificate_pem' not in result
            assert result['certificate_type'] == 'client'
            assert 'fingerprint_sha256' in result
            assert 'subject' in result
            assert 'issuer' in result
            assert 'validity' in result
    
    def test_to_dict_with_pem(self, app, sample_cert_data):
        """Test converting certificate log to dictionary with PEM."""
        with app.app_context():
            log_entry = CertificateLog(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type']
            )
            
            result = log_entry.to_dict(include_pem=True)
            
            assert 'certificate_pem' in result
            assert result['certificate_pem'] == sample_cert_data['certificate_pem']
    
    def test_mark_revoked(self, app, sample_cert_data):
        """Test marking certificate as revoked."""
        with app.app_context():
            log_entry = CertificateLog(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type']
            )
            
            assert log_entry.revoked_at is None
            
            log_entry.mark_revoked("Key compromise")
            
            assert log_entry.revoked_at is not None
            assert log_entry.revocation_reason == "Key compromise"
    
    def test_log_certificate_classmethod(self, app, sample_cert_data):
        """Test the log_certificate class method."""
        with app.app_context():
            log_entry = CertificateLog.log_certificate(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type'],
                certificate_purpose=sample_cert_data['certificate_purpose']
            )
            
            assert log_entry.id is not None
            assert log_entry.certificate_type == 'client'
            assert log_entry.certificate_purpose == 'test-user-profile'
    
    def test_get_by_fingerprint(self, app, sample_cert_data):
        """Test getting certificate by fingerprint."""
        with app.app_context():
            log_entry = CertificateLog.log_certificate(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type']
            )
            
            fingerprint = log_entry.fingerprint_sha256
            found_entry = CertificateLog.get_by_fingerprint(fingerprint)
            
            assert found_entry is not None
            assert found_entry.id == log_entry.id
    
    def test_get_by_serial_number(self, app, sample_cert_data):
        """Test getting certificate by serial number."""
        with app.app_context():
            log_entry = CertificateLog.log_certificate(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type']
            )
            
            serial = log_entry.serial_number
            found_entry = CertificateLog.get_by_serial_number(serial)
            
            assert found_entry is not None
            assert found_entry.id == log_entry.id
    
    def test_certificate_log_without_key_size(self, app):
        """Test certificate processing without key_size attribute - line 128."""
        # Create a mock certificate with a public key that doesn't have key_size
        from unittest.mock import patch, MagicMock
        from cryptography import x509
        
        # Use a basic certificate PEM for testing
        test_cert_pem = """-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAJqz1VhQm1GEMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCXRl
c3QgY2VydDAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBQxEjAQBgNV
BAMMCXRlc3QgY2VydDBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC5XULZzsZIGwHI
VUkQzqzFLvv9HcKO8aDc0hQGb0J9sYg3f6fNztWzGrKzLrEhMQSj5tQFbgB8rqL3
TvOt7J3xAgMBAAEwDQYJKoZIhvcNAQELBQADQQAGVDJVtBVYX9FQWM8lx0fRH2wt
vNY3M/KqQv2zV8CcmXrWXg8kcK1vXY4dZJhHhj4VqRZbFxzHdR9hNl8pKqR3
-----END CERTIFICATE-----"""
        
        with app.app_context():
            with patch('cryptography.x509.load_pem_x509_certificate') as mock_load_cert:
                mock_cert = MagicMock()
                mock_cert.serial_number = 12345
                mock_cert.fingerprint.return_value.hex.return_value.upper.return_value = 'ABCDEF123456'
                
                # Mock subject and issuer
                mock_subject = MagicMock()
                mock_subject.get_attributes_for_oid.return_value = [MagicMock(value='Test Subject')]
                mock_cert.subject = mock_subject
                
                mock_issuer = MagicMock()
                mock_issuer.get_attributes_for_oid.return_value = [MagicMock(value='Test Issuer')]
                mock_cert.issuer = mock_issuer
                
                # Mock validity dates
                mock_cert.not_valid_before_utc = datetime.now(timezone.utc)
                mock_cert.not_valid_after_utc = datetime.now(timezone.utc)
                
                # Mock public key WITHOUT key_size attribute - line 128
                # Create a class that doesn't have key_size attribute
                class MockPublicKeyWithoutSize:
                    pass
                
                mock_public_key = MockPublicKeyWithoutSize()
                mock_cert.public_key.return_value = mock_public_key
                
                mock_cert.signature_algorithm_oid._name = 'sha256WithRSAEncryption'
                
                # Mock extensions to raise proper ExtensionNotFound exception
                def mock_extension_not_found(oid):
                    raise x509.ExtensionNotFound('Extension not found', oid)
                mock_cert.extensions.get_extension_for_oid.side_effect = mock_extension_not_found
                
                mock_load_cert.return_value = mock_cert
                
                log_entry = CertificateLog(test_cert_pem, 'client')
                
                # Verify key_size is None when not available
                assert log_entry.key_size is None
    
    def test_certificate_log_subject_alt_names_processing(self, app):
        """Test Subject Alternative Names processing - lines 153-162."""
        from unittest.mock import patch, MagicMock
        from cryptography import x509
        import json
        
        test_cert_pem = """-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAJqz1VhQm1GEMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCXRl
c3QgY2VydDAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBQxEjAQBgNV
BAMMCXRlc3QgY2VydDBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC5XULZzsZIGwHI
VUkQzqzFLvv9HcKO8aDc0hQGb0J9sYg3f6fNztWzGrKzLrEhMQSj5tQFbgB8rqL3
TvOt7J3xAgMBAAEwDQYJKoZIhvcNAQELBQADQQAGVDJVtBVYX9FQWM8lx0fRH2wt
vNY3M/KqQv2zV8CcmXrWXg8kcK1vXY4dZJhHhj4VqRZbFxzHdR9hNl8pKqR3
-----END CERTIFICATE-----"""
        
        with app.app_context():
            with patch('cryptography.x509.load_pem_x509_certificate') as mock_load_cert:
                mock_cert = MagicMock()
                mock_cert.serial_number = 12345
                mock_cert.fingerprint.return_value.hex.return_value.upper.return_value = 'ABCDEF123456'
                
                # Mock subject and issuer
                mock_subject = MagicMock()
                mock_subject.get_attributes_for_oid.return_value = [MagicMock(value='Test Subject')]
                mock_cert.subject = mock_subject
                
                mock_issuer = MagicMock()
                mock_issuer.get_attributes_for_oid.return_value = [MagicMock(value='Test Issuer')]
                mock_cert.issuer = mock_issuer
                
                # Mock validity dates
                mock_cert.not_valid_before_utc = datetime.now(timezone.utc)
                mock_cert.not_valid_after_utc = datetime.now(timezone.utc)
                
                # Mock public key with key_size
                mock_public_key = MagicMock()
                mock_public_key.key_size = 2048
                mock_cert.public_key.return_value = mock_public_key
                
                mock_cert.signature_algorithm_oid._name = 'sha256WithRSAEncryption'
                
                # Mock Subject Alternative Names extension - lines 153-162
                mock_san_ext = MagicMock()
                mock_dns_name = MagicMock(spec=x509.DNSName)
                mock_dns_name.value = 'example.com'
                mock_ip_address = MagicMock(spec=x509.IPAddress)
                mock_ip_address.value = '192.168.1.1'
                mock_email = MagicMock(spec=x509.RFC822Name)
                mock_email.value = 'test@example.com'
                
                mock_san_ext.value = [mock_dns_name, mock_ip_address, mock_email]
                
                def mock_get_extension_for_oid(oid):
                    if oid == x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                        return mock_san_ext
                    else:
                        raise x509.ExtensionNotFound('Extension not found', oid)
                
                mock_cert.extensions.get_extension_for_oid.side_effect = mock_get_extension_for_oid
                mock_load_cert.return_value = mock_cert
                
                log_entry = CertificateLog(test_cert_pem, 'client')
                
                # Verify Subject Alternative Names are processed correctly
                expected_sans = ["DNS:example.com", "IP:192.168.1.1", "email:test@example.com"]
                assert log_entry.subject_alt_names == json.dumps(expected_sans)
    
    def test_certificate_log_key_usage_processing(self, app):
        """Test Key Usage processing - lines 172, 174, 176."""
        from unittest.mock import patch, MagicMock
        from cryptography import x509
        import json
        
        test_cert_pem = """-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAJqz1VhQm1GEMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCXRl
c3QgY2VydDAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBQxEjAQBgNV
BAMMCXRlc3QgY2VydDBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC5XULZzsZIGwHI
VUkQzqzFLvv9HcKO8aDc0hQGb0J9sYg3f6fNztWzGrKzLrEhMQSj5tQFbgB8rqL3
TvOt7J3xAgMBAAEwDQYJKoZIhvcNAQELBQADQQAGVDJVtBVYX9FQWM8lx0fRH2wt
vNY3M/KqQv2zV8CcmXrWXg8kcK1vXY4dZJhHhj4VqRZbFxzHdR9hNl8pKqR3
-----END CERTIFICATE-----"""
        
        with app.app_context():
            with patch('cryptography.x509.load_pem_x509_certificate') as mock_load_cert:
                mock_cert = MagicMock()
                mock_cert.serial_number = 12345
                mock_cert.fingerprint.return_value.hex.return_value.upper.return_value = 'ABCDEF123456'
                
                # Mock subject and issuer
                mock_subject = MagicMock()
                mock_subject.get_attributes_for_oid.return_value = [MagicMock(value='Test Subject')]
                mock_cert.subject = mock_subject
                
                mock_issuer = MagicMock()
                mock_issuer.get_attributes_for_oid.return_value = [MagicMock(value='Test Issuer')]
                mock_cert.issuer = mock_issuer
                
                # Mock validity dates
                mock_cert.not_valid_before_utc = datetime.now(timezone.utc)
                mock_cert.not_valid_after_utc = datetime.now(timezone.utc)
                
                # Mock public key with key_size
                mock_public_key = MagicMock()
                mock_public_key.key_size = 2048
                mock_cert.public_key.return_value = mock_public_key
                
                mock_cert.signature_algorithm_oid._name = 'sha256WithRSAEncryption'
                
                # Mock Key Usage extension - lines 172, 174, 176
                mock_ku_ext = MagicMock()
                mock_ku_value = MagicMock()
                mock_ku_value.digital_signature = True  # line 172
                mock_ku_value.key_encipherment = True   # line 174
                mock_ku_value.key_agreement = True      # line 176
                mock_ku_value.key_cert_sign = False
                mock_ku_value.crl_sign = False
                mock_ku_ext.value = mock_ku_value
                
                def mock_get_extension_for_oid(oid):
                    if oid == x509.oid.ExtensionOID.KEY_USAGE:
                        return mock_ku_ext
                    else:
                        raise x509.ExtensionNotFound('Extension not found', oid)
                
                mock_cert.extensions.get_extension_for_oid.side_effect = mock_get_extension_for_oid
                mock_load_cert.return_value = mock_cert
                
                log_entry = CertificateLog(test_cert_pem, 'client')
                
                # Verify Key Usage are processed correctly
                expected_key_usage = ["digital_signature", "key_encipherment", "key_agreement"]
                assert log_entry.key_usage == json.dumps(expected_key_usage)
    
    def test_certificate_log_key_usage_not_found(self, app):
        """Test Key Usage extension not found - lines 183-184."""
        from unittest.mock import patch, MagicMock
        from cryptography import x509
        
        test_cert_pem = """-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAJqz1VhQm1GEMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCXRl
c3QgY2VydDAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBQxEjAQBgNV
BAMMCXRlc3QgY2VydDBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC5XULZzsZIGwHI
VUkQzqzFLvv9HcKO8aDc0hQGb0J9sYg3f6fNztWzGrKzLrEhMQSj5tQFbgB8rqL3
TvOt7J3xAgMBAAEwDQYJKoZIhvcNAQELBQADQQAGVDJVtBVYX9FQWM8lx0fRH2wt
vNY3M/KqQv2zV8CcmXrWXg8kcK1vXY4dZJhHhj4VqRZbFxzHdR9hNl8pKqR3
-----END CERTIFICATE-----"""
        
        with app.app_context():
            with patch('cryptography.x509.load_pem_x509_certificate') as mock_load_cert:
                mock_cert = MagicMock()
                mock_cert.serial_number = 12345
                mock_cert.fingerprint.return_value.hex.return_value.upper.return_value = 'ABCDEF123456'
                
                # Mock subject and issuer
                mock_subject = MagicMock()
                mock_subject.get_attributes_for_oid.return_value = [MagicMock(value='Test Subject')]
                mock_cert.subject = mock_subject
                
                mock_issuer = MagicMock()
                mock_issuer.get_attributes_for_oid.return_value = [MagicMock(value='Test Issuer')]
                mock_cert.issuer = mock_issuer
                
                # Mock validity dates
                mock_cert.not_valid_before_utc = datetime.now(timezone.utc)
                mock_cert.not_valid_after_utc = datetime.now(timezone.utc)
                
                # Mock public key with key_size
                mock_public_key = MagicMock()
                mock_public_key.key_size = 2048
                mock_cert.public_key.return_value = mock_public_key
                
                mock_cert.signature_algorithm_oid._name = 'sha256WithRSAEncryption'
                
                # Mock no Key Usage extension - lines 183-184
                def mock_extension_not_found(oid):
                    raise x509.ExtensionNotFound('Extension not found', oid)
                mock_cert.extensions.get_extension_for_oid.side_effect = mock_extension_not_found
                
                mock_load_cert.return_value = mock_cert
                
                log_entry = CertificateLog(test_cert_pem, 'client')
                
                # Verify Key Usage is None when extension not found
                assert log_entry.key_usage is None
    
    def test_certificate_log_extended_key_usage_processing(self, app):
        """Test Extended Key Usage processing - lines 189-200."""
        from unittest.mock import patch, MagicMock
        from cryptography import x509
        import json
        
        test_cert_pem = """-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAJqz1VhQm1GEMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCXRl
c3QgY2VydDAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBQxEjAQBgNV
BAMMCXRlc3QgY2VydDBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC5XULZzsZIGwHI
VUkQzqzFLvv9HcKO8aDc0hQGb0J9sYg3f6fNztWzGrKzLrEhMQSj5tQFbgB8rqL3
TvOt7J3xAgMBAAEwDQYJKoZIhvcNAQELBQADQQAGVDJVtBVYX9FQWM8lx0fRH2wt
vNY3M/KqQv2zV8CcmXrWXg8kcK1vXY4dZJhHhj4VqRZbFxzHdR9hNl8pKqR3
-----END CERTIFICATE-----"""
        
        with app.app_context():
            with patch('cryptography.x509.load_pem_x509_certificate') as mock_load_cert:
                mock_cert = MagicMock()
                mock_cert.serial_number = 12345
                mock_cert.fingerprint.return_value.hex.return_value.upper.return_value = 'ABCDEF123456'
                
                # Mock subject and issuer
                mock_subject = MagicMock()
                mock_subject.get_attributes_for_oid.return_value = [MagicMock(value='Test Subject')]
                mock_cert.subject = mock_subject
                
                mock_issuer = MagicMock()
                mock_issuer.get_attributes_for_oid.return_value = [MagicMock(value='Test Issuer')]
                mock_cert.issuer = mock_issuer
                
                # Mock validity dates
                mock_cert.not_valid_before_utc = datetime.now(timezone.utc)
                mock_cert.not_valid_after_utc = datetime.now(timezone.utc)
                
                # Mock public key with key_size
                mock_public_key = MagicMock()
                mock_public_key.key_size = 2048
                mock_cert.public_key.return_value = mock_public_key
                
                mock_cert.signature_algorithm_oid._name = 'sha256WithRSAEncryption'
                
                # Mock Extended Key Usage extension - lines 189-200
                mock_eku_ext = MagicMock()
                mock_eku_ext.value = [
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,      # line 191-192
                    x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,      # line 193-194
                    x509.oid.ExtendedKeyUsageOID.CODE_SIGNING,     # line 195-196
                    x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION  # line 197-198
                ]
                
                def mock_get_extension_for_oid(oid):
                    if oid == x509.oid.ExtensionOID.EXTENDED_KEY_USAGE:
                        return mock_eku_ext
                    else:
                        raise x509.ExtensionNotFound('Extension not found', oid)
                
                mock_cert.extensions.get_extension_for_oid.side_effect = mock_get_extension_for_oid
                mock_load_cert.return_value = mock_cert
                
                log_entry = CertificateLog(test_cert_pem, 'client')
                
                # Verify Extended Key Usage are processed correctly
                expected_eku = ["client_auth", "server_auth", "code_signing", "email_protection"]
                assert log_entry.extended_key_usage == json.dumps(expected_eku)
    
    def test_certificate_log_to_dict_with_extensions(self, app):
        """Test to_dict includes extensions - lines 248, 252."""
        from unittest.mock import patch, MagicMock
        from cryptography import x509
        import json
        
        test_cert_pem = """-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAJqz1VhQm1GEMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCXRl
c3QgY2VydDAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBQxEjAQBgNV
BAMMCXRlc3QgY2VydDBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC5XULZzsZIGwHI
VUkQzqzFLvv9HcKO8aDc0hQGb0J9sYg3f6fNztWzGrKzLrEhMQSj5tQFbgB8rqL3
TvOt7J3xAgMBAAEwDQYJKoZIhvcNAQELBQADQQAGVDJVtBVYX9FQWM8lx0fRH2wt
vNY3M/KqQv2zV8CcmXrWXg8kcK1vXY4dZJhHhj4VqRZbFxzHdR9hNl8pKqR3
-----END CERTIFICATE-----"""
        
        with app.app_context():
            with patch('cryptography.x509.load_pem_x509_certificate') as mock_load_cert:
                mock_cert = MagicMock()
                mock_cert.serial_number = 12345
                mock_cert.fingerprint.return_value.hex.return_value.upper.return_value = 'ABCDEF123456'
                
                # Mock subject and issuer
                mock_subject = MagicMock()
                mock_subject.get_attributes_for_oid.return_value = [MagicMock(value='Test Subject')]
                mock_cert.subject = mock_subject
                
                mock_issuer = MagicMock()
                mock_issuer.get_attributes_for_oid.return_value = [MagicMock(value='Test Issuer')]
                mock_cert.issuer = mock_issuer
                
                # Mock validity dates
                mock_cert.not_valid_before_utc = datetime.now(timezone.utc)
                mock_cert.not_valid_after_utc = datetime.now(timezone.utc)
                
                # Mock public key with key_size
                mock_public_key = MagicMock()
                mock_public_key.key_size = 2048
                mock_cert.public_key.return_value = mock_public_key
                
                mock_cert.signature_algorithm_oid._name = 'sha256WithRSAEncryption'
                
                # Mock both SAN and Extended Key Usage extensions
                mock_san_ext = MagicMock()
                mock_dns_name = MagicMock(spec=x509.DNSName)
                mock_dns_name.value = 'test.example.com'
                mock_san_ext.value = [mock_dns_name]
                
                mock_eku_ext = MagicMock()
                mock_eku_ext.value = [x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]
                
                def mock_get_extension_for_oid(oid):
                    if oid == x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                        return mock_san_ext
                    elif oid == x509.oid.ExtensionOID.EXTENDED_KEY_USAGE:
                        return mock_eku_ext
                    else:
                        raise x509.ExtensionNotFound('Extension not found', oid)
                
                mock_cert.extensions.get_extension_for_oid.side_effect = mock_get_extension_for_oid
                mock_load_cert.return_value = mock_cert
                
                log_entry = CertificateLog(test_cert_pem, 'client')
                result_dict = log_entry.to_dict()
                
                # Verify extensions are included in to_dict - lines 248, 252
                assert 'subject_alt_names' in result_dict  # line 248
                assert result_dict['subject_alt_names'] == ["DNS:test.example.com"]
                assert 'extended_key_usage' in result_dict  # line 252
                assert result_dict['extended_key_usage'] == ["client_auth"]
    
    def test_get_certificates_by_subject_method(self, app, sample_cert_data):
        """Test get_certificates_by_subject method - line 308."""
        with app.app_context():
            log_entry = CertificateLog.log_certificate(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type']
            )
            
            subject_cn = log_entry.subject_common_name
            certificates = CertificateLog.get_certificates_by_subject(subject_cn)
            
            assert len(certificates) >= 1
            assert certificates[0].subject_common_name == subject_cn
    
    def test_get_recent_certificates_with_filter(self, app, sample_cert_data):
        """Test get_recent_certificates with certificate_type filter - lines 313-316."""
        with app.app_context():
            CertificateLog.log_certificate(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type']
            )
            
            # Test with certificate_type filter - lines 314-315
            client_certificates = CertificateLog.get_recent_certificates(limit=10, certificate_type='client')
            assert len(client_certificates) >= 1
            assert all(cert.certificate_type == 'client' for cert in client_certificates)
            
            # Test without filter
            all_certificates = CertificateLog.get_recent_certificates(limit=10)
            assert len(all_certificates) >= 1
    
    def test_certificate_log_repr(self, app, sample_cert_data):
        """Test __repr__ method - line 319."""
        with app.app_context():
            log_entry = CertificateLog(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type']
            )
            
            repr_str = repr(log_entry)
            assert 'CertificateLog' in repr_str
            assert log_entry.subject_common_name in repr_str
            assert log_entry.certificate_type in repr_str
    
    def test_get_revoked_certificates_with_limit(self, app, sample_cert_data):
        """Test get_revoked_certificates with limit parameter - line 348."""
        import secrets
        with app.app_context():
            cert_pem = sample_cert_data['certificate_pem']
            
            # Create 5 revoked certificates with unique fingerprints and serial numbers
            for i in range(5):
                cert_log = CertificateLog(cert_pem, 'client')
                cert_log.subject_common_name = f'test{i}.example.com'
                cert_log.fingerprint_sha256 = f'REVOKED_{i}_{secrets.token_hex(20)}'
                cert_log.serial_number = f'REV{i}{secrets.token_hex(8)}'
                cert_log.revoked_at = datetime.now(timezone.utc)
                db.session.add(cert_log)
            
            # Create 1 non-revoked certificate
            active_cert = CertificateLog(cert_pem, 'client')
            active_cert.subject_common_name = 'active.example.com'
            active_cert.fingerprint_sha256 = f'ACTIVE_{secrets.token_hex(20)}'
            active_cert.serial_number = f'ACT{secrets.token_hex(8)}'
            db.session.add(active_cert)
            
            db.session.commit()
            
            # Test without limit (should return all 5 revoked)
            all_revoked = CertificateLog.get_revoked_certificates()
            assert len(all_revoked) == 5
            
            # Test with limit=3 (should return only 3) - this tests line 348
            limited_revoked = CertificateLog.get_revoked_certificates(limit=3)
            assert len(limited_revoked) == 3
    
    def test_can_be_revoked_property(self, app, sample_cert_data):
        """Test can_be_revoked property - line 404."""
        import secrets
        with app.app_context():
            cert_pem = sample_cert_data['certificate_pem']
            
            # Test active certificate (can be revoked)
            active_cert = CertificateLog(cert_pem, 'client')
            active_cert.subject_common_name = 'active.example.com'
            active_cert.fingerprint_sha256 = f'ACTIVE_{secrets.token_hex(20)}'
            active_cert.serial_number = f'ACT{secrets.token_hex(8)}'
            assert active_cert.can_be_revoked() is True  # Tests line 404: return self.revoked_at is None
            
            # Test revoked certificate (cannot be revoked)
            revoked_cert = CertificateLog(cert_pem, 'client')
            revoked_cert.subject_common_name = 'revoked.example.com'  
            revoked_cert.fingerprint_sha256 = f'REVOKED_{secrets.token_hex(20)}'
            revoked_cert.serial_number = f'REV{secrets.token_hex(8)}'
            revoked_cert.revoked_at = datetime.now(timezone.utc)
            assert revoked_cert.can_be_revoked() is False  # Tests line 404: return self.revoked_at is None

    def test_get_latest_certificates_invalid_from_date(self, app, sample_cert_data):
        """Test get_latest_certificates with invalid from_date format - lines 397-398."""
        with app.app_context():
            # Create a test certificate
            log_entry = CertificateLog.log_certificate(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type']
            )
            
            # Test with invalid from_date - should trigger ValueError exception and pass silently
            filters = {
                'from_date': 'invalid-date-format'  # This will cause ValueError in datetime.fromisoformat
            }
            
            # The method should handle the ValueError and continue without the date filter
            certificates_data, total_count = CertificateLog.get_latest_certificates(filters=filters)
            
            # Should return results (not crash) - invalid date filter is ignored
            assert total_count >= 1
            assert len(certificates_data) >= 1

    def test_get_latest_certificates_invalid_to_date(self, app, sample_cert_data):
        """Test get_latest_certificates with invalid to_date format - lines 403-404."""
        with app.app_context():
            # Create a test certificate
            log_entry = CertificateLog.log_certificate(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type']
            )

            # Test with invalid to_date - should trigger ValueError exception and pass silently
            filters = {
                'to_date': 'not-a-valid-date'  # This will cause ValueError in datetime.fromisoformat
            }

            # The method should handle the ValueError and continue without the date filter
            certificates_data, total_count = CertificateLog.get_latest_certificates(filters=filters)

            # Should return results (not crash) - invalid date filter is ignored
            assert total_count >= 1
            assert len(certificates_data) >= 1

    def test_to_dict_with_extra_metadata_attributes(self, app, sample_cert_data):
        """Test to_dict with extra metadata attributes - lines 303, 306."""
        with app.app_context():
            log_entry = CertificateLog(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type']
            )

            # Manually set extra metadata attributes that would trigger lines 303, 306
            log_entry.user_email = 'test@example.com'
            log_entry.os_version = 'Windows 10'
            log_entry.browser = 'Chrome'
            log_entry.browser_version = '91.0.4472.124'
            log_entry.is_mobile = False
            log_entry.request_timestamp = datetime.now(timezone.utc)

            # Also set an attribute to None to test the conditional
            log_entry.user_agent = None  # This should not be included in extra_metadata

            result = log_entry.to_dict()

            # Verify that extra metadata attributes are included in requester_info
            assert 'requester_info' in result
            requester_info = result['requester_info']

            # These should be added via lines 303, 306
            assert requester_info['user_email'] == 'test@example.com'
            assert requester_info['os_version'] == 'Windows 10'
            assert requester_info['browser'] == 'Chrome'
            assert requester_info['browser_version'] == '91.0.4472.124'
            assert requester_info['is_mobile'] is False
            assert 'request_timestamp' in requester_info

            # user_agent should still be None in base requester_info (not overwritten by extra_metadata)
            assert requester_info['user_agent'] is None

    def test_to_dict_without_extra_metadata_attributes(self, app, sample_cert_data):
        """Test to_dict without extra metadata attributes to ensure lines 303, 306 are not reached."""
        with app.app_context():
            log_entry = CertificateLog(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type']
            )

            # Ensure none of the extra metadata attributes are set
            # Note: We don't need to explicitly delete them since they weren't set in the first place
            # The test is to verify that these attributes don't exist, so lines 303, 306 are not reached

            result = log_entry.to_dict()

            # Verify that basic requester_info is still present
            assert 'requester_info' in result
            requester_info = result['requester_info']

            # Should only have the basic fields, no extra metadata
            expected_keys = {'ip', 'country', 'user_agent', 'os'}
            assert set(requester_info.keys()) == expected_keys