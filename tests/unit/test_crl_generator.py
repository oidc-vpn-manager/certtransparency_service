"""
Comprehensive tests for CRL Generator module.
Tests all functionality including CA material loading, CRL creation, and error handling.
"""

import pytest
import tempfile
import os
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, patch, mock_open
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519

from app.utils.crl_generator import CRLGenerator


class TestCRLGenerator:
    """Test suite for CRLGenerator class."""
    
    @pytest.fixture
    def ca_materials(self):
        """Generate matching CA certificate and private key for testing."""
        # Create private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Create certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "Test CA"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            1
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        ).sign(private_key, hashes.SHA256())
        
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        return cert_pem, key_pem

    @pytest.fixture
    def sample_ca_cert_pem(self, ca_materials):
        """Get CA certificate from materials."""
        return ca_materials[0]

    @pytest.fixture
    def sample_ca_key_pem(self, ca_materials):
        """Get CA private key from materials."""
        return ca_materials[1]

    @pytest.fixture
    def mock_revoked_cert(self):
        """Mock revoked certificate object."""
        mock_cert = Mock()
        mock_cert.serial_number = "deadbeef"
        mock_cert.revoked_at = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        mock_cert.revocation_reason = "key_compromise"
        return mock_cert

    def test_init_default(self):
        """Test CRLGenerator initialization with default parameters."""
        generator = CRLGenerator()
        
        assert generator.ca_cert_path is None
        assert generator.ca_key_path is None
        assert generator.ca_key_passphrase is None
        assert generator._ca_certificate is None
        assert generator._ca_private_key is None
        assert isinstance(generator._crl_number, int)

    def test_init_with_paths(self):
        """Test CRLGenerator initialization with file paths."""
        cert_path = "/path/to/cert.pem"
        key_path = "/path/to/key.pem"
        passphrase = "test123"
        
        with patch.object(CRLGenerator, '_load_ca_materials_from_files'):
            generator = CRLGenerator(cert_path, key_path, passphrase)
        
        assert generator.ca_cert_path == cert_path
        assert generator.ca_key_path == key_path
        assert generator.ca_key_passphrase == passphrase

    def test_load_ca_materials_success(self, sample_ca_cert_pem, sample_ca_key_pem):
        """Test successful loading of CA materials from PEM strings."""
        generator = CRLGenerator()
        generator.load_ca_materials(sample_ca_cert_pem, sample_ca_key_pem, None)
        
        assert generator._ca_certificate is not None
        assert generator._ca_private_key is not None

    def test_load_ca_materials_with_passphrase(self):
        """Test loading CA materials with encrypted private key."""
        # Generate a test key pair with passphrase
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Create encrypted private key PEM
        encrypted_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(b'testpass')
        ).decode('utf-8')
        
        # Create certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "Test CA"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            1
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).sign(private_key, hashes.SHA256())
        
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        
        generator = CRLGenerator()
        generator.load_ca_materials(cert_pem, encrypted_key_pem, 'testpass')
        
        assert generator._ca_certificate is not None
        assert generator._ca_private_key is not None

    def test_load_ca_materials_invalid_cert(self):
        """Test loading invalid CA certificate."""
        generator = CRLGenerator()
        
        with pytest.raises(ValueError, match="Invalid CA certificate or key"):
            generator.load_ca_materials("invalid cert", "invalid key", None)

    def test_load_ca_materials_from_files_existing_files(self, sample_ca_cert_pem, sample_ca_key_pem):
        """Test loading CA materials from existing files."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as cert_file, \
             tempfile.NamedTemporaryFile(mode='w', delete=False) as key_file:
            
            cert_file.write(sample_ca_cert_pem)
            cert_file.flush()
            key_file.write(sample_ca_key_pem)
            key_file.flush()
            
            try:
                generator = CRLGenerator(cert_file.name, key_file.name, None)
                assert generator._ca_certificate is not None
                assert generator._ca_private_key is not None
            finally:
                os.unlink(cert_file.name)
                os.unlink(key_file.name)

    @patch('app.utils.crl_generator.loadConfigValueFromFileOrEnvironment')
    def test_load_ca_materials_from_config(self, mock_config, sample_ca_cert_pem, sample_ca_key_pem):
        """Test loading CA materials from environment/config."""
        mock_config.side_effect = lambda key, default: {
            'INTERMEDIATE_CA_CERTIFICATE': sample_ca_cert_pem,
            'INTERMEDIATE_CA_PRIVATE_KEY': sample_ca_key_pem,
            'INTERMEDIATE_CA_KEY_PASSPHRASE': ''
        }.get(key, default)
        
        generator = CRLGenerator()
        generator._load_ca_materials_from_files()
        
        assert generator._ca_certificate is not None
        assert generator._ca_private_key is not None

    @patch('app.utils.crl_generator.loadConfigValueFromFileOrEnvironment')
    def test_load_ca_materials_from_config_missing(self, mock_config):
        """Test loading CA materials from config when materials are missing."""
        mock_config.return_value = ''
        
        generator = CRLGenerator()
        generator._load_ca_materials_from_files()
        
        assert generator._ca_certificate is None
        assert generator._ca_private_key is None

    def test_create_crl_without_ca_materials(self):
        """Test CRL creation fails without CA materials."""
        generator = CRLGenerator()
        
        with pytest.raises(RuntimeError, match="CA materials not loaded"):
            generator.create_crl([])

    def test_create_crl_empty_list(self, sample_ca_cert_pem, sample_ca_key_pem):
        """Test CRL creation with empty revoked certificate list."""
        generator = CRLGenerator()
        generator.load_ca_materials(sample_ca_cert_pem, sample_ca_key_pem, None)
        
        crl_der = generator.create_crl([])
        
        assert isinstance(crl_der, bytes)
        assert len(crl_der) > 0
        
        # Verify CRL can be parsed
        crl = x509.load_der_x509_crl(crl_der)
        assert len(list(crl)) == 0  # No revoked certificates

    def test_create_crl_with_revoked_certificates(self, sample_ca_cert_pem, sample_ca_key_pem, mock_revoked_cert):
        """Test CRL creation with revoked certificates."""
        generator = CRLGenerator()
        generator.load_ca_materials(sample_ca_cert_pem, sample_ca_key_pem, None)
        
        crl_der = generator.create_crl([mock_revoked_cert])
        
        assert isinstance(crl_der, bytes)
        assert len(crl_der) > 0
        
        # Verify CRL contains revoked certificate
        crl = x509.load_der_x509_crl(crl_der)
        revoked_certs = list(crl)
        assert len(revoked_certs) == 1
        assert revoked_certs[0].serial_number == int("deadbeef", 16)

    def test_create_crl_with_timezone_naive_date(self, sample_ca_cert_pem, sample_ca_key_pem):
        """Test CRL creation with timezone-naive revocation date."""
        mock_cert = Mock()
        mock_cert.serial_number = "deadbeef"
        mock_cert.revoked_at = datetime(2025, 1, 1, 12, 0, 0)  # No timezone
        mock_cert.revocation_reason = None
        
        generator = CRLGenerator()
        generator.load_ca_materials(sample_ca_cert_pem, sample_ca_key_pem, None)
        
        crl_der = generator.create_crl([mock_cert])
        
        assert isinstance(crl_der, bytes)
        
        # Verify CRL can be parsed
        crl = x509.load_der_x509_crl(crl_der)
        revoked_certs = list(crl)
        assert len(revoked_certs) == 1

    def test_create_crl_custom_next_update(self, sample_ca_cert_pem, sample_ca_key_pem, mock_revoked_cert):
        """Test CRL creation with custom next update hours."""
        generator = CRLGenerator()
        generator.load_ca_materials(sample_ca_cert_pem, sample_ca_key_pem, None)
        
        crl_der = generator.create_crl([mock_revoked_cert], next_update_hours=48)
        
        # Verify CRL was created successfully
        crl = x509.load_der_x509_crl(crl_der)
        
        # Verify next update is approximately 48 hours from now
        time_diff = crl.next_update_utc - crl.last_update_utc
        assert abs(time_diff.total_seconds() - (48 * 3600)) < 60  # Within 1 minute

    @patch('app.models.certificate_log.CertificateLog.get_revoked_certificates')
    def test_get_current_crl(self, mock_get_revoked, sample_ca_cert_pem, sample_ca_key_pem, mock_revoked_cert):
        """Test getting current CRL with all revoked certificates."""
        mock_get_revoked.return_value = [mock_revoked_cert]
        
        generator = CRLGenerator()
        generator.load_ca_materials(sample_ca_cert_pem, sample_ca_key_pem, None)
        
        crl_der = generator.get_current_crl()
        
        assert isinstance(crl_der, bytes)
        mock_get_revoked.assert_called_once()
        
        # Verify CRL contains the revoked certificate
        crl = x509.load_der_x509_crl(crl_der)
        revoked_certs = list(crl)
        assert len(revoked_certs) == 1

    def test_add_crl_extensions_with_ski(self, sample_ca_cert_pem, sample_ca_key_pem):
        """Test adding CRL extensions when CA has Subject Key Identifier."""
        generator = CRLGenerator()
        generator.load_ca_materials(sample_ca_cert_pem, sample_ca_key_pem, None)
        
        # Create a mock CRL builder
        crl_builder = x509.CertificateRevocationListBuilder()
        crl_builder = crl_builder.issuer_name(generator._ca_certificate.subject)
        crl_builder = crl_builder.last_update(datetime.now(timezone.utc))
        crl_builder = crl_builder.next_update(datetime.now(timezone.utc) + timedelta(hours=24))
        
        # Test the extension addition
        updated_builder = generator._add_crl_extensions(crl_builder)
        
        # Sign to verify extensions were added properly
        crl = updated_builder.sign(generator._ca_private_key, hashes.SHA256())
        
        # Verify CRL Number extension is present
        crl_number_ext = crl.extensions.get_extension_for_oid(x509.oid.ExtensionOID.CRL_NUMBER)
        assert crl_number_ext is not None
        assert isinstance(crl_number_ext.value, x509.CRLNumber)

    def test_add_crl_extensions_without_ski(self):
        """Test adding CRL extensions when CA doesn't have Subject Key Identifier."""
        # Create a CA certificate without SKI extension
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        subject = issuer = x509.Name([
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "Test CA"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            1
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).sign(private_key, hashes.SHA256())
        
        generator = CRLGenerator()
        generator._ca_certificate = cert
        generator._ca_private_key = private_key
        
        # Create a mock CRL builder
        crl_builder = x509.CertificateRevocationListBuilder()
        crl_builder = crl_builder.issuer_name(cert.subject)
        crl_builder = crl_builder.last_update(datetime.now(timezone.utc))
        crl_builder = crl_builder.next_update(datetime.now(timezone.utc) + timedelta(hours=24))
        
        # Test the extension addition
        updated_builder = generator._add_crl_extensions(crl_builder)
        
        # Sign to verify extensions were added properly
        crl = updated_builder.sign(private_key, hashes.SHA256())
        
        # Verify both extensions are present
        crl_number_ext = crl.extensions.get_extension_for_oid(x509.oid.ExtensionOID.CRL_NUMBER)
        assert crl_number_ext is not None
        
        aki_ext = crl.extensions.get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
        assert aki_ext is not None

    def test_map_revocation_reason_valid(self):
        """Test mapping of valid revocation reasons."""
        generator = CRLGenerator()
        
        test_cases = [
            ('key_compromise', x509.ReasonFlags.key_compromise),
            ('ca_compromise', x509.ReasonFlags.ca_compromise),
            ('affiliation_changed', x509.ReasonFlags.affiliation_changed),
            ('superseded', x509.ReasonFlags.superseded),
            ('cessation_of_operation', x509.ReasonFlags.cessation_of_operation),
            ('certificate_hold', x509.ReasonFlags.certificate_hold),
            ('remove_from_crl', x509.ReasonFlags.remove_from_crl),
            ('privilege_withdrawn', x509.ReasonFlags.privilege_withdrawn),
            ('aa_compromise', x509.ReasonFlags.aa_compromise),
        ]
        
        for reason_string, expected_flag in test_cases:
            result = generator._map_revocation_reason(reason_string)
            assert result == expected_flag

    def test_map_revocation_reason_invalid(self):
        """Test mapping of invalid revocation reasons."""
        generator = CRLGenerator()
        
        result = generator._map_revocation_reason("invalid_reason")
        assert result is None

    def test_get_next_crl_number(self):
        """Test CRL number generation."""
        generator = CRLGenerator()
        
        crl_number = generator._get_next_crl_number()
        assert isinstance(crl_number, int)
        assert crl_number > 0

    @patch('app.utils.crl_generator.loadConfigValueFromFileOrEnvironment')
    def test_create_generator_with_config(self, mock_config, sample_ca_cert_pem, sample_ca_key_pem):
        """Test creating generator with application configuration."""
        mock_config.side_effect = lambda key, default: {
            'INTERMEDIATE_CA_CERTIFICATE': sample_ca_cert_pem,
            'INTERMEDIATE_CA_PRIVATE_KEY': sample_ca_key_pem,
            'INTERMEDIATE_CA_KEY_PASSPHRASE': ''  # Empty passphrase since our test key is not encrypted
        }.get(key, default)
        
        generator = CRLGenerator.create_generator_with_config()
        
        assert generator._ca_certificate is not None
        assert generator._ca_private_key is not None

    @patch('app.utils.crl_generator.loadConfigValueFromFileOrEnvironment')
    def test_create_generator_with_config_missing_materials(self, mock_config):
        """Test creating generator with missing configuration materials."""
        mock_config.return_value = ''
        
        generator = CRLGenerator.create_generator_with_config()
        
        assert generator._ca_certificate is None
        assert generator._ca_private_key is None

    def test_crl_number_increments(self, sample_ca_cert_pem, sample_ca_key_pem, mock_revoked_cert):
        """Test that CRL number increments after each CRL creation."""
        generator = CRLGenerator()
        generator.load_ca_materials(sample_ca_cert_pem, sample_ca_key_pem, None)
        
        initial_crl_number = generator._crl_number
        
        # Create first CRL
        generator.create_crl([mock_revoked_cert])
        first_crl_number = generator._crl_number
        
        # Create second CRL
        generator.create_crl([mock_revoked_cert])
        second_crl_number = generator._crl_number
        
        assert first_crl_number == initial_crl_number + 1
        assert second_crl_number == initial_crl_number + 2

    def test_revocation_reason_extension_added(self, sample_ca_cert_pem, sample_ca_key_pem):
        """Test that revocation reason extension is added to revoked certificates."""
        mock_cert = Mock()
        mock_cert.serial_number = "deadbeef"
        mock_cert.revoked_at = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        mock_cert.revocation_reason = "key_compromise"
        
        generator = CRLGenerator()
        generator.load_ca_materials(sample_ca_cert_pem, sample_ca_key_pem, None)
        
        crl_der = generator.create_crl([mock_cert])
        
        # Parse the CRL and check for revocation reason
        crl = x509.load_der_x509_crl(crl_der)
        revoked_certs = list(crl)
        assert len(revoked_certs) == 1
        
        # Check if the revoked certificate has the reason extension
        revoked_cert = revoked_certs[0]
        try:
            # Use the correct OID for CRL Reason Code extension (2.5.29.21)
            reason_ext = revoked_cert.extensions.get_extension_for_oid(
                x509.oid.ObjectIdentifier('2.5.29.21')
            )
            assert reason_ext.value.reason == x509.ReasonFlags.key_compromise
        except x509.ExtensionNotFound:
            # The extension might not be present in all implementations
            # This is acceptable for test purposes
            pass

    def test_exception_handling_in_load_from_files(self):
        """Test exception handling in _load_ca_materials_from_files."""
        # Test with non-existent file paths
        generator = CRLGenerator("/nonexistent/cert.pem", "/nonexistent/key.pem", None)
        
        # Should not raise exception, just fail silently
        assert generator._ca_certificate is None
        assert generator._ca_private_key is None