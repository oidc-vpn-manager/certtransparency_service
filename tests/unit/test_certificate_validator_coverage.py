"""
Comprehensive tests for certificate validator to achieve 100% coverage.
Tests validation functions, error conditions, and security policies.
"""

import pytest
from unittest.mock import Mock, patch
from datetime import datetime, timezone, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, dsa
from flask import Flask

from app.utils.certificate_validator import (
    CertificateValidator,
    CertificateValidationError
)

@pytest.fixture
def flask_app():
    """Create a Flask app with application context for testing."""
    app = Flask(__name__)
    app.config['TESTING'] = True
    with app.app_context():
        yield app


class TestCertificateValidatorInitialization:
    """Test certificate validator initialization and basic functionality."""

    def test_certificate_validator_initialization(self):
        """Test CertificateValidator initialization."""
        validator = CertificateValidator()

        assert validator.validation_errors == []
        assert validator.validation_warnings == []
        assert hasattr(validator, 'MIN_KEY_SIZES')
        assert hasattr(validator, 'MAX_VALIDITY_PERIODS')
        assert hasattr(validator, 'REQUIRED_EXTENSIONS')


class TestPEMFormatValidation:
    """Test PEM format validation functionality - covers lines 120, 123, 130, 141, 146."""

    def test_validate_pem_format_non_string_input(self):
        """Test PEM validation with non-string input - covers line 120."""
        validator = CertificateValidator()

        with pytest.raises(CertificateValidationError, match="Certificate must be a string"):
            validator._validate_pem_format(123)

    def test_validate_pem_format_empty_string(self):
        """Test PEM validation with empty string - covers line 123."""
        validator = CertificateValidator()

        with pytest.raises(CertificateValidationError, match="Certificate PEM is empty"):
            validator._validate_pem_format("")

        with pytest.raises(CertificateValidationError, match="Certificate PEM is empty"):
            validator._validate_pem_format("   ")

    def test_validate_pem_format_missing_end_header(self):
        """Test PEM validation with missing end header - covers line 130."""
        validator = CertificateValidator()

        invalid_pem = "-----BEGIN CERTIFICATE-----\nVGVzdCBjZXJ0aWZpY2F0ZQ=="

        with pytest.raises(CertificateValidationError, match="Missing PEM end header"):
            validator._validate_pem_format(invalid_pem)

    def test_validate_pem_format_invalid_structure(self):
        """Test PEM validation with invalid structure - covers line 141."""
        validator = CertificateValidator()

        invalid_pem = """-----BEGIN CERTIFICATE-----
Invalid base64 content with special chars !@#$%^&*()
-----END CERTIFICATE-----"""

        with pytest.raises(CertificateValidationError, match="Invalid PEM format structure"):
            validator._validate_pem_format(invalid_pem)

    def test_validate_pem_format_multiple_certificates(self):
        """Test PEM validation with multiple certificates - covers line 146."""
        validator = CertificateValidator()

        multiple_certs_pem = """-----BEGIN CERTIFICATE-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
-----END CERTIFICATE-----"""

        with pytest.raises(CertificateValidationError, match="Multiple certificates found \\(2\\), expected single certificate"):
            validator._validate_pem_format(multiple_certs_pem)


class TestCertificateStructureValidation:
    """Test certificate structure validation - covers lines 151-152, 161, 165, 169."""

    def test_certificate_structure_validation_parse_error(self):
        """Test certificate parsing error handling - covers lines 151-152."""
        validator = CertificateValidator()

        # Invalid base64 content that passes regex but fails parsing
        invalid_cert_pem = """-----BEGIN CERTIFICATE-----
VGhpcyBpcyBub3QgYSB2YWxpZCBjZXJ0aWZpY2F0ZQ==
-----END CERTIFICATE-----"""

        with pytest.raises(CertificateValidationError, match="Failed to parse certificate"):
            validator._validate_pem_format(invalid_cert_pem)

    def test_certificate_structure_validation_unknown_type(self, flask_app):
        """Test certificate structure validation with unknown type - covers line 161."""

        # Create a valid certificate for testing
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])

        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            private_key.public_key()
        ).serial_number(12345).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).sign(private_key, hashes.SHA256())

        validator = CertificateValidator()
        validator._validate_certificate_structure(cert, "unknown_type")

        # Should add error for invalid certificate type
        assert any("Invalid certificate type" in error for error in validator.validation_errors)

    def test_certificate_structure_validation_version_check(self, flask_app):
        """Test certificate structure version validation - covers line 169."""

        # Create a certificate and mock version to trigger warning
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])

        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            private_key.public_key()
        ).serial_number(12345).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).sign(private_key, hashes.SHA256())

        # Mock version to not be X509v3
        mock_cert = Mock()
        mock_cert.version = x509.Version.v1
        mock_cert.serial_number = 12345

        validator = CertificateValidator()
        validator._validate_certificate_structure(mock_cert, "client")

        # Should add warning for non-v3 certificate
        assert any("v3" in warning for warning in validator.validation_warnings)

    def test_certificate_structure_validation_serial_number_check(self, flask_app):
        """Test certificate structure serial number validation - covers line 165."""

        # Create a certificate with serial number 0
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])

        # Mock certificate with zero serial number
        mock_cert = Mock()
        mock_cert.version = x509.Version.v3
        mock_cert.serial_number = 0  # Zero serial number

        validator = CertificateValidator()
        validator._validate_certificate_structure(mock_cert, "client")

        # Should add error for serial number 0
        assert any("positive" in error for error in validator.validation_errors)


class TestPublicKeyValidation:
    """Test public key validation functionality - covers lines 178-185, 189-199."""

    def test_public_key_validation_rsa_weak(self, flask_app):
        """Test RSA key validation with weak key size - covers lines 181, 185."""

        # Create certificate with weak RSA key (1024 bit)
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])

        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            private_key.public_key()
        ).serial_number(12345).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).sign(private_key, hashes.SHA256())

        validator = CertificateValidator()
        validator._validate_public_key(cert, "client")

        # Should add error for weak RSA key
        assert any("RSA key size" in error and "2048" in error for error in validator.validation_errors)

    def test_public_key_validation_ec_weak(self, flask_app):
        """Test EC key validation with weak curve - covers lines 189-199."""

        # Create certificate with weak EC key (P-192)
        private_key = ec.generate_private_key(ec.SECP192R1())
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])

        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            private_key.public_key()
        ).serial_number(12345).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).sign(private_key, hashes.SHA256())

        validator = CertificateValidator()
        validator._validate_public_key(cert, "client")

        # Should add error for weak EC key
        assert any("EC key size" in error and "256" in error for error in validator.validation_errors)


class TestValidityPeriodValidation:
    """Test validity period validation - covers lines 207-215."""

    def test_validity_period_validation_expired_certificate(self, flask_app):
        """Test validity period validation with expired certificate - covers line 228."""

        # Create expired certificate
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])

        past_date = datetime.now(timezone.utc) - timedelta(days=365)
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            private_key.public_key()
        ).serial_number(12345).not_valid_before(
            past_date - timedelta(days=30)
        ).not_valid_after(
            past_date  # Expired
        ).sign(private_key, hashes.SHA256())

        validator = CertificateValidator()
        validator._validate_validity_period(cert, "client")

        # Should add warning for expired certificate
        assert any("Certificate has expired" in warning for warning in validator.validation_warnings)

    def test_validity_period_validation_not_yet_valid(self, flask_app):
        """Test validity period validation with not-yet-valid certificate - covers line 225."""

        # Create not-yet-valid certificate
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])

        future_date = datetime.now(timezone.utc) + timedelta(days=30)
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            private_key.public_key()
        ).serial_number(12345).not_valid_before(
            future_date  # Not yet valid
        ).not_valid_after(
            future_date + timedelta(days=365)
        ).sign(private_key, hashes.SHA256())

        validator = CertificateValidator()
        validator._validate_validity_period(cert, "client")

        # Should add warning for not-yet-valid certificate
        assert any("Certificate is not yet valid" in warning for warning in validator.validation_warnings)

    def test_validity_period_validation_too_long(self, flask_app):
        """Test validity period validation with too long period - covers line 243."""

        # Create certificate with validity period too long
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])

        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            private_key.public_key()
        ).serial_number(12345).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=500)  # Too long for client cert (max 395 days)
        ).sign(private_key, hashes.SHA256())

        validator = CertificateValidator()
        validator._validate_validity_period(cert, "client")

        # Should add warning for validity period too long
        assert any("validity period" in warning and "395" in warning for warning in validator.validation_warnings)


class TestExtensionValidation:
    """Test extension validation functionality - covers lines 225, 228, 263, 275-277, 284, 292, 301, 307, 309."""

    def test_extension_validation_missing_required_extensions(self):
        """Test extension validation with missing required extensions - covers line 263."""
        # Create certificate without required extensions
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])

        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            private_key.public_key()
        ).serial_number(12345).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).sign(private_key, hashes.SHA256())

        validator = CertificateValidator()
        validator._validate_extensions(cert, "client")

        # Should add errors for missing required extensions
        assert any("Missing required extension" in error for error in validator.validation_errors)

    def test_extension_validation_ed25519_test_certificate(self):
        """Test extension validation with Ed25519 test certificate - covers lines 275-277."""
        # Create Ed25519 certificate with minimal extensions (test certificate)
        private_key = ed25519.Ed25519PrivateKey.generate()
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])

        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            private_key.public_key()
        ).serial_number(12345).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).sign(private_key, None)  # Ed25519 doesn't need hash algorithm

        validator = CertificateValidator()
        validator._validate_extensions(cert, "client")

        # Should add warnings for test certificate missing extensions
        assert any("Test certificate missing extension" in warning for warning in validator.validation_warnings)

    def test_key_usage_validation_missing_key_usage(self, flask_app):
        """Test key usage validation when extension is missing - covers line 276."""
        extensions = {}  # No extensions
        validator = CertificateValidator()
        validator._validate_key_usage(extensions, "client", is_test_cert=False)

        # Should not add any warning since extension is missing
        # This tests the return path on line 276-277
        assert len(validator.validation_warnings) == 0

    def test_key_usage_validation_client_certificate(self):
        """Test key usage validation for client certificate - covers line 292."""
        # Create key usage extension without required usage
        key_usage = x509.KeyUsage(
            digital_signature=False,  # Missing required usage
            key_encipherment=True,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            content_commitment=False,
            data_encipherment=False,
            encipher_only=False,
            decipher_only=False
        )

        extensions = {ExtensionOID.KEY_USAGE: x509.Extension(ExtensionOID.KEY_USAGE, True, key_usage)}
        validator = CertificateValidator()
        validator._validate_key_usage(extensions, "client", is_test_cert=False)

        # Should add error for missing digital signature
        assert any("Client certificates must have digital_signature" in error for error in validator.validation_errors)

    def test_extended_key_usage_validation_missing_extension(self, flask_app):
        """Test extended key usage validation when extension is missing - covers line 316."""
        extensions = {}  # No extensions
        validator = CertificateValidator()
        validator._validate_extended_key_usage(extensions, "client", is_test_cert=False)

        # Should not add any warning since extension is missing
        # This tests the return path on line 316-317
        assert len(validator.validation_warnings) == 0

    def test_basic_constraints_validation_intermediate_ca(self, flask_app):
        """Test basic constraints validation for intermediate CA - covers line 355."""
        # Create basic constraints that are not CA
        basic_constraints = x509.BasicConstraints(ca=False, path_length=None)
        extensions = {ExtensionOID.BASIC_CONSTRAINTS: x509.Extension(ExtensionOID.BASIC_CONSTRAINTS, True, basic_constraints)}

        validator = CertificateValidator()
        validator._validate_basic_constraints(extensions, "intermediate")

        # Should add error for intermediate CA without CA=true
        assert any("CA flag set to True" in error for error in validator.validation_errors)

    def test_basic_constraints_validation_end_entity_with_ca_true(self, flask_app):
        """Test basic constraints validation for end entity with CA=true - covers line 358."""
        # Create basic constraints with CA=true for client certificate
        basic_constraints = x509.BasicConstraints(ca=True, path_length=None)
        extensions = {ExtensionOID.BASIC_CONSTRAINTS: x509.Extension(ExtensionOID.BASIC_CONSTRAINTS, True, basic_constraints)}

        validator = CertificateValidator()
        validator._validate_basic_constraints(extensions, "client")

        # Should add warning for end entity certificate with CA=true
        assert any("CA flag set" in warning for warning in validator.validation_warnings)


class TestSubjectIssuerValidation:
    """Test subject and issuer field validation - covers lines 319-335, 341-343, 350, 355."""

    def test_subject_issuer_validation_empty_subject(self, flask_app):
        """Test subject validation with empty subject - covers line 398."""
        # Create certificate with empty subject
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([])  # Empty subject
        issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])

        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            private_key.public_key()
        ).serial_number(12345).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).sign(private_key, hashes.SHA256())

        validator = CertificateValidator()
        validator._validate_subject_issuer_fields(cert, "client")

        # Should add error for missing subject common name
        assert any("Subject Common Name is missing" in error for error in validator.validation_errors)

    def test_subject_issuer_validation_empty_issuer(self, flask_app):
        """Test issuer validation with empty issuer - covers line 406."""
        # Create certificate with empty issuer
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])
        issuer = x509.Name([])  # Empty issuer

        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            private_key.public_key()
        ).serial_number(12345).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).sign(private_key, hashes.SHA256())

        validator = CertificateValidator()
        validator._validate_subject_issuer_fields(cert, "client")

        # Should add error for missing issuer common name
        assert any("Issuer Common Name is missing" in error for error in validator.validation_errors)

    # NOTE: test_subject_issuer_validation_long_common_name removed
    # The cryptography library prevents creation of NameAttribute with CN > 64 chars
    # This validation is enforced at the cryptography library level (line 152 in name.py)
    # making it impossible to test the application-level validation code path (line 396)
    # The library constraint provides equivalent protection.

    # NOTE: test_subject_issuer_validation_empty_common_name removed
    # The cryptography library prevents creation of NameAttribute with empty CN
    # This validation is enforced at the cryptography library level (line 152 in name.py)
    # making it impossible to test the application-level validation code path (line 394)
    # The library constraint provides equivalent protection.


class TestSignatureAlgorithmValidation:
    """Test signature algorithm validation - covers lines 368-383, 394, 396-398."""

    def test_signature_algorithm_validation_weak_algorithm(self, flask_app):
        """Test signature algorithm validation with weak algorithm - covers line 416."""
        # Mock certificate with weak signature algorithm
        mock_cert = Mock()
        mock_cert.signature_algorithm_oid._name = "md5WithRSAEncryption"

        validator = CertificateValidator()
        validator._validate_signature_algorithm(mock_cert)

        # Should add error for weak signature algorithm
        assert any("Weak signature algorithm" in error for error in validator.validation_errors)

    def test_signature_algorithm_validation_rsa_with_sha1(self, flask_app):
        """Test signature algorithm validation with RSA SHA1 - covers line 416."""
        # Mock certificate with SHA1 signature algorithm
        mock_cert = Mock()
        mock_cert.signature_algorithm_oid._name = "sha1WithRSAEncryption"

        validator = CertificateValidator()
        validator._validate_signature_algorithm(mock_cert)

        # Should add error for weak signature algorithm
        assert any("Weak signature algorithm" in error for error in validator.validation_errors)

    def test_signature_algorithm_validation_unknown_algorithm(self, flask_app):
        """Test signature algorithm validation with unknown algorithm - covers line 422."""
        # Mock certificate with unknown signature algorithm
        mock_cert = Mock()
        mock_cert.signature_algorithm_oid._name = "unknownWithRSAEncryption"

        validator = CertificateValidator()
        validator._validate_signature_algorithm(mock_cert)

        # Should add warning for unknown signature algorithm
        assert any("may not be optimal" in warning for warning in validator.validation_warnings)


class TestValidationErrors:
    """Test validation error and warning handling - covers lines 101-103."""

    def test_validation_with_errors_raises_exception(self, flask_app):
        """Test that validation errors cause exception to be raised - covers lines 102-103."""
        # Create a certificate that will fail validation
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)  # Weak key
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])

        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            private_key.public_key()
        ).serial_number(12345).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).sign(private_key, hashes.SHA256())

        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        validator = CertificateValidator()

        with pytest.raises(CertificateValidationError, match="Certificate validation failed"):
            validator.validate_certificate(cert_pem, "client")


class TestDSAKeyValidation:
    """Test DSA key validation - covers lines 404-406, 416-417."""

    def test_dsa_key_validation_weak_key_size(self):
        """Test DSA key validation with weak key size - covers lines 404-406."""
        # Create certificate with weak DSA key
        private_key = dsa.generate_private_key(key_size=1024)  # Weak key size
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])

        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            private_key.public_key()
        ).serial_number(12345).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).sign(private_key, hashes.SHA256())

        validator = CertificateValidator()
        validator._validate_public_key(cert, "client")

        # Should add error for weak DSA key
        assert any("DSA key size" in error and "2048" in error for error in validator.validation_errors)

    def test_unknown_key_type_validation(self, flask_app):
        """Test validation with unknown key type - covers lines 215."""
        # Mock certificate with unknown key type
        mock_cert = Mock()
        mock_public_key = Mock()
        mock_public_key.__class__.__name__ = "UnknownPublicKey"
        mock_cert.public_key.return_value = mock_public_key

        validator = CertificateValidator()
        validator._validate_public_key(mock_cert, "client")

        # Should add warning for unknown key type
        assert any("Unknown" in warning or "unsupported" in warning for warning in validator.validation_warnings)


class TestCompleteValidationWorkflow:
    """Test complete validation workflow - covers lines 426-431."""

    def test_validation_with_warnings_only(self, flask_app):
        """Test complete validation with warnings but no errors - covers lines 106-115."""
        # Create a valid certificate with extensions to pass validation
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])

        # Create certificate with required extensions but long validity period
        cert_builder = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            private_key.public_key()
        ).serial_number(12345).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=500)  # Too long, will generate warning
        )

        # Add required extensions for client certificate
        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        ).add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False
        )

        cert = cert_builder.sign(private_key, hashes.SHA256())
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

        validator = CertificateValidator()
        result_cert, validation_results = validator.validate_certificate(cert_pem, "client")

        # Should complete successfully with warnings
        assert result_cert is not None
        assert validation_results['status'] == 'valid'
        assert len(validation_results['warnings']) > 0
        assert len(validation_results['errors']) == 0


class TestCertificateValidatorWithoutFlask:
    """Test certificate validator with Flask dependencies."""

    def test_validate_pem_format_successful_parsing(self):
        """Test successful PEM parsing - covers lines 149-156."""
        # Create a valid certificate for testing PEM parsing
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])

        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            private_key.public_key()
        ).serial_number(12345).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).sign(private_key, hashes.SHA256())

        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

        validator = CertificateValidator()
        parsed_cert = validator._validate_pem_format(cert_pem)

        assert parsed_cert is not None
        assert parsed_cert.serial_number == 12345

    def test_certificate_structure_validation_successful(self):
        """Test successful certificate structure validation."""
        # Create a valid certificate
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])

        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            private_key.public_key()
        ).serial_number(12345).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).sign(private_key, hashes.SHA256())

        validator = CertificateValidator()
        validator._validate_certificate_structure(cert, "client")

        # Should complete without errors for valid certificate
        assert len(validator.validation_errors) == 0

    def test_public_key_validation_successful(self):
        """Test successful public key validation."""
        # Create certificate with strong RSA key
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])

        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            private_key.public_key()
        ).serial_number(12345).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).sign(private_key, hashes.SHA256())

        validator = CertificateValidator()
        validator._validate_public_key(cert, "client")

        # Should complete without errors for strong RSA key
        assert len(validator.validation_errors) == 0

    def test_validity_period_validation_successful(self):
        """Test successful validity period validation."""
        # Create certificate with valid period
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])

        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            private_key.public_key()
        ).serial_number(12345).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)  # Valid 1-year period
        ).sign(private_key, hashes.SHA256())

        validator = CertificateValidator()
        validator._validate_validity_period(cert, "client")

        # Should complete without errors for valid period
        assert len(validator.validation_errors) == 0

    def test_signature_algorithm_validation_successful(self):
        """Test successful signature algorithm validation."""
        # Create certificate with strong signature algorithm
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])

        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            private_key.public_key()
        ).serial_number(12345).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).sign(private_key, hashes.SHA256())  # Strong signature algorithm

        validator = CertificateValidator()
        validator._validate_signature_algorithm(cert)

        # Should complete without errors for strong algorithm
        assert len(validator.validation_errors) == 0

    def test_ed25519_key_validation_successful(self):
        """Test successful Ed25519 key validation."""
        # Create certificate with Ed25519 key
        private_key = ed25519.Ed25519PrivateKey.generate()
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])

        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            private_key.public_key()
        ).serial_number(12345).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).sign(private_key, None)  # Ed25519 doesn't need hash algorithm

        validator = CertificateValidator()
        validator._validate_public_key(cert, "client")

        # Should complete without errors for Ed25519 key
        assert len(validator.validation_errors) == 0

    def test_certificate_validation_complete_workflow_without_flask(self, flask_app):
        """Test complete validation workflow with Flask dependencies."""
        # Create a valid certificate that should pass all validation
        private_key = ed25519.Ed25519PrivateKey.generate()
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])

        # Add basic extensions to make it more realistic
        cert_builder = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            private_key.public_key()
        ).serial_number(12345).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        )

        # Add key usage extension
        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )

        cert = cert_builder.sign(private_key, None)
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

        validator = CertificateValidator()
        result_cert, validation_results = validator.validate_certificate(cert_pem, "client")

        # Should complete successfully
        assert result_cert is not None
        assert validation_results['status'] == 'valid'


class TestMissingCoverageTargets:
    """Test specific lines that need coverage to reach 100%."""

    def test_pem_format_missing_begin_header(self, flask_app):
        """Test PEM validation with missing begin header - covers line 127."""
        validator = CertificateValidator()

        invalid_pem = "VGVzdCBjZXJ0aWZpY2F0ZQ==\n-----END CERTIFICATE-----"

        with pytest.raises(CertificateValidationError, match="Missing PEM begin header"):
            validator._validate_pem_format(invalid_pem)

    def test_rsa_weak_public_exponent(self, flask_app):
        """Test RSA key with weak public exponent - covers line 185."""
        # Create a mock RSA public key with weak exponent
        mock_cert = Mock()
        mock_public_key = Mock()
        mock_public_key.__class__ = rsa.RSAPublicKey
        mock_public_key.key_size = 2048
        mock_public_numbers = Mock()
        mock_public_numbers.e = 3  # Weak exponent
        mock_public_key.public_numbers.return_value = mock_public_numbers
        mock_cert.public_key.return_value = mock_public_key

        validator = CertificateValidator()
        validator._validate_public_key(mock_cert, "client")

        # Should add warning for weak RSA public exponent
        assert any("RSA public exponent" in warning for warning in validator.validation_warnings)

    def test_ec_unapproved_curve(self, flask_app):
        """Test EC key with unapproved curve - covers lines 194-195."""
        # Create certificate with unapproved EC curve
        private_key = ec.generate_private_key(ec.SECP224R1())  # Unapproved curve
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])

        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            private_key.public_key()
        ).serial_number(12345).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).sign(private_key, hashes.SHA256())

        validator = CertificateValidator()
        validator._validate_public_key(cert, "client")

        # Should add warning for unapproved curve
        assert any("not in approved list" in warning for warning in validator.validation_warnings)

    def test_dsa_key_deprecation_warning(self, flask_app):
        """Test DSA key deprecation warning - covers line 208."""
        # Create certificate with DSA key
        private_key = dsa.generate_private_key(key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])

        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            private_key.public_key()
        ).serial_number(12345).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).sign(private_key, hashes.SHA256())

        validator = CertificateValidator()
        validator._validate_public_key(cert, "client")

        # Should add warning for DSA deprecation
        assert any("DSA keys are deprecated" in warning for warning in validator.validation_warnings)

    def test_key_usage_not_critical(self, flask_app):
        """Test key usage extension not marked as critical - covers line 284."""
        # Create key usage extension that's not critical
        key_usage = x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            content_commitment=False,
            data_encipherment=False,
            encipher_only=False,
            decipher_only=False
        )

        extensions = {ExtensionOID.KEY_USAGE: x509.Extension(ExtensionOID.KEY_USAGE, False, key_usage)}  # Not critical
        validator = CertificateValidator()
        validator._validate_key_usage(extensions, "client", is_test_cert=False)

        # Should add warning for not critical key usage
        assert any("should be marked as critical" in warning for warning in validator.validation_warnings)

    def test_client_certificate_with_ca_key_usage(self, flask_app):
        """Test client certificate with CA key usages - covers line 294."""
        # Create key usage with CA flags for client cert
        key_usage = x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            key_agreement=False,
            key_cert_sign=True,  # CA usage
            crl_sign=True,       # CA usage
            content_commitment=False,
            data_encipherment=False,
            encipher_only=False,
            decipher_only=False
        )

        extensions = {ExtensionOID.KEY_USAGE: x509.Extension(ExtensionOID.KEY_USAGE, True, key_usage)}
        validator = CertificateValidator()
        validator._validate_key_usage(extensions, "client", is_test_cert=False)

        # Should add warning for client cert with CA usages
        assert any("should not have CA key usages" in warning for warning in validator.validation_warnings)

    def test_server_certificate_missing_key_encipherment(self, flask_app):
        """Test server certificate missing key encipherment - covers lines 302-303."""
        # Create key usage without key encipherment or agreement for server
        key_usage = x509.KeyUsage(
            digital_signature=True,
            key_encipherment=False,  # Missing
            key_agreement=False,     # Missing
            key_cert_sign=False,
            crl_sign=False,
            content_commitment=False,
            data_encipherment=False,
            encipher_only=False,
            decipher_only=False
        )

        extensions = {ExtensionOID.KEY_USAGE: x509.Extension(ExtensionOID.KEY_USAGE, True, key_usage)}
        validator = CertificateValidator()
        validator._validate_key_usage(extensions, "server", is_test_cert=False)

        # Should add warning for missing key encipherment
        assert any("key_encipherment or key_agreement" in warning for warning in validator.validation_warnings)

    def test_ca_certificate_missing_key_cert_sign(self, flask_app):
        """Test CA certificate missing key cert sign - covers line 307."""
        # Create key usage without key cert sign for CA
        key_usage = x509.KeyUsage(
            digital_signature=True,
            key_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,  # Missing for CA
            crl_sign=True,
            content_commitment=False,
            data_encipherment=False,
            encipher_only=False,
            decipher_only=False
        )

        extensions = {ExtensionOID.KEY_USAGE: x509.Extension(ExtensionOID.KEY_USAGE, True, key_usage)}
        validator = CertificateValidator()
        validator._validate_key_usage(extensions, "intermediate", is_test_cert=False)

        # Should add error for missing key cert sign
        assert any("must have key_cert_sign" in error for error in validator.validation_errors)

    def test_ca_certificate_missing_crl_sign(self, flask_app):
        """Test CA certificate missing CRL sign - covers line 309."""
        # Create key usage without CRL sign for CA
        key_usage = x509.KeyUsage(
            digital_signature=True,
            key_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=False,  # Missing for CA
            content_commitment=False,
            data_encipherment=False,
            encipher_only=False,
            decipher_only=False
        )

        extensions = {ExtensionOID.KEY_USAGE: x509.Extension(ExtensionOID.KEY_USAGE, True, key_usage)}
        validator = CertificateValidator()
        validator._validate_key_usage(extensions, "intermediate", is_test_cert=False)

        # Should add warning for missing CRL sign
        assert any("should have crl_sign" in warning for warning in validator.validation_warnings)

    def test_basic_constraints_not_critical_for_ca(self, flask_app):
        """Test basic constraints not critical for CA - covers line 350."""
        # Create basic constraints that are not critical for CA
        basic_constraints = x509.BasicConstraints(ca=True, path_length=None)
        extensions = {ExtensionOID.BASIC_CONSTRAINTS: x509.Extension(ExtensionOID.BASIC_CONSTRAINTS, False, basic_constraints)}  # Not critical

        validator = CertificateValidator()
        validator._validate_basic_constraints(extensions, "intermediate")

        # Should add error for non-critical basic constraints
        assert any("must be critical" in error for error in validator.validation_errors)

    def test_server_certificate_missing_san(self, flask_app):
        """Test server certificate missing SAN - covers line 365."""
        extensions = {}  # No SAN extension
        validator = CertificateValidator()
        validator._validate_subject_alt_name(extensions, "server")

        # Should add warning for missing SAN
        assert any("should have Subject Alternative Name" in warning for warning in validator.validation_warnings)

    def test_san_validation_with_invalid_dns_name(self, flask_app):
        """Test SAN validation with invalid DNS name - covers line 376."""
        # Create SAN with invalid DNS name
        san_names = [x509.DNSName("invalid..domain.com")]  # Invalid DNS name
        san_extension = x509.SubjectAlternativeName(san_names)
        extensions = {ExtensionOID.SUBJECT_ALTERNATIVE_NAME: x509.Extension(ExtensionOID.SUBJECT_ALTERNATIVE_NAME, False, san_extension)}

        validator = CertificateValidator()
        validator._validate_subject_alt_name(extensions, "server")

        # Should add warning for invalid DNS name
        assert any("Invalid DNS name" in warning for warning in validator.validation_warnings)

    def test_san_validation_with_invalid_email(self, flask_app):
        """Test SAN validation with invalid email - covers line 383."""
        # Create SAN with invalid email
        san_names = [x509.RFC822Name("invalid-email")]  # Missing @ symbol
        san_extension = x509.SubjectAlternativeName(san_names)
        extensions = {ExtensionOID.SUBJECT_ALTERNATIVE_NAME: x509.Extension(ExtensionOID.SUBJECT_ALTERNATIVE_NAME, False, san_extension)}

        validator = CertificateValidator()
        validator._validate_subject_alt_name(extensions, "server")

        # Should add warning for invalid email
        assert any("Invalid email" in warning for warning in validator.validation_warnings)

    def test_dns_name_validation_empty_name(self, flask_app):
        """Test DNS name validation with empty name - covers line 426."""
        validator = CertificateValidator()
        result = validator._is_valid_dns_name("")

        # Should return False for empty DNS name
        assert result is False

    def test_dns_name_validation_too_long(self, flask_app):
        """Test DNS name validation with too long name - covers line 426."""
        validator = CertificateValidator()
        long_name = "a" * 254  # Exceeds 253 character limit
        result = validator._is_valid_dns_name(long_name)

        # Should return False for too long DNS name
        assert result is False

    def test_dns_name_validation_invalid_pattern(self, flask_app):
        """Test DNS name validation with invalid pattern - covers line 431."""
        validator = CertificateValidator()
        result = validator._is_valid_dns_name("invalid-.domain.com")

        # Should return False for invalid DNS pattern
        assert result is False

    def test_convenience_function_validate_certificate_format(self, flask_app):
        """Test convenience function - covers lines 448-449."""
        from app.utils.certificate_validator import validate_certificate_format

        # Create a valid certificate with required extensions
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])

        cert_builder = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            private_key.public_key()
        ).serial_number(12345).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        )

        # Add required extensions for client certificate
        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        ).add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False
        )

        cert = cert_builder.sign(private_key, hashes.SHA256())
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

        # Should work with convenience function
        result_cert, validation_results = validate_certificate_format(cert_pem, "client")
        assert result_cert is not None
        assert validation_results['status'] == 'valid'

    def test_client_certificate_test_cert_missing_digital_signature(self, flask_app):
        """Test client certificate test cert missing digital signature - covers lines 290-291."""
        # Create key usage without digital signature for client test cert
        key_usage = x509.KeyUsage(
            digital_signature=False,  # Missing for client
            key_encipherment=True,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            content_commitment=False,
            data_encipherment=False,
            encipher_only=False,
            decipher_only=False
        )

        extensions = {ExtensionOID.KEY_USAGE: x509.Extension(ExtensionOID.KEY_USAGE, True, key_usage)}
        validator = CertificateValidator()
        validator._validate_key_usage(extensions, "client", is_test_cert=True)

        # Should add warning for test client cert missing digital signature
        assert any("Test client certificate missing digital_signature" in warning for warning in validator.validation_warnings)

    def test_server_certificate_test_cert_missing_digital_signature(self, flask_app):
        """Test server certificate test cert missing digital signature - covers lines 298-301."""
        # Create key usage without digital signature for server test cert
        key_usage = x509.KeyUsage(
            digital_signature=False,  # Missing for server
            key_encipherment=True,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            content_commitment=False,
            data_encipherment=False,
            encipher_only=False,
            decipher_only=False
        )

        extensions = {ExtensionOID.KEY_USAGE: x509.Extension(ExtensionOID.KEY_USAGE, True, key_usage)}
        validator = CertificateValidator()
        validator._validate_key_usage(extensions, "server", is_test_cert=True)

        # Should add warning for test server cert missing digital signature
        assert any("Test server certificate missing digital_signature" in warning for warning in validator.validation_warnings)

    def test_client_certificate_test_cert_missing_client_auth(self, flask_app):
        """Test client certificate test cert missing client auth - covers lines 324-327."""
        # Create extended key usage without client auth for client test cert
        eku_values = [x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]  # Wrong usage
        eku_extension = x509.ExtendedKeyUsage(eku_values)
        extensions = {ExtensionOID.EXTENDED_KEY_USAGE: x509.Extension(ExtensionOID.EXTENDED_KEY_USAGE, False, eku_extension)}

        validator = CertificateValidator()
        validator._validate_extended_key_usage(extensions, "client", is_test_cert=True)

        # Should add warning for test client cert missing client auth
        assert any("Test client certificate missing clientAuth" in warning for warning in validator.validation_warnings)

    def test_server_certificate_test_cert_missing_server_auth(self, flask_app):
        """Test server certificate test cert missing server auth - covers lines 332-335."""
        # Create extended key usage without server auth for server test cert
        eku_values = [x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]  # Wrong usage
        eku_extension = x509.ExtendedKeyUsage(eku_values)
        extensions = {ExtensionOID.EXTENDED_KEY_USAGE: x509.Extension(ExtensionOID.EXTENDED_KEY_USAGE, False, eku_extension)}

        validator = CertificateValidator()
        validator._validate_extended_key_usage(extensions, "server", is_test_cert=True)

        # Should add warning for test server cert missing server auth
        assert any("Test server certificate missing serverAuth" in warning for warning in validator.validation_warnings)

    def test_ca_certificate_missing_basic_constraints(self, flask_app):
        """Test CA certificate missing basic constraints - covers line 342."""
        extensions = {}  # No basic constraints
        validator = CertificateValidator()
        validator._validate_basic_constraints(extensions, "intermediate")

        # Should add error for missing basic constraints
        assert any("must have Basic Constraints" in error for error in validator.validation_errors)

    def test_san_validation_with_ip_address(self, flask_app):
        """Test SAN validation with IP address - covers line 379."""
        # Create SAN with IP address
        import ipaddress
        san_names = [x509.IPAddress(ipaddress.IPv4Address('192.168.1.1'))]
        san_extension = x509.SubjectAlternativeName(san_names)
        extensions = {ExtensionOID.SUBJECT_ALTERNATIVE_NAME: x509.Extension(ExtensionOID.SUBJECT_ALTERNATIVE_NAME, False, san_extension)}

        validator = CertificateValidator()
        validator._validate_subject_alt_name(extensions, "server")

        # Should complete without warnings for valid IP address
        assert len(validator.validation_warnings) == 0

    # NOTE: test_subject_issuer_validation_empty_issuer_cn removed
    # The cryptography library prevents creation of NameAttribute with empty CN
    # This validation is enforced at the cryptography library level (line 152 in name.py)
    # making it impossible to test the application-level validation code path (line 404)
    # The mock-based test in test_mock_tests_for_final_coverage covers this scenario.

    def test_server_certificate_missing_digital_signature(self, flask_app):
        """Test server certificate missing digital signature - covers line 301."""
        # Create key usage without digital signature for server cert
        key_usage = x509.KeyUsage(
            digital_signature=False,  # Missing for server
            key_encipherment=True,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            content_commitment=False,
            data_encipherment=False,
            encipher_only=False,
            decipher_only=False
        )

        extensions = {ExtensionOID.KEY_USAGE: x509.Extension(ExtensionOID.KEY_USAGE, True, key_usage)}
        validator = CertificateValidator()
        validator._validate_key_usage(extensions, "server", is_test_cert=False)

        # Should add error for server missing digital signature
        assert any("Server certificates must have digital_signature" in error for error in validator.validation_errors)

    def test_client_certificate_missing_client_auth(self, flask_app):
        """Test client certificate missing client auth - covers line 328."""
        # Create extended key usage without client auth for client cert
        eku_values = [x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]  # Wrong usage
        eku_extension = x509.ExtendedKeyUsage(eku_values)
        extensions = {ExtensionOID.EXTENDED_KEY_USAGE: x509.Extension(ExtensionOID.EXTENDED_KEY_USAGE, False, eku_extension)}

        validator = CertificateValidator()
        validator._validate_extended_key_usage(extensions, "client", is_test_cert=False)

        # Should add error for client missing client auth
        assert any("Client certificates must have clientAuth" in error for error in validator.validation_errors)

    def test_server_certificate_missing_server_auth(self, flask_app):
        """Test server certificate missing server auth - covers line 335."""
        # Create extended key usage without server auth for server cert
        eku_values = [x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]  # Wrong usage
        eku_extension = x509.ExtendedKeyUsage(eku_values)
        extensions = {ExtensionOID.EXTENDED_KEY_USAGE: x509.Extension(ExtensionOID.EXTENDED_KEY_USAGE, False, eku_extension)}

        validator = CertificateValidator()
        validator._validate_extended_key_usage(extensions, "server", is_test_cert=False)

        # Should add error for server missing server auth
        assert any("Server certificates must have serverAuth" in error for error in validator.validation_errors)

    def test_mock_tests_for_final_coverage(self, flask_app):
        """Test remaining uncovered lines with mocks - covers lines 394, 396, 404."""
        validator = CertificateValidator()

        # Test empty subject CN validation - line 394
        mock_cert = Mock()
        mock_subject = Mock()
        mock_issuer = Mock()

        # Mock subject with empty CN
        mock_subject_attr = Mock()
        mock_subject_attr.value = "   "  # Empty/whitespace CN
        mock_subject.get_attributes_for_oid.return_value = [mock_subject_attr]

        # Mock issuer with valid CN
        mock_issuer_attr = Mock()
        mock_issuer_attr.value = "Test CA"
        mock_issuer.get_attributes_for_oid.return_value = [mock_issuer_attr]

        mock_cert.subject = mock_subject
        mock_cert.issuer = mock_issuer

        validator._validate_subject_issuer_fields(mock_cert, "client")

        # Should add error for empty subject CN
        assert any("Subject Common Name is empty" in error for error in validator.validation_errors)

        # Reset errors for next test
        validator.validation_errors = []

        # Test long subject CN validation - line 396
        mock_subject_attr.value = "a" * 65  # Too long
        validator._validate_subject_issuer_fields(mock_cert, "client")

        # Should add warning for long subject CN
        assert any("64 characters" in warning for warning in validator.validation_warnings)

        # Reset for issuer test
        validator.validation_warnings = []
        mock_subject_attr.value = "test.example.com"  # Valid subject
        mock_issuer_attr.value = "   "  # Empty issuer CN

        validator._validate_subject_issuer_fields(mock_cert, "client")

        # Should add error for empty issuer CN - line 404
        assert any("Issuer Common Name is empty" in error for error in validator.validation_errors)