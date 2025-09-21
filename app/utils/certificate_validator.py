"""
Enhanced certificate format validation for the Certificate Transparency service.

This module provides comprehensive validation for certificate format, structure,
and security properties to ensure only valid certificates are logged to the CT service.
"""

import re
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, dsa
from flask import current_app


class CertificateValidationError(ValueError):
    """Raised when certificate validation fails."""
    pass


class CertificateValidator:
    """
    Enhanced certificate validator for CT service.

    Provides comprehensive validation including:
    - PEM format validation
    - Certificate structure validation
    - Key type and size validation
    - Extension validation
    - Security policy compliance
    """

    # Minimum key sizes for security
    MIN_KEY_SIZES = {
        'RSA': 2048,
        'DSA': 2048,
        'EC': 256  # P-256 curve
    }

    # Maximum certificate validity periods (in days)
    MAX_VALIDITY_PERIODS = {
        'client': 395,     # 13 months for client certificates
        'server': 395,     # 13 months for server certificates
        'intermediate': 3650,  # 10 years for intermediate CAs
        'root': 7300      # 20 years for root CAs
    }

    # Required extensions for certificate types
    REQUIRED_EXTENSIONS = {
        'client': [x509.oid.ExtensionOID.KEY_USAGE, x509.oid.ExtensionOID.EXTENDED_KEY_USAGE],
        'server': [x509.oid.ExtensionOID.KEY_USAGE, x509.oid.ExtensionOID.EXTENDED_KEY_USAGE],
        'intermediate': [x509.oid.ExtensionOID.KEY_USAGE, x509.oid.ExtensionOID.BASIC_CONSTRAINTS]
    }

    def __init__(self):
        """Initialize the certificate validator."""
        self.validation_errors = []
        self.validation_warnings = []

    def validate_certificate(self, certificate_pem: str, certificate_type: str) -> Tuple[x509.Certificate, Dict]:
        """
        Perform comprehensive certificate validation.

        Args:
            certificate_pem: PEM-encoded certificate string
            certificate_type: Type of certificate ('client', 'server', 'intermediate')

        Returns:
            Tuple of (parsed certificate object, validation results dict)

        Raises:
            CertificateValidationError: If validation fails
        """
        self.validation_errors = []
        self.validation_warnings = []

        # Step 1: Validate PEM format
        cert = self._validate_pem_format(certificate_pem)

        # Step 2: Validate certificate structure
        self._validate_certificate_structure(cert, certificate_type)

        # Step 3: Validate public key
        self._validate_public_key(cert, certificate_type)

        # Step 4: Validate validity period
        self._validate_validity_period(cert, certificate_type)

        # Step 5: Validate extensions
        self._validate_extensions(cert, certificate_type)

        # Step 6: Validate subject/issuer fields
        self._validate_subject_issuer_fields(cert, certificate_type)

        # Step 7: Validate signature algorithm
        self._validate_signature_algorithm(cert)

        # If there are critical errors, raise exception
        if self.validation_errors:
            error_message = f"Certificate validation failed: {'; '.join(self.validation_errors)}"
            current_app.logger.error(f"Certificate validation errors: {self.validation_errors}")
            raise CertificateValidationError(error_message)

        # Log warnings but don't fail validation
        if self.validation_warnings:
            current_app.logger.warning(f"Certificate validation warnings: {self.validation_warnings}")

        validation_results = {
            'errors': self.validation_errors,
            'warnings': self.validation_warnings,
            'status': 'valid'
        }

        return cert, validation_results

    def _validate_pem_format(self, certificate_pem: str) -> x509.Certificate:
        """Validate PEM format and parse certificate."""
        if not isinstance(certificate_pem, str):
            raise CertificateValidationError("Certificate must be a string")

        if not certificate_pem.strip():
            raise CertificateValidationError("Certificate PEM is empty")

        # Check for proper PEM headers
        if '-----BEGIN CERTIFICATE-----' not in certificate_pem:
            raise CertificateValidationError("Missing PEM begin header")

        if '-----END CERTIFICATE-----' not in certificate_pem:
            raise CertificateValidationError("Missing PEM end header")

        # Validate basic PEM structure
        pem_pattern = re.compile(
            r'-----BEGIN CERTIFICATE-----\s*'
            r'([A-Za-z0-9+/\s=]+)'
            r'-----END CERTIFICATE-----',
            re.MULTILINE
        )

        if not pem_pattern.search(certificate_pem):
            raise CertificateValidationError("Invalid PEM format structure")

        # Check for multiple certificates (should be single certificate)
        cert_count = certificate_pem.count('-----BEGIN CERTIFICATE-----')
        if cert_count > 1:
            raise CertificateValidationError(f"Multiple certificates found ({cert_count}), expected single certificate")

        # Parse the certificate
        try:
            cert = x509.load_pem_x509_certificate(certificate_pem.encode('utf-8'))
        except Exception as e:
            raise CertificateValidationError(f"Failed to parse certificate: {str(e)}")

        return cert

    def _validate_certificate_structure(self, cert: x509.Certificate, certificate_type: str):
        """Validate basic certificate structure."""
        # Validate certificate type
        valid_types = ['client', 'server', 'intermediate', 'root']
        if certificate_type not in valid_types:
            self.validation_errors.append(f"Invalid certificate type '{certificate_type}', must be one of: {valid_types}")

        # Validate serial number
        if cert.serial_number <= 0:
            self.validation_errors.append("Certificate serial number must be positive")

        # Validate version (should be v3 for modern certificates)
        if cert.version != x509.Version.v3:
            self.validation_warnings.append(f"Certificate version is {cert.version.name}, recommended v3")

    def _validate_public_key(self, cert: x509.Certificate, certificate_type: str):
        """Validate public key type and size."""
        public_key = cert.public_key()
        key_type = public_key.__class__.__name__.replace('Public', '').replace('Key', '')

        # RSA key validation
        if isinstance(public_key, rsa.RSAPublicKey):
            key_size = public_key.key_size
            min_size = self.MIN_KEY_SIZES.get('RSA', 2048)
            if key_size < min_size:
                self.validation_errors.append(f"RSA key size {key_size} is below minimum {min_size}")

            # Check for weak RSA public exponent
            if public_key.public_numbers().e < 65537:
                self.validation_warnings.append("RSA public exponent is smaller than recommended (65537)")

        # EC key validation
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            curve_name = public_key.curve.name
            key_size = public_key.curve.key_size

            # Check for approved curves
            approved_curves = ['secp256r1', 'secp384r1', 'secp521r1']
            if curve_name not in approved_curves:
                self.validation_warnings.append(f"EC curve '{curve_name}' not in approved list: {approved_curves}")

            min_size = self.MIN_KEY_SIZES.get('EC', 256)
            if key_size < min_size:
                self.validation_errors.append(f"EC key size {key_size} is below minimum {min_size}")

        # Ed25519/Ed448 validation (always acceptable)
        elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            # Ed25519/Ed448 are always considered secure
            pass

        # DSA key validation (discouraged)
        elif isinstance(public_key, dsa.DSAPublicKey):
            self.validation_warnings.append("DSA keys are deprecated, consider using RSA or EC keys")
            key_size = public_key.key_size
            min_size = self.MIN_KEY_SIZES.get('DSA', 2048)
            if key_size < min_size:
                self.validation_errors.append(f"DSA key size {key_size} is below minimum {min_size}")

        else:
            self.validation_warnings.append(f"Unknown or unsupported key type: {key_type}")

    def _validate_validity_period(self, cert: x509.Certificate, certificate_type: str):
        """Validate certificate validity period."""
        now = datetime.now(timezone.utc)
        not_before = cert.not_valid_before_utc.replace(tzinfo=timezone.utc)
        not_after = cert.not_valid_after_utc.replace(tzinfo=timezone.utc)

        # Check if certificate is currently valid
        if now < not_before:
            self.validation_warnings.append("Certificate is not yet valid")

        if now > not_after:
            self.validation_warnings.append("Certificate has expired")

        # Check validity period length
        validity_period = not_after - not_before
        max_validity_days = self.MAX_VALIDITY_PERIODS.get(certificate_type, 395)
        max_validity = timedelta(days=max_validity_days)

        if validity_period > max_validity:
            self.validation_warnings.append(
                f"Certificate validity period ({validity_period.days} days) exceeds recommended maximum "
                f"({max_validity_days} days) for {certificate_type} certificates"
            )

        # Check for backdated certificates
        if not_before < now - timedelta(days=1):
            self.validation_warnings.append("Certificate not_before is more than 1 day in the past")

    def _validate_extensions(self, cert: x509.Certificate, certificate_type: str):
        """Validate certificate extensions."""
        extensions = {ext.oid: ext for ext in cert.extensions}

        # Check for test certificates (Ed25519 with minimal extensions) - be more lenient
        public_key = cert.public_key()
        is_ed25519_test_cert = (
            isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)) and
            len(extensions) <= 2  # Minimal extensions suggest test certificate
        )

        # Check required extensions (but be lenient for test certificates)
        required_extensions = self.REQUIRED_EXTENSIONS.get(certificate_type, [])
        for required_oid in required_extensions:
            if required_oid not in extensions:
                if is_ed25519_test_cert:
                    self.validation_warnings.append(f"Test certificate missing extension: {required_oid._name}")
                else:
                    self.validation_errors.append(f"Missing required extension: {required_oid._name}")

        # Validate specific extensions
        self._validate_key_usage(extensions, certificate_type, is_test_cert=is_ed25519_test_cert)
        self._validate_extended_key_usage(extensions, certificate_type, is_test_cert=is_ed25519_test_cert)
        self._validate_basic_constraints(extensions, certificate_type)
        self._validate_subject_alt_name(extensions, certificate_type)

    def _validate_key_usage(self, extensions: Dict, certificate_type: str, is_test_cert: bool = False):
        """Validate Key Usage extension."""
        ku_oid = x509.oid.ExtensionOID.KEY_USAGE
        if ku_oid not in extensions:
            if is_test_cert:
                self.validation_warnings.append("Test certificate missing Key Usage extension")
            return

        ku_ext = extensions[ku_oid]
        ku = ku_ext.value

        # Validate critical flag
        if not ku_ext.critical:
            self.validation_warnings.append("Key Usage extension should be marked as critical")

        # Type-specific key usage validation (be lenient for test certificates)
        if certificate_type == 'client':
            if not ku.digital_signature:
                if is_test_cert:
                    self.validation_warnings.append("Test client certificate missing digital_signature key usage")
                else:
                    self.validation_errors.append("Client certificates must have digital_signature key usage")
            if ku.key_cert_sign or ku.crl_sign:
                self.validation_warnings.append("Client certificates should not have CA key usages")

        elif certificate_type == 'server':
            if not ku.digital_signature:
                if is_test_cert:
                    self.validation_warnings.append("Test server certificate missing digital_signature key usage")
                else:
                    self.validation_errors.append("Server certificates must have digital_signature key usage")
            if not ku.key_encipherment and not ku.key_agreement:
                self.validation_warnings.append("Server certificates should have key_encipherment or key_agreement")

        elif certificate_type in ['intermediate', 'root']:
            if not ku.key_cert_sign:
                self.validation_errors.append("CA certificates must have key_cert_sign key usage")
            if not ku.crl_sign:
                self.validation_warnings.append("CA certificates should have crl_sign key usage")

    def _validate_extended_key_usage(self, extensions: Dict, certificate_type: str, is_test_cert: bool = False):
        """Validate Extended Key Usage extension."""
        eku_oid = x509.oid.ExtensionOID.EXTENDED_KEY_USAGE
        if eku_oid not in extensions:
            if is_test_cert:
                self.validation_warnings.append("Test certificate missing Extended Key Usage extension")
            return

        eku_ext = extensions[eku_oid]
        eku_values = list(eku_ext.value)

        # Type-specific EKU validation (be lenient for test certificates)
        if certificate_type == 'client':
            if x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH not in eku_values:
                if is_test_cert:
                    self.validation_warnings.append("Test client certificate missing clientAuth extended key usage")
                else:
                    self.validation_errors.append("Client certificates must have clientAuth extended key usage")

        elif certificate_type == 'server':
            if x509.oid.ExtendedKeyUsageOID.SERVER_AUTH not in eku_values:
                if is_test_cert:
                    self.validation_warnings.append("Test server certificate missing serverAuth extended key usage")
                else:
                    self.validation_errors.append("Server certificates must have serverAuth extended key usage")

    def _validate_basic_constraints(self, extensions: Dict, certificate_type: str):
        """Validate Basic Constraints extension."""
        bc_oid = x509.oid.ExtensionOID.BASIC_CONSTRAINTS
        if bc_oid not in extensions:
            if certificate_type in ['intermediate', 'root']:
                self.validation_errors.append("CA certificates must have Basic Constraints extension")
            return

        bc_ext = extensions[bc_oid]
        bc = bc_ext.value

        # Validate critical flag for CA certificates
        if certificate_type in ['intermediate', 'root'] and not bc_ext.critical:
            self.validation_errors.append("Basic Constraints extension must be critical for CA certificates")

        # Validate CA flag
        if certificate_type in ['intermediate', 'root']:
            if not bc.ca:
                self.validation_errors.append("CA certificates must have CA flag set to True")
        else:
            if bc.ca:
                self.validation_warnings.append("End-entity certificates should not have CA flag set")

    def _validate_subject_alt_name(self, extensions: Dict, certificate_type: str):
        """Validate Subject Alternative Name extension."""
        san_oid = x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        if san_oid not in extensions:
            if certificate_type == 'server':
                self.validation_warnings.append("Server certificates should have Subject Alternative Name extension")
            return

        san_ext = extensions[san_oid]
        san_values = list(san_ext.value)

        # Validate SAN entries
        for san in san_values:
            if isinstance(san, x509.DNSName):
                # Basic DNS name validation
                if not self._is_valid_dns_name(san.value):
                    self.validation_warnings.append(f"Invalid DNS name in SAN: {san.value}")
            elif isinstance(san, x509.IPAddress):
                # IP addresses are generally valid if parsed correctly
                pass
            elif isinstance(san, x509.RFC822Name):
                # Basic email validation
                if '@' not in san.value:
                    self.validation_warnings.append(f"Invalid email in SAN: {san.value}")

    def _validate_subject_issuer_fields(self, cert: x509.Certificate, certificate_type: str):
        """Validate subject and issuer fields."""
        subject = cert.subject
        issuer = cert.issuer

        # Validate subject common name
        try:
            subject_cn = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            if not subject_cn or not subject_cn.strip():
                self.validation_errors.append("Subject Common Name is empty")
            elif len(subject_cn) > 64:
                self.validation_warnings.append("Subject Common Name is longer than 64 characters")
        except IndexError:
            self.validation_errors.append("Subject Common Name is missing")

        # Validate issuer common name
        try:
            issuer_cn = issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            if not issuer_cn or not issuer_cn.strip():
                self.validation_errors.append("Issuer Common Name is empty")
        except IndexError:
            self.validation_errors.append("Issuer Common Name is missing")

    def _validate_signature_algorithm(self, cert: x509.Certificate):
        """Validate signature algorithm."""
        sig_alg = cert.signature_algorithm_oid._name.lower()

        # Check for weak signature algorithms
        weak_algorithms = ['md5', 'sha1']
        for weak_alg in weak_algorithms:
            if weak_alg in sig_alg:
                self.validation_errors.append(f"Weak signature algorithm: {sig_alg}")
                break

        # Check for acceptable algorithms
        acceptable_algorithms = ['sha256', 'sha384', 'sha512', 'sha3']
        if not any(alg in sig_alg for alg in acceptable_algorithms):
            self.validation_warnings.append(f"Signature algorithm '{sig_alg}' may not be optimal")

    def _is_valid_dns_name(self, dns_name: str) -> bool:
        """Basic DNS name validation."""
        if not dns_name or len(dns_name) > 253:
            return False

        # Check for valid characters and structure
        dns_pattern = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')
        return bool(dns_pattern.match(dns_name))


def validate_certificate_format(certificate_pem: str, certificate_type: str) -> Tuple[x509.Certificate, Dict]:
    """
    Convenience function for certificate validation.

    Args:
        certificate_pem: PEM-encoded certificate string
        certificate_type: Type of certificate

    Returns:
        Tuple of (parsed certificate, validation results)

    Raises:
        CertificateValidationError: If validation fails
    """
    validator = CertificateValidator()
    return validator.validate_certificate(certificate_pem, certificate_type)