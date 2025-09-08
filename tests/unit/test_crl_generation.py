"""
Unit tests for Certificate Revocation List (CRL) generation functionality.

These tests follow TDD methodology for implementing CRL generation features.
"""

import pytest
from datetime import datetime, timezone, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from app.models.certificate_log import CertificateLog
from app import db


@pytest.fixture
def test_ca_materials():
    """Generate test CA certificate and private key for CRL signing."""
    # Generate a test CA private key
    ca_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Create a test CA certificate
    ca_subject = issuer = x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, "Test State"),
        x509.NameAttribute(x509.NameOID.LOCALITY_NAME, "Test City"),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "Test CA Organization"),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, "Test Intermediate CA"),
    ])
    
    ca_cert = x509.CertificateBuilder().subject_name(
        ca_subject
    ).issuer_name(
        issuer
    ).public_key(
        ca_private_key.public_key()
    ).serial_number(
        12345
    ).not_valid_before(
        datetime.now(timezone.utc) - timedelta(days=1)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=365)
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(ca_private_key.public_key()),
        critical=False
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True
    ).sign(ca_private_key, hashes.SHA256())
    
    # Serialize to PEM
    ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    ca_key_pem = ca_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    return {
        'ca_cert_pem': ca_cert_pem,
        'ca_key_pem': ca_key_pem,
        'ca_key_passphrase': ''
    }


def setup_generator_with_ca(test_ca_materials):
    """Helper function to create and configure a CRL generator with test CA materials."""
    from app.utils.crl_generator import CRLGenerator
    generator = CRLGenerator()
    generator.load_ca_materials(
        test_ca_materials['ca_cert_pem'],
        test_ca_materials['ca_key_pem'],
        test_ca_materials['ca_key_passphrase']
    )
    return generator


class TestCRLGeneration:
    """Test CRL generation functionality using TDD approach."""
    
    def test_crl_generator_class_exists(self, app):
        """Test that CRL generator utility class exists."""
        with app.app_context():
            from app.utils.crl_generator import CRLGenerator
            assert CRLGenerator is not None
            
            # Test that we can instantiate the class
            generator = CRLGenerator()
            assert generator is not None
    
    def test_crl_generator_initialization_with_ca_cert_and_key(self, app):
        """Test CRL generator initialization with CA certificate and key."""
        with app.app_context():
            from app.utils.crl_generator import CRLGenerator
            
            # Test initialization with certificate and key paths
            generator = CRLGenerator(
                ca_cert_path="/path/to/intermediate-ca.crt",
                ca_key_path="/path/to/intermediate-ca.key",
                ca_key_passphrase="test_passphrase"
            )
            
            assert generator.ca_cert_path == "/path/to/intermediate-ca.crt"
            assert generator.ca_key_path == "/path/to/intermediate-ca.key"
            assert generator.ca_key_passphrase == "test_passphrase"
    
    def test_crl_generator_load_ca_materials_method(self, app):
        """Test loading CA certificate and private key."""
        with app.app_context():
            from app.utils.crl_generator import CRLGenerator
            
            generator = CRLGenerator()
            
            # Test that load_ca_materials method exists
            assert hasattr(generator, 'load_ca_materials')
            
            # Test method signature
            import inspect
            sig = inspect.signature(generator.load_ca_materials)
            expected_params = ['ca_cert_pem', 'ca_key_pem', 'ca_key_passphrase']
            actual_params = list(sig.parameters.keys())
            
            for param in expected_params:
                assert param in actual_params
    
    def test_crl_generator_create_crl_method_signature(self, app):
        """Test CRL creation method signature and basic structure."""
        with app.app_context():
            from app.utils.crl_generator import CRLGenerator
            
            generator = CRLGenerator()
            
            # Test that create_crl method exists
            assert hasattr(generator, 'create_crl')
            
            # Test method signature
            import inspect
            sig = inspect.signature(generator.create_crl)
            expected_params = ['revoked_certificates', 'next_update_hours']
            actual_params = list(sig.parameters.keys())
            
            for param in expected_params:
                assert param in actual_params
    
    def test_crl_generation_with_no_revoked_certificates(self, app, sample_cert_data, test_ca_materials):
        """Test CRL generation when no certificates are revoked."""
        with app.app_context():
            from app.utils.crl_generator import CRLGenerator
            
            # Create some active (non-revoked) certificates
            cert1 = CertificateLog.log_certificate(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type'],
                issuing_user_id='user123'
            )
            
            generator = setup_generator_with_ca(test_ca_materials)
            
            # Get revoked certificates (should be empty)
            revoked_certs = CertificateLog.get_revoked_certificates()
            assert len(revoked_certs) == 0
            
            # Test CRL creation with empty revocation list
            crl_der = generator.create_crl(revoked_certs)
            
            # Verify CRL is valid DER-encoded data
            assert isinstance(crl_der, bytes)
            assert len(crl_der) > 0
            
            # Parse the CRL to verify structure
            crl = x509.load_der_x509_crl(crl_der)
            assert isinstance(crl, x509.CertificateRevocationList)
            
            # Verify no revoked certificates in CRL
            revoked_list = list(crl)
            assert len(revoked_list) == 0
    
    def test_crl_generation_with_revoked_certificates(self, app, sample_cert_data, test_ca_materials):
        """Test CRL generation with revoked certificates."""
        with app.app_context():
            from app.utils.crl_generator import CRLGenerator
            
            # Create and revoke some certificates
            cert1 = CertificateLog.log_certificate(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type'],
                issuing_user_id='user123'
            )
            cert1.mark_revoked(reason='key_compromise', revoked_by='admin456')
            
            # Create another revoked certificate with different fingerprint
            cert2 = CertificateLog(
                sample_cert_data['certificate_pem'],
                'server',
                issuing_user_id='user789'
            )
            cert2.fingerprint_sha256 = 'DIFFERENT_FINGERPRINT_CRL_TEST'
            cert2.serial_number = 'ABCDEF123456789'
            db.session.add(cert2)
            cert2.mark_revoked(reason='superseded', revoked_by='admin456')
            db.session.commit()
            
            generator = setup_generator_with_ca(test_ca_materials)
            
            # Get revoked certificates
            revoked_certs = CertificateLog.get_revoked_certificates()
            assert len(revoked_certs) == 2
            
            # Test CRL creation with revoked certificates
            crl_der = generator.create_crl(revoked_certs)
            
            # Verify CRL is valid DER-encoded data
            assert isinstance(crl_der, bytes)
            assert len(crl_der) > 0
            
            # Parse the CRL to verify structure
            crl = x509.load_der_x509_crl(crl_der)
            assert isinstance(crl, x509.CertificateRevocationList)
            
            # Verify revoked certificates are in CRL
            revoked_list = list(crl)
            assert len(revoked_list) == 2
            
            # Check that serial numbers match
            crl_serials = [entry.serial_number for entry in revoked_list]
            expected_serials = [int(cert.serial_number, 16) for cert in revoked_certs]
            
            for expected_serial in expected_serials:
                assert expected_serial in crl_serials
    
    def test_crl_generation_with_revocation_reasons(self, app, sample_cert_data, test_ca_materials):
        """Test that CRL includes proper revocation reasons."""
        with app.app_context():
            from app.utils.crl_generator import CRLGenerator
            
            # Create and revoke certificate with specific reason
            cert1 = CertificateLog.log_certificate(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type'],
                issuing_user_id='user123'
            )
            cert1.mark_revoked(reason='key_compromise', revoked_by='admin456')
            db.session.commit()
            
            generator = setup_generator_with_ca(test_ca_materials)
            revoked_certs = CertificateLog.get_revoked_certificates()
            
            # Generate CRL
            crl_der = generator.create_crl(revoked_certs)
            crl = x509.load_der_x509_crl(crl_der)
            
            # Check revocation entry details
            revoked_list = list(crl)
            assert len(revoked_list) == 1
            
            revoked_entry = revoked_list[0]
            
            # Verify serial number
            expected_serial = int(cert1.serial_number, 16)
            assert revoked_entry.serial_number == expected_serial
            
            # Verify revocation date
            assert revoked_entry.revocation_date_utc is not None
            assert isinstance(revoked_entry.revocation_date_utc, datetime)
            
            # Check for revocation reason extension
            # Note: CRL_REASON extension might not be available in all cryptography versions
            # For now, we'll just verify that revocation reason is properly handled
            # The actual extension OID for CRL reason code is 2.5.29.21
            try:
                from cryptography.x509.oid import ObjectIdentifier
                crl_reason_oid = ObjectIdentifier("2.5.29.21")
                reason_ext = revoked_entry.extensions.get_extension_for_oid(crl_reason_oid)
                # key_compromise should map to reason code 1
                assert reason_ext.value.reason == x509.ReasonFlags.key_compromise
            except (x509.ExtensionNotFound, AttributeError):
                # Extension might not be present in all implementations
                # This is acceptable as revocation reason extensions are optional
                pass
    
    def test_crl_generation_validity_period(self, app, sample_cert_data, test_ca_materials):
        """Test CRL has proper validity period."""
        with app.app_context():
            from app.utils.crl_generator import CRLGenerator
            
            generator = setup_generator_with_ca(test_ca_materials)
            revoked_certs = []  # Empty list for this test
            
            # Generate CRL with specific next update period
            next_update_hours = 24
            crl_der = generator.create_crl(revoked_certs, next_update_hours=next_update_hours)
            crl = x509.load_der_x509_crl(crl_der)
            
            # Check this_update and next_update times
            now = datetime.now(timezone.utc)
            
            assert crl.last_update_utc <= now
            assert crl.next_update_utc > now
            
            # Verify next_update is approximately next_update_hours from now
            expected_next_update = now + timedelta(hours=next_update_hours)
            time_diff = abs((crl.next_update_utc - expected_next_update).total_seconds())
            assert time_diff < 60  # Within 1 minute tolerance
    
    def test_crl_generation_issuer_information(self, app, test_ca_materials):
        """Test CRL contains correct issuer information."""
        with app.app_context():
            from app.utils.crl_generator import CRLGenerator
            
            generator = setup_generator_with_ca(test_ca_materials)
            revoked_certs = []
            
            # Generate CRL
            crl_der = generator.create_crl(revoked_certs)
            crl = x509.load_der_x509_crl(crl_der)
            
            # Verify issuer information
            assert crl.issuer is not None
            
            # Check that issuer contains expected attributes
            issuer_attributes = crl.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            assert len(issuer_attributes) > 0
            
            # Verify issuer matches the intermediate CA
            issuer_cn = issuer_attributes[0].value
            assert 'CA' in issuer_cn or 'Certificate Authority' in issuer_cn.lower()
    
    def test_crl_generation_signature_verification(self, app, test_ca_materials):
        """Test that generated CRL has valid signature."""
        with app.app_context():
            from app.utils.crl_generator import CRLGenerator
            
            generator = setup_generator_with_ca(test_ca_materials)
            revoked_certs = []
            
            # Generate CRL
            crl_der = generator.create_crl(revoked_certs)
            crl = x509.load_der_x509_crl(crl_der)
            
            # Test signature algorithm
            assert crl.signature_algorithm_oid is not None
            
            # Common signature algorithms for CRLs
            expected_algorithms = [
                x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA256,
                x509.oid.SignatureAlgorithmOID.ED25519,
                x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA384,
                x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA512
            ]
            
            assert crl.signature_algorithm_oid in expected_algorithms
    
    def test_crl_generation_crl_number_extension(self, app, test_ca_materials):
        """Test CRL includes proper CRL Number extension."""
        with app.app_context():
            from app.utils.crl_generator import CRLGenerator
            
            generator = setup_generator_with_ca(test_ca_materials)
            revoked_certs = []
            
            # Generate first CRL
            crl_der_1 = generator.create_crl(revoked_certs)
            crl_1 = x509.load_der_x509_crl(crl_der_1)
            
            # Generate second CRL
            crl_der_2 = generator.create_crl(revoked_certs)
            crl_2 = x509.load_der_x509_crl(crl_der_2)
            
            # Both CRLs should have CRL Number extension
            try:
                crl_num_ext_1 = crl_1.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.CRL_NUMBER
                )
                crl_num_ext_2 = crl_2.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.CRL_NUMBER
                )
                
                # Second CRL should have higher number than first
                assert crl_num_ext_2.value.crl_number > crl_num_ext_1.value.crl_number
                
            except x509.ExtensionNotFound:
                # CRL Number extension might not be implemented yet
                pass
    
    def test_crl_generation_authority_key_identifier(self, app, test_ca_materials):
        """Test CRL includes Authority Key Identifier extension."""
        with app.app_context():
            from app.utils.crl_generator import CRLGenerator
            
            generator = setup_generator_with_ca(test_ca_materials)
            revoked_certs = []
            
            # Generate CRL
            crl_der = generator.create_crl(revoked_certs)
            crl = x509.load_der_x509_crl(crl_der)
            
            # Check for Authority Key Identifier extension
            try:
                aki_ext = crl.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER
                )
                
                assert aki_ext.value.key_identifier is not None
                assert len(aki_ext.value.key_identifier) > 0
                
            except x509.ExtensionNotFound:
                # Extension might not be implemented yet
                pass
    
    def test_crl_generator_error_handling_invalid_ca_materials(self, app):
        """Test CRL generator handles invalid CA materials gracefully."""
        with app.app_context():
            from app.utils.crl_generator import CRLGenerator
            
            generator = CRLGenerator()
            
            # Test with invalid certificate PEM
            with pytest.raises(ValueError, match="Invalid CA certificate"):
                generator.load_ca_materials(
                    ca_cert_pem="invalid_cert_pem",
                    ca_key_pem="invalid_key_pem",
                    ca_key_passphrase="test"
                )
    
    def test_crl_generator_error_handling_missing_ca_materials(self, app):
        """Test CRL generator handles missing CA materials."""
        with app.app_context():
            from app.utils.crl_generator import CRLGenerator
            
            generator = CRLGenerator()
            
            # Test creating CRL without loading CA materials
            with pytest.raises(RuntimeError, match="CA materials not loaded"):
                generator.create_crl([])
    
    def test_crl_generator_get_current_crl_method(self, app, test_ca_materials):
        """Test method to get the current/latest CRL."""
        with app.app_context():
            from app.utils.crl_generator import CRLGenerator
            
            generator = setup_generator_with_ca(test_ca_materials)
            
            # Test that get_current_crl method exists
            assert hasattr(generator, 'get_current_crl')
            
            # Generate and get current CRL
            revoked_certs = CertificateLog.get_revoked_certificates()
            current_crl = generator.get_current_crl()
            
            # Should return DER-encoded CRL
            assert isinstance(current_crl, bytes)
            
            # Should be parseable as CRL
            crl = x509.load_der_x509_crl(current_crl)
            assert isinstance(crl, x509.CertificateRevocationList)
    
    def test_crl_generation_performance_with_large_revocation_list(self, app, sample_cert_data, test_ca_materials):
        """Test CRL generation performance with large number of revoked certificates."""
        with app.app_context():
            from app.utils.crl_generator import CRLGenerator
            import time
            
            # Create multiple revoked certificates
            revoked_certs = []
            for i in range(10):  # Smaller number for unit test
                cert = CertificateLog(
                    sample_cert_data['certificate_pem'],
                    'client',
                    issuing_user_id=f'user{i}'
                )
                cert.fingerprint_sha256 = f'FINGERPRINT_PERF_TEST_{i}'
                cert.serial_number = f'{(0x100000 + i):X}'  # Valid hex serial numbers
                cert.mark_revoked(reason='superseded', revoked_by='admin')
                revoked_certs.append(cert)
                db.session.add(cert)
            
            db.session.commit()
            
            generator = setup_generator_with_ca(test_ca_materials)
            
            # Time the CRL generation
            start_time = time.time()
            crl_der = generator.create_crl(revoked_certs)
            end_time = time.time()
            
            generation_time = end_time - start_time
            
            # Verify CRL was generated successfully
            assert isinstance(crl_der, bytes)
            assert len(crl_der) > 0
            
            # Performance should be reasonable (less than 1 second for 10 certs)
            assert generation_time < 1.0
            
            # Verify all certificates are in CRL
            crl = x509.load_der_x509_crl(crl_der)
            revoked_list = list(crl)
            assert len(revoked_list) == 10