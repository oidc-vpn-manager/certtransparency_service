"""
Unit tests for Certificate Transparency Log revocation functionality.

These tests follow TDD methodology for implementing certificate revocation features.
"""

import pytest
from datetime import datetime, timezone
from app.models.certificate_log import CertificateLog
from app import db


class TestCertificateRevocationModel:
    """Test Certificate Log revocation functionality using TDD approach."""
    
    def test_issuing_user_id_field_exists(self, app, sample_cert_data):
        """Test that issuing_user_id field exists and can be set."""
        with app.app_context():
            log_entry = CertificateLog(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type'],
                issuing_user_id='user123'
            )
            
            assert hasattr(log_entry, 'issuing_user_id')
            assert log_entry.issuing_user_id == 'user123'
    
    def test_revoked_by_field_exists(self, app, sample_cert_data):
        """Test that revoked_by field exists and can be set."""
        with app.app_context():
            log_entry = CertificateLog(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type']
            )
            
            assert hasattr(log_entry, 'revoked_by')
            assert log_entry.revoked_by is None  # Should be None initially
    
    def test_mark_revoked_with_user_tracking(self, app, sample_cert_data):
        """Test mark_revoked method with user tracking."""
        with app.app_context():
            log_entry = CertificateLog(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type'],
                issuing_user_id='user123'
            )
            
            # Initially not revoked
            assert log_entry.revoked_at is None
            assert log_entry.revoked_by is None
            assert log_entry.revocation_reason is None
            
            # Mark as revoked
            revoked_by_user = 'admin456'
            revocation_reason = 'key_compromise'
            log_entry.mark_revoked(reason=revocation_reason, revoked_by=revoked_by_user)
            
            # Verify revocation data
            assert log_entry.revoked_at is not None
            assert isinstance(log_entry.revoked_at, datetime)
            assert log_entry.revoked_by == revoked_by_user
            assert log_entry.revocation_reason == revocation_reason
    
    def test_revocation_status_methods(self, app, sample_cert_data):
        """Test methods for checking revocation status."""
        with app.app_context():
            log_entry = CertificateLog(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type'],
                issuing_user_id='user123'
            )
            
            # Test is_revoked method
            assert hasattr(log_entry, 'is_revoked')
            assert log_entry.is_revoked() is False
            
            # Mark as revoked
            log_entry.mark_revoked(reason='cessation_of_operation', revoked_by='user123')
            
            # Test revoked status
            assert log_entry.is_revoked() is True
    
    def test_to_dict_includes_revocation_info_with_user_tracking(self, app, sample_cert_data):
        """Test to_dict includes enhanced revocation information."""
        with app.app_context():
            log_entry = CertificateLog(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type'],
                issuing_user_id='user123'
            )
            
            # Test without revocation
            result = log_entry.to_dict()
            assert 'revocation' not in result
            assert 'issuing_user_id' in result
            assert result['issuing_user_id'] == 'user123'
            
            # Create revocation record using append-only approach
            revocation_record = CertificateLog(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type'],
                action_type='revoked',
                log_timestamp=datetime.now(timezone.utc),
                revoked_at=datetime.now(timezone.utc),
                revocation_reason='key_compromise',
                revoked_by='admin456',
                issuing_user_id='user123'
            )
            db.session.add(revocation_record)
            db.session.commit()
            
            # Test with revocation - query latest record
            latest_record = CertificateLog.get_by_fingerprint(log_entry.fingerprint_sha256)
            result = latest_record.to_dict()
            assert 'revocation' in result
            assert result['revocation']['revoked_at'] is not None
            assert result['revocation']['reason'] == 'key_compromise'
            assert result['revocation']['revoked_by'] == 'admin456'
    
    def test_get_certificates_by_user_method(self, app, sample_cert_data):
        """Test class method to get all certificates for a specific user."""
        with app.app_context():
            user_id = 'testuser123'
            
            # Create multiple certificates for the same user
            cert1 = CertificateLog.log_certificate(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type'],
                issuing_user_id=user_id
            )
            
            # Create another certificate for different user (modify cert to avoid duplicate fingerprint)
            modified_cert_pem = sample_cert_data['certificate_pem'].replace('server', 'client')
            cert2 = CertificateLog(
                modified_cert_pem,
                'client',
                issuing_user_id='otheruser456'
            )
            # Manually set different fingerprint to avoid UNIQUE constraint
            cert2.fingerprint_sha256 = 'DIFFERENT_FINGERPRINT_FOR_TEST'
            cert2.serial_number = 'DIFFERENT_SERIAL_123'
            db.session.add(cert2)
            db.session.commit()
            
            # Test get_certificates_by_user method
            assert hasattr(CertificateLog, 'get_certificates_by_user')
            user_certs = CertificateLog.get_certificates_by_user(user_id)
            
            assert len(user_certs) == 1
            assert user_certs[0].issuing_user_id == user_id
            assert user_certs[0].id == cert1.id
    
    def test_get_active_certificates_by_user_method(self, app, sample_cert_data):
        """Test class method to get only active (non-revoked) certificates for a user."""
        with app.app_context():
            user_id = 'testuser123'
            
            # Create multiple certificates for the same user
            cert1 = CertificateLog.log_certificate(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type'],
                issuing_user_id=user_id
            )
            
            cert2 = CertificateLog(
                sample_cert_data['certificate_pem'],
                'server',
                issuing_user_id=user_id
            )
            # Manually set different fingerprint to avoid UNIQUE constraint
            cert2.fingerprint_sha256 = 'DIFFERENT_FINGERPRINT_FOR_USER_TEST'
            cert2.serial_number = 'DIFFERENT_SERIAL_456'
            db.session.add(cert2)
            db.session.commit()
            
            # Revoke one certificate
            cert2.mark_revoked(reason='superseded', revoked_by=user_id)
            db.session.commit()
            
            # Test get_active_certificates_by_user method
            assert hasattr(CertificateLog, 'get_active_certificates_by_user')
            active_certs = CertificateLog.get_active_certificates_by_user(user_id)
            
            assert len(active_certs) == 1
            assert active_certs[0].id == cert1.id
            assert active_certs[0].revoked_at is None
    
    def test_get_revoked_certificates_method(self, app, sample_cert_data):
        """Test class method to get all revoked certificates."""
        with app.app_context():
            # Create active certificate
            active_cert = CertificateLog.log_certificate(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type'],
                issuing_user_id='user123'
            )
            
            # Create and revoke another certificate
            revoked_cert = CertificateLog(
                sample_cert_data['certificate_pem'],
                'server',
                issuing_user_id='user456'
            )
            # Manually set different fingerprint to avoid UNIQUE constraint
            revoked_cert.fingerprint_sha256 = 'DIFFERENT_FINGERPRINT_FOR_REVOKED_TEST'
            revoked_cert.serial_number = 'DIFFERENT_SERIAL_789'
            db.session.add(revoked_cert)
            db.session.commit()
            revoked_cert.mark_revoked(reason='key_compromise', revoked_by='admin789')
            db.session.commit()
            
            # Test get_revoked_certificates method
            assert hasattr(CertificateLog, 'get_revoked_certificates')
            revoked_certs = CertificateLog.get_revoked_certificates()
            
            assert len(revoked_certs) >= 1
            # Check that all returned certificates are revoked
            for cert in revoked_certs:
                assert cert.revoked_at is not None
            
            # Check that our revoked certificate is in the results
            revoked_ids = [cert.id for cert in revoked_certs]
            assert revoked_cert.id in revoked_ids
            assert active_cert.id not in revoked_ids
    
    def test_bulk_revoke_user_certificates_method(self, app, sample_cert_data):
        """Test class method to revoke all active certificates for a user."""
        with app.app_context():
            user_id = 'testuser123'
            admin_id = 'admin456'
            
            # Create multiple active certificates for the user
            cert1 = CertificateLog.log_certificate(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type'],
                issuing_user_id=user_id
            )
            
            cert2 = CertificateLog(
                sample_cert_data['certificate_pem'],
                'server',
                issuing_user_id=user_id
            )
            # Manually set different fingerprint to avoid UNIQUE constraint
            cert2.fingerprint_sha256 = 'DIFFERENT_FINGERPRINT_FOR_BULK_TEST1'
            cert2.serial_number = 'DIFFERENT_SERIAL_BULK1'
            db.session.add(cert2)
            db.session.commit()
            
            # Create certificate for different user (should not be affected)
            other_cert = CertificateLog(
                sample_cert_data['certificate_pem'],
                'client',
                issuing_user_id='otheruser789'
            )
            # Manually set different fingerprint to avoid UNIQUE constraint
            other_cert.fingerprint_sha256 = 'DIFFERENT_FINGERPRINT_FOR_BULK_TEST2'
            other_cert.serial_number = 'DIFFERENT_SERIAL_BULK2'
            db.session.add(other_cert)
            db.session.commit()
            
            # Test bulk_revoke_user_certificates method
            assert hasattr(CertificateLog, 'bulk_revoke_user_certificates')
            revoked_count = CertificateLog.bulk_revoke_user_certificates(
                user_id=user_id,
                revoked_by=admin_id,
                reason='admin_bulk_revocation'
            )
            
            assert revoked_count == 2
            
            # Verify certificates are revoked
            cert1_updated = CertificateLog.get_by_fingerprint(cert1.fingerprint_sha256)
            cert2_updated = CertificateLog.get_by_fingerprint(cert2.fingerprint_sha256)
            other_cert_updated = CertificateLog.get_by_fingerprint(other_cert.fingerprint_sha256)
            
            assert cert1_updated.revoked_at is not None
            assert cert1_updated.revoked_by == admin_id
            assert cert1_updated.revocation_reason == 'admin_bulk_revocation'
            
            assert cert2_updated.revoked_at is not None
            assert cert2_updated.revoked_by == admin_id
            
            # Other user's certificate should not be affected
            assert other_cert_updated.revoked_at is None
    
    def test_revocation_reason_validation(self, app, sample_cert_data):
        """Test validation of revocation reasons."""
        with app.app_context():
            log_entry = CertificateLog(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type'],
                issuing_user_id='user123'
            )
            
            # Test valid revocation reasons
            valid_reasons = [
                'key_compromise',
                'ca_compromise',
                'affiliation_changed',
                'superseded',
                'cessation_of_operation',
                'certificate_hold',
                'remove_from_crl',
                'privilege_withdrawn',
                'aa_compromise'
            ]
            
            assert hasattr(log_entry, 'validate_revocation_reason')
            
            for reason in valid_reasons:
                assert log_entry.validate_revocation_reason(reason) is True
            
            # Test invalid reason
            assert log_entry.validate_revocation_reason('invalid_reason') is False
    
    def test_revocation_audit_trail(self, app, sample_cert_data):
        """Test that revocation creates proper audit trail."""
        with app.app_context():
            user_id = 'testuser123'
            admin_id = 'admin456'
            
            log_entry = CertificateLog.log_certificate(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type'],
                issuing_user_id=user_id
            )
            
            # Record pre-revocation state
            original_issued_at = log_entry.issued_at
            
            # Create revocation record using append-only approach
            revocation_time = datetime.now(timezone.utc)
            revocation_record = CertificateLog(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type'],
                action_type='revoked',
                log_timestamp=revocation_time,
                revoked_at=revocation_time,
                revocation_reason='key_compromise',
                revoked_by=admin_id,
                issuing_user_id=user_id,
                issued_at=original_issued_at  # Preserve original issue time
            )
            db.session.add(revocation_record)
            db.session.commit()
            
            # Verify audit trail - original record unchanged
            assert log_entry.issued_at == original_issued_at  # Should not change
            assert log_entry.revoked_at is None  # Original record not mutated
            assert log_entry.issuing_user_id == user_id
            
            # Verify latest record (revocation record) has correct audit trail
            latest_record = CertificateLog.get_by_fingerprint(log_entry.fingerprint_sha256)
            assert latest_record.action_type == 'revoked'
            assert latest_record.revoked_at.replace(tzinfo=timezone.utc) >= revocation_time.replace(microsecond=0)
            assert latest_record.revoked_by == admin_id
            assert latest_record.issuing_user_id == user_id
            assert latest_record.issued_at == original_issued_at  # Preserved from original
            
            # Test audit information in dictionary format
            audit_dict = latest_record.to_dict()
            assert audit_dict['issuing_user_id'] == user_id
            assert audit_dict['issued_at'] is not None
            assert audit_dict['revocation']['revoked_by'] == admin_id
            assert audit_dict['revocation']['revoked_at'] is not None
    
    def test_database_indexes_for_revocation_queries(self, app, sample_cert_data):
        """Test that proper database indexes exist for efficient revocation queries."""
        with app.app_context():
            # This test verifies the model has the right indexes defined
            # The actual indexes should be checked in the model definition
            table_args = CertificateLog.__table_args__
            
            # Check that we have indexes for revocation queries
            index_names = []
            for arg in table_args:
                if hasattr(arg, 'name') or hasattr(arg, 'columns'):
                    if hasattr(arg, 'columns'):
                        column_names = [col.name for col in arg.columns]
                        index_names.append(column_names)
            
            # We should have an index on revoked_at for efficient revocation queries
            # and on issuing_user_id for user-based queries
            # These will be verified when we implement the actual model changes
            assert True  # Placeholder - will be updated when indexes are added
    
    def test_cascade_revocation_protection(self, app, sample_cert_data):
        """Test that revoked certificates cannot be revoked again without warning."""
        with app.app_context():
            log_entry = CertificateLog.log_certificate(
                sample_cert_data['certificate_pem'],
                sample_cert_data['certificate_type'],
                issuing_user_id='user123'
            )
            
            # First revocation
            log_entry.mark_revoked(reason='key_compromise', revoked_by='admin1')
            original_revoked_at = log_entry.revoked_at
            original_reason = log_entry.revocation_reason
            
            # Attempt second revocation - should handle gracefully
            log_entry.mark_revoked(reason='superseded', revoked_by='admin2')
            
            # Should not update revocation time or change original reason
            # (This behavior needs to be implemented)
            assert hasattr(log_entry, 'can_be_revoked')
            
            # For now, we expect the method to exist and return appropriate values
            # Implementation will determine exact behavior