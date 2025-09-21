"""
Certificate Transparency Log Model.

This model stores certificate transparency logs for all certificates
issued by the OpenVPN Manager system, providing a public audit trail
for certificate issuance.
"""

import json
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, Index
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes

from app.extensions import db
from app.utils.certificate_validator import validate_certificate_format, CertificateValidationError


class CertificateLog(db.Model):
    """
    Certificate Transparency Log entry.
    
    This model stores information about every certificate issued
    by the system for transparency and audit purposes.
    """
    
    __tablename__ = 'certificate_logs'
    
    # Composite index for efficient append-only queries
    __table_args__ = (
        Index('ix_fingerprint_timestamp', 'fingerprint_sha256', 'log_timestamp'),
        Index('ix_action_timestamp', 'action_type', 'log_timestamp'),
    )
    
    # Primary key - auto-incrementing log entry ID
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Certificate identification
    serial_number = Column(String(64), nullable=False, index=True)
    fingerprint_sha256 = Column(String(64), nullable=False, index=True)  # Removed unique=True for append-only
    
    # Append-only CT fields
    action_type = Column(String(20), nullable=False, default='issued', index=True)  # 'issued', 'revoked'
    log_timestamp = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    
    # Request metadata (for security and audit)
    requester_ip = Column(String(45), nullable=True, index=True)  # IPv4/IPv6 address
    requester_country = Column(String(2), nullable=True, index=True)  # ISO country code
    requester_user_agent = Column(Text, nullable=True)  # Full user agent string
    requester_os = Column(String(50), nullable=True)  # Detected OS from user agent

    # Extended requester metadata (from frontend request details)
    user_email = Column(String(255), nullable=True)  # User email from OIDC
    os_version = Column(String(50), nullable=True)  # OS version details
    browser = Column(String(50), nullable=True)  # Browser name
    browser_version = Column(String(50), nullable=True)  # Browser version
    is_mobile = Column(Boolean, nullable=True)  # Mobile device detection
    request_timestamp = Column(DateTime(timezone=True), nullable=True)  # Original request timestamp from frontend
    
    # Certificate details
    subject_common_name = Column(String(255), nullable=False, index=True)
    subject_organization = Column(String(255), nullable=True)
    subject_organizational_unit = Column(String(255), nullable=True)
    subject_country = Column(String(2), nullable=True)
    subject_state = Column(String(255), nullable=True)
    subject_locality = Column(String(255), nullable=True)
    
    # Issuer information
    issuer_common_name = Column(String(255), nullable=False)
    issuer_organization = Column(String(255), nullable=True)
    
    # Validity period
    not_before = Column(DateTime(timezone=True), nullable=False, index=True)
    not_after = Column(DateTime(timezone=True), nullable=False, index=True)
    
    # Certificate data
    certificate_pem = Column(Text, nullable=False)
    public_key_algorithm = Column(String(50), nullable=False)
    signature_algorithm = Column(String(50), nullable=False)
    key_size = Column(Integer, nullable=True)
    
    # Extensions
    subject_alt_names = Column(Text, nullable=True)  # JSON array of SANs
    key_usage = Column(Text, nullable=True)  # JSON array of key usages
    extended_key_usage = Column(Text, nullable=True)  # JSON array of extended key usages
    
    # Certificate type and purpose
    certificate_type = Column(String(50), nullable=False, index=True)  # 'client', 'server', 'intermediate'
    certificate_purpose = Column(String(100), nullable=True)  # Additional purpose description
    
    # Audit trail
    issued_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    issued_by_service = Column(String(50), nullable=False, default='signing_service')
    request_source = Column(String(100), nullable=True)  # Source of certificate request
    issuing_user_id = Column(String(255), nullable=True, index=True)  # OIDC subject ID of requesting user
    
    # Revocation information
    revoked_at = Column(DateTime(timezone=True), nullable=True, index=True)
    revocation_reason = Column(String(100), nullable=True)
    revoked_by = Column(String(255), nullable=True)  # User ID who performed revocation

    # Validation results
    validation_warnings = Column(Text, nullable=True)  # JSON array of validation warnings
    
    # Database indexes for efficient queries
    __table_args__ = (
        Index('idx_ct_issued_at_type', 'issued_at', 'certificate_type'),
        Index('idx_ct_validity_period', 'not_before', 'not_after'),
        Index('idx_ct_subject_cn_issued', 'subject_common_name', 'issued_at'),
        Index('idx_ct_issuing_user_id', 'issuing_user_id'),
        Index('idx_ct_revoked_at', 'revoked_at'),
        Index('idx_ct_user_revocation', 'issuing_user_id', 'revoked_at'),
    )
    
    def __init__(self, certificate_pem, certificate_type, **kwargs):
        """
        Initialize a certificate log entry from a PEM certificate.

        Args:
            certificate_pem (str): PEM-encoded certificate
            certificate_type (str): Type of certificate ('client', 'server', 'intermediate')
            **kwargs: Additional fields to set

        Raises:
            CertificateValidationError: If certificate validation fails
        """
        # Check if validation should be bypassed (for testing)
        skip_validation = kwargs.pop('skip_validation', False)

        if skip_validation:
            # Parse certificate without validation for testing
            cert = x509.load_pem_x509_certificate(certificate_pem.encode('utf-8'))
        else:
            # Enhanced certificate validation and parsing
            cert, validation_results = validate_certificate_format(certificate_pem, certificate_type)

            # Store validation results for audit purposes
            if validation_results.get('warnings'):
                kwargs.setdefault('validation_warnings', json.dumps(validation_results['warnings']))
        
        # Basic certificate information
        self.certificate_pem = certificate_pem
        self.certificate_type = certificate_type
        self.serial_number = format(cert.serial_number, 'x').upper()
        
        # Calculate SHA-256 fingerprint
        fingerprint = cert.fingerprint(algorithm=hashes.SHA256())
        self.fingerprint_sha256 = fingerprint.hex().upper()
        
        # Subject information
        subject = cert.subject
        self.subject_common_name = self._get_name_attribute(subject, x509.NameOID.COMMON_NAME)
        self.subject_organization = self._get_name_attribute(subject, x509.NameOID.ORGANIZATION_NAME)
        self.subject_organizational_unit = self._get_name_attribute(subject, x509.NameOID.ORGANIZATIONAL_UNIT_NAME)
        self.subject_country = self._get_name_attribute(subject, x509.NameOID.COUNTRY_NAME)
        self.subject_state = self._get_name_attribute(subject, x509.NameOID.STATE_OR_PROVINCE_NAME)
        self.subject_locality = self._get_name_attribute(subject, x509.NameOID.LOCALITY_NAME)
        
        # Issuer information
        issuer = cert.issuer
        self.issuer_common_name = self._get_name_attribute(issuer, x509.NameOID.COMMON_NAME)
        self.issuer_organization = self._get_name_attribute(issuer, x509.NameOID.ORGANIZATION_NAME)
        
        # Validity period
        self.not_before = cert.not_valid_before_utc.replace(tzinfo=timezone.utc)
        self.not_after = cert.not_valid_after_utc.replace(tzinfo=timezone.utc)
        
        # Public key information
        public_key = cert.public_key()
        self.public_key_algorithm = public_key.__class__.__name__.replace('Public', '').replace('Key', '')
        
        # Get key size if available
        if hasattr(public_key, 'key_size'):
            self.key_size = public_key.key_size
        
        # Signature algorithm
        self.signature_algorithm = cert.signature_algorithm_oid._name
        
        # Process extensions
        self._process_extensions(cert)
        
        # Set append-only CT fields
        self.action_type = 'issued'  # All new certificates start as 'issued'
        self.log_timestamp = datetime.now(timezone.utc)
        
        # Set any additional fields
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
    
    def _get_name_attribute(self, name, oid):
        """Get a specific attribute from a certificate name."""
        try:
            return name.get_attributes_for_oid(oid)[0].value
        except (IndexError, AttributeError):
            return None
    
    def _process_extensions(self, cert):
        """Process certificate extensions and store relevant information."""
        # Subject Alternative Names
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_list = []
            for san in san_ext.value:
                if isinstance(san, x509.DNSName):
                    san_list.append(f"DNS:{san.value}")
                elif isinstance(san, x509.IPAddress):
                    san_list.append(f"IP:{san.value}")
                elif isinstance(san, x509.RFC822Name):
                    san_list.append(f"email:{san.value}")
            if san_list:
                self.subject_alt_names = json.dumps(san_list)
        except x509.ExtensionNotFound:
            pass
        
        # Key Usage
        try:
            ku_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.KEY_USAGE)
            key_usage = []
            ku = ku_ext.value
            if ku.digital_signature:
                key_usage.append("digital_signature")
            if ku.key_encipherment:
                key_usage.append("key_encipherment")
            if ku.key_agreement:
                key_usage.append("key_agreement")
            if ku.key_cert_sign:
                key_usage.append("key_cert_sign")
            if ku.crl_sign:
                key_usage.append("crl_sign")
            if key_usage:
                self.key_usage = json.dumps(key_usage)
        except x509.ExtensionNotFound:
            pass
        
        # Extended Key Usage
        try:
            eku_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.EXTENDED_KEY_USAGE)
            eku_list = []
            for eku in eku_ext.value:
                if eku == x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH:
                    eku_list.append("client_auth")
                elif eku == x509.oid.ExtendedKeyUsageOID.SERVER_AUTH:
                    eku_list.append("server_auth")
                elif eku == x509.oid.ExtendedKeyUsageOID.CODE_SIGNING:
                    eku_list.append("code_signing")
                elif eku == x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION:
                    eku_list.append("email_protection")
            if eku_list:
                self.extended_key_usage = json.dumps(eku_list)
        except x509.ExtensionNotFound:
            pass
    
    def to_dict(self, include_pem=False):
        """
        Convert the certificate log entry to a dictionary.
        
        Args:
            include_pem (bool): Whether to include the full PEM certificate
            
        Returns:
            dict: Dictionary representation of the certificate log entry
        """
        data = {
            'id': self.id,
            'serial_number': self.serial_number,
            'fingerprint_sha256': self.fingerprint_sha256,
            'subject': {
                'common_name': self.subject_common_name,
                'organization': self.subject_organization,
                'organizational_unit': self.subject_organizational_unit,
                'country': self.subject_country,
                'state': self.subject_state,
                'locality': self.subject_locality,
            },
            'issuer': {
                'common_name': self.issuer_common_name,
                'organization': self.issuer_organization,
            },
            'validity': {
                'not_before': self.not_before.isoformat() if self.not_before else None,
                'not_after': self.not_after.isoformat() if self.not_after else None,
            },
            'public_key': {
                'algorithm': self.public_key_algorithm,
                'size': self.key_size,
            },
            'signature_algorithm': self.signature_algorithm,
            'certificate_type': self.certificate_type,
            'certificate_purpose': self.certificate_purpose,
            'issued_at': self.issued_at.isoformat() if self.issued_at else None,
            'issued_by_service': self.issued_by_service,
            'request_source': self.request_source,
        }
        
        # Add extensions if present
        if self.subject_alt_names:
            data['subject_alt_names'] = json.loads(self.subject_alt_names)
        if self.key_usage:
            data['key_usage'] = json.loads(self.key_usage)
        if self.extended_key_usage:
            data['extended_key_usage'] = json.loads(self.extended_key_usage)

        # Add validation warnings if present
        if self.validation_warnings:
            data['validation_warnings'] = json.loads(self.validation_warnings)
        
        # Add user tracking information
        data['issuing_user_id'] = self.issuing_user_id

        # Add requester metadata for audit trail
        data['requester_info'] = {
            'ip': self.requester_ip,
            'country': self.requester_country,
            'user_agent': self.requester_user_agent,
            'os': self.requester_os,
        }

        # Add additional metadata if available via dynamic attributes
        extra_metadata = {}
        for attr in ['user_email', 'os_version', 'browser', 'browser_version', 'is_mobile', 'request_timestamp']:
            if hasattr(self, attr):
                value = getattr(self, attr)
                if value is not None:
                    extra_metadata[attr] = value

        if extra_metadata:
            data['requester_info'].update(extra_metadata)

        # Add append-only CT fields
        data['action_type'] = self.action_type
        data['log_timestamp'] = self.log_timestamp.isoformat() if self.log_timestamp else None

        # Add revocation information if this is a revocation record
        if self.action_type == 'revoked' and self.revoked_at:
            data['revocation'] = {
                'revoked_at': self.revoked_at.isoformat(),
                'reason': self.revocation_reason,
                'revoked_by': self.revoked_by,
            }
            # Also add legacy revoked_at field for backward compatibility
            data['revoked_at'] = self.revoked_at.isoformat()
        
        # Include PEM if requested
        if include_pem:
            data['certificate_pem'] = self.certificate_pem
        
        return data
    
    def mark_revoked(self, reason=None, revoked_by=None):
        """
        Mark this certificate as revoked.
        
        Args:
            reason (str): Reason for revocation
            revoked_by (str): User ID who performed the revocation
        """
        self.revoked_at = datetime.now(timezone.utc)
        self.revocation_reason = reason
        self.revoked_by = revoked_by
        self.action_type = 'revoked'  # Set action_type for append-only CT architecture
    
    @classmethod
    def log_certificate(cls, certificate_pem, certificate_type, **kwargs):
        """
        Create and save a certificate log entry.

        For append-only CT logs, we should not log the same certificate twice.
        This method checks for duplicates and raises an error if the certificate
        has already been logged.

        Args:
            certificate_pem (str): PEM-encoded certificate
            certificate_type (str): Type of certificate
            **kwargs: Additional fields (including optional skip_validation for testing)

        Returns:
            CertificateLog: Created certificate log entry

        Raises:
            ValueError: If the certificate has already been logged
        """
        # Create a temporary instance to get the fingerprint
        temp_entry = cls(certificate_pem, certificate_type, **kwargs)

        # Append-only CT architecture: Log every interaction as a separate event
        # Duplicates are allowed as they represent separate logging events
        db.session.add(temp_entry)
        db.session.commit()
        return temp_entry
    
    @classmethod
    def get_by_fingerprint(cls, fingerprint):
        """Get most recent certificate log entry by SHA-256 fingerprint."""
        return cls.query.filter_by(fingerprint_sha256=fingerprint.upper()).order_by(cls.log_timestamp.desc()).first()
    
    @classmethod
    def get_latest_certificates(cls, limit=100, offset=0, filters=None, sort_field='log_timestamp', sort_order='desc'):
        """
        Get the most recent record for each unique fingerprint (append-only CT design).
        
        Args:
            limit (int): Maximum number of certificates to return
            offset (int): Number of records to skip
            filters (dict): Filter criteria
            sort_field (str): Field to sort by
            sort_order (str): Sort order ('asc' or 'desc')
            
        Returns:
            tuple: (certificates_list, total_count)
        """
        from sqlalchemy import func, and_, or_
        
        # Subquery to find the maximum log_timestamp for each fingerprint
        subquery = cls.query.with_entities(
            cls.fingerprint_sha256,
            func.max(cls.log_timestamp).label('max_timestamp')
        ).group_by(cls.fingerprint_sha256).subquery()
        
        # Main query to get the full records with the latest timestamp per fingerprint
        query = cls.query.join(
            subquery,
            and_(
                cls.fingerprint_sha256 == subquery.c.fingerprint_sha256,
                cls.log_timestamp == subquery.c.max_timestamp
            )
        )
        
        # Apply filters if provided
        if filters:
            if filters.get('type'):
                query = query.filter(cls.certificate_type == filters['type'])
            if filters.get('subject'):
                query = query.filter(cls.subject_common_name.contains(filters['subject']))
            if filters.get('issuer'):
                query = query.filter(cls.issuer_common_name.contains(filters['issuer']))
            if filters.get('serial'):
                query = query.filter(cls.serial_number == filters['serial'].upper())
            if filters.get('fingerprint'):
                query = query.filter(cls.fingerprint_sha256 == filters['fingerprint'].upper())
            if filters.get('from_date'):
                try:
                    from_dt = datetime.fromisoformat(filters['from_date'].replace('Z', '+00:00'))
                    query = query.filter(cls.issued_at >= from_dt)
                except ValueError:
                    pass  # Invalid date format, skip filter
            if filters.get('to_date'):
                try:
                    to_dt = datetime.fromisoformat(filters['to_date'].replace('Z', '+00:00'))
                    query = query.filter(cls.issued_at <= to_dt)
                except ValueError:
                    pass  # Invalid date format, skip filter
            if filters.get('include_revoked') == 'false':
                # Only show non-revoked certificates (action_type != 'revoked')
                query = query.filter(cls.action_type != 'revoked')
        
        # Get capped count to prevent expensive full table scans on large datasets
        # This prevents DoS attacks through complex filter queries
        MAX_COUNT_LIMIT = 10000  # Reasonable limit for pagination UI
        
        try:
            # Use a subquery with LIMIT to avoid counting all rows
            count_query = query.limit(MAX_COUNT_LIMIT + 1)
            count_result = count_query.count()
            total_count = min(count_result, MAX_COUNT_LIMIT)
        except Exception:  # pragma: no cover
            
            ## PRAGMA-NO-COVER Exception; JS 2025-09-03 DDoS protection but hard to test

            # Fallback to a safe default if count query fails
            total_count = limit  # At least show current page worth
        
        # Apply sorting
        sort_column = getattr(cls, sort_field, cls.log_timestamp)
        if sort_order.lower() == 'asc':
            query = query.order_by(sort_column.asc())
        else:
            query = query.order_by(sort_column.desc())
        
        # Apply pagination
        query = query.offset(offset).limit(limit)
        
        return query.all(), total_count
    
    @classmethod
    def get_by_serial_number(cls, serial_number):
        """Get certificate log entry by serial number."""
        return cls.query.filter_by(serial_number=serial_number.upper()).first()
    
    @classmethod
    def get_certificates_by_subject(cls, common_name):
        """Get all certificates for a given subject common name."""
        return cls.query.filter_by(subject_common_name=common_name).order_by(cls.issued_at.desc()).all()
    
    @classmethod
    def get_recent_certificates(cls, limit=100, certificate_type=None):
        """Get recently issued certificates."""
        query = cls.query
        if certificate_type:
            query = query.filter_by(certificate_type=certificate_type)
        return query.order_by(cls.issued_at.desc()).limit(limit).all()
    
    def is_revoked(self):
        """Check if this certificate is revoked."""
        return self.revoked_at is not None
    
    @classmethod
    def get_certificates_by_user(cls, user_id):
        """Get all certificates for a specific user."""
        return cls.query.filter_by(issuing_user_id=user_id).order_by(cls.issued_at.desc()).all()
    
    @classmethod
    def get_active_certificates_by_user(cls, user_id):
        """Get only active (non-revoked) certificates for a user."""
        return cls.query.filter_by(issuing_user_id=user_id, revoked_at=None).order_by(cls.issued_at.desc()).all()
    
    @classmethod
    def get_revoked_certificates(cls, limit=None):
        """Get all revoked certificates."""
        query = cls.query.filter(cls.revoked_at.isnot(None)).order_by(cls.revoked_at.desc())
        if limit:
            query = query.limit(limit)
        return query.all()
    
    @classmethod
    def bulk_revoke_user_certificates(cls, user_id, revoked_by, reason='admin_bulk_revocation'):
        """
        Revoke all active certificates for a specific user.
        
        Args:
            user_id (str): User ID whose certificates should be revoked
            revoked_by (str): User ID who performed the revocation
            reason (str): Reason for revocation
            
        Returns:
            int: Number of certificates revoked
        """
        active_certificates = cls.get_active_certificates_by_user(user_id)
        count = 0
        
        for cert in active_certificates:
            cert.mark_revoked(reason=reason, revoked_by=revoked_by)
            count += 1
        
        db.session.commit()
        return count
    
    def validate_revocation_reason(self, reason):
        """
        Validate that the revocation reason is one of the standard reasons.
        
        Args:
            reason (str): Revocation reason to validate
            
        Returns:
            bool: True if valid, False otherwise
        """
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
        return reason in valid_reasons
    
    def can_be_revoked(self):
        """
        Check if this certificate can be revoked (i.e., is not already revoked).
        
        Returns:
            bool: True if certificate can be revoked, False if already revoked
        """
        return self.revoked_at is None
    
    def __repr__(self):
        return f'<CertificateLog {self.subject_common_name} ({self.certificate_type})>'