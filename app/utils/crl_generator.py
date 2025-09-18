"""
Certificate Revocation List (CRL) Generator

This module provides functionality to generate X.509 Certificate Revocation Lists
from the Certificate Transparency database.
"""

import os
from datetime import datetime, timezone, timedelta
from typing import List, Optional
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from app.utils.environment import loadConfigValueFromFileOrEnvironment


class CRLGenerator:
    """
    Generates Certificate Revocation Lists (CRLs) from revoked certificates.
    
    This class handles the creation of properly formatted X.509 CRLs that can be
    consumed by OpenVPN servers and other certificate validation systems.
    """
    
    def __init__(self, ca_cert_path=None, ca_key_path=None, ca_key_passphrase=None):
        """
        Initialize the CRL generator.
        
        Args:
            ca_cert_path (str, optional): Path to CA certificate file
            ca_key_path (str, optional): Path to CA private key file
            ca_key_passphrase (str, optional): Passphrase for CA private key
        """
        self.ca_cert_path = ca_cert_path
        self.ca_key_path = ca_key_path
        self.ca_key_passphrase = ca_key_passphrase
        
        # Internal state
        self._ca_certificate = None
        self._ca_private_key = None
        self._crl_number = self._get_next_crl_number()
        
        # Try to load CA materials from config if paths provided
        if ca_cert_path and ca_key_path:
            self._load_ca_materials_from_files()
    
    def load_ca_materials(self, ca_cert_pem: str, ca_key_pem: str, ca_key_passphrase: str):
        """
        Load CA certificate and private key from PEM strings.
        
        Args:
            ca_cert_pem (str): PEM-encoded CA certificate
            ca_key_pem (str): PEM-encoded CA private key
            ca_key_passphrase (str): Passphrase for CA private key
            
        Raises:
            ValueError: If certificate or key PEM is invalid
        """
        try:
            # Load CA certificate
            self._ca_certificate = x509.load_pem_x509_certificate(ca_cert_pem.encode('utf-8'))
            
            # Load CA private key
            self._ca_private_key = serialization.load_pem_private_key(
                ca_key_pem.encode('utf-8'),
                password=ca_key_passphrase.encode('utf-8') if ca_key_passphrase else None
            )
            
        except Exception as e:
            raise ValueError(f"Invalid CA certificate or key: {str(e)}")
    
    def _load_ca_materials_from_files(self):
        """Load CA materials from file paths."""
        try:
            # Load CA certificate
            if self.ca_cert_path and os.path.exists(self.ca_cert_path):
                with open(self.ca_cert_path, 'r') as f:
                    ca_cert_pem = f.read()
            else:
                # Try to load from environment/config
                ca_cert_pem = loadConfigValueFromFileOrEnvironment('INTERMEDIATE_CA_CERTIFICATE', '')
            
            # Load CA private key
            if self.ca_key_path and os.path.exists(self.ca_key_path):
                with open(self.ca_key_path, 'r') as f:
                    ca_key_pem = f.read()
            else:
                # Try to load from environment/config
                ca_key_pem = loadConfigValueFromFileOrEnvironment('INTERMEDIATE_CA_PRIVATE_KEY', '')
            
            # Get passphrase
            passphrase = self.ca_key_passphrase or loadConfigValueFromFileOrEnvironment('INTERMEDIATE_CA_KEY_PASSPHRASE', '')
            
            if ca_cert_pem and ca_key_pem:
                self.load_ca_materials(ca_cert_pem, ca_key_pem, passphrase)
                
        except Exception as e: # pragma: no cover
            ## PRAGMA-NO-COVER Exception; JS 2025-09-03 Filesystem Exception requires FS bug to test.
            pass
    
    def create_crl(self, revoked_certificates: List, next_update_hours: int = 24) -> bytes:
        """
        Create a Certificate Revocation List from revoked certificates.
        
        Args:
            revoked_certificates (List): List of CertificateLog objects that are revoked
            next_update_hours (int): Hours until next CRL update (default: 24)
            
        Returns:
            bytes: DER-encoded CRL
            
        Raises:
            RuntimeError: If CA materials are not loaded
        """
        if not self._ca_certificate or not self._ca_private_key:
            raise RuntimeError("CA materials not loaded. Call load_ca_materials() first.")
        
        # Build revoked certificate entries
        revoked_cert_list = []
        
        for cert_log in revoked_certificates:
            # Convert hex serial number to integer
            serial_number = int(cert_log.serial_number, 16)
            
            # Parse revocation date
            revocation_date = cert_log.revoked_at
            if revocation_date.tzinfo is None:
                revocation_date = revocation_date.replace(tzinfo=timezone.utc)
            
            # Create revoked certificate entry
            builder = x509.RevokedCertificateBuilder()
            builder = builder.serial_number(serial_number)
            builder = builder.revocation_date(revocation_date)
            
            # Add revocation reason if available
            if cert_log.revocation_reason:
                reason_flag = self._map_revocation_reason(cert_log.revocation_reason)
                if reason_flag:
                    builder = builder.add_extension(
                        x509.CRLReason(reason_flag),
                        critical=False
                    )
            
            revoked_cert_list.append(builder.build())
        
        # Build CRL
        now = datetime.now(timezone.utc)
        next_update = now + timedelta(hours=next_update_hours)
        
        crl_builder = x509.CertificateRevocationListBuilder()
        crl_builder = crl_builder.issuer_name(self._ca_certificate.subject)
        crl_builder = crl_builder.last_update(now)
        crl_builder = crl_builder.next_update(next_update)
        
        # Add all revoked certificates
        for revoked_cert in revoked_cert_list:
            crl_builder = crl_builder.add_revoked_certificate(revoked_cert)
        
        # Add CRL extensions
        crl_builder = self._add_crl_extensions(crl_builder)
        
        # Sign the CRL
        crl = crl_builder.sign(self._ca_private_key, hashes.SHA256())
        
        # Increment CRL number for next time
        self._crl_number += 1
        
        # Return DER-encoded CRL
        return crl.public_bytes(serialization.Encoding.DER)
    
    def get_current_crl(self) -> bytes:
        """
        Get the current CRL with all revoked certificates.
        
        Returns:
            bytes: DER-encoded current CRL
        """
        # Import here to avoid circular imports
        from app.models.certificate_log import CertificateLog
        
        revoked_certificates = CertificateLog.get_revoked_certificates()
        return self.create_crl(revoked_certificates)
    
    def _add_crl_extensions(self, crl_builder):
        """
        Add standard CRL extensions.
        
        Args:
            crl_builder: CRL builder object
            
        Returns:
            CRL builder with extensions added
        """
        # Add CRL Number extension
        crl_builder = crl_builder.add_extension(
            x509.CRLNumber(self._crl_number),
            critical=False
        )
        
        # Add Authority Key Identifier if possible
        try:
            # Extract Subject Key Identifier from CA certificate
            ski_ext = self._ca_certificate.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER
            )
            
            aki = x509.AuthorityKeyIdentifier(
                key_identifier=ski_ext.value.key_identifier,
                authority_cert_issuer=None,
                authority_cert_serial_number=None
            )
            
            crl_builder = crl_builder.add_extension(aki, critical=False)
            
        except x509.ExtensionNotFound:
            # If CA doesn't have SKI, generate AKI from public key
            public_key = self._ca_certificate.public_key()
            public_key_der = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Create SHA-1 hash of the public key (standard for AKI)
            digest = hashes.Hash(hashes.SHA1())
            digest.update(public_key_der)
            key_id = digest.finalize()
            
            aki = x509.AuthorityKeyIdentifier(
                key_identifier=key_id,
                authority_cert_issuer=None,
                authority_cert_serial_number=None
            )
            
            crl_builder = crl_builder.add_extension(aki, critical=False)
        
        return crl_builder
    
    def _map_revocation_reason(self, reason_string: str) -> Optional[x509.ReasonFlags]:
        """
        Map string revocation reason to X.509 ReasonFlags.
        
        Args:
            reason_string (str): String revocation reason
            
        Returns:
            x509.ReasonFlags or None: Corresponding reason flag
        """
        reason_mapping = {
            'key_compromise': x509.ReasonFlags.key_compromise,
            'ca_compromise': x509.ReasonFlags.ca_compromise,
            'affiliation_changed': x509.ReasonFlags.affiliation_changed,
            'superseded': x509.ReasonFlags.superseded,
            'cessation_of_operation': x509.ReasonFlags.cessation_of_operation,
            'certificate_hold': x509.ReasonFlags.certificate_hold,
            'remove_from_crl': x509.ReasonFlags.remove_from_crl,
            'privilege_withdrawn': x509.ReasonFlags.privilege_withdrawn,
            'aa_compromise': x509.ReasonFlags.aa_compromise,
        }
        
        return reason_mapping.get(reason_string)
    
    def _get_next_crl_number(self) -> int:
        """
        Get the next CRL number.
        
        Returns:
            int: Next CRL number
        """
        # In a real implementation, this would be persisted to database
        # For now, use timestamp-based number
        return int(datetime.now(timezone.utc).timestamp())
    
    @classmethod
    def create_generator_with_config(cls):
        """
        Create a CRL generator using application configuration.
        
        Returns:
            CRLGenerator: Configured generator instance
        """
        ca_cert = loadConfigValueFromFileOrEnvironment('INTERMEDIATE_CA_CERTIFICATE', '')
        ca_key = loadConfigValueFromFileOrEnvironment('INTERMEDIATE_CA_PRIVATE_KEY', '')
        ca_passphrase = loadConfigValueFromFileOrEnvironment('INTERMEDIATE_CA_KEY_PASSPHRASE', '')
        
        generator = cls()
        if ca_cert and ca_key:
            generator.load_ca_materials(ca_cert, ca_key, ca_passphrase)
        
        return generator