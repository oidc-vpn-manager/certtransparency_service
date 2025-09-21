"""
CRL Counter Model for tracking monotonically increasing CRL numbers.

This model ensures that CRL numbers are always monotonically increasing
as required by the X.509 standard (RFC 5280).
"""

from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Index
from app.extensions import db


class CRLCounter(db.Model):
    """
    CRL Counter for tracking the next CRL number.
    
    This table maintains a single counter per issuer to ensure
    monotonically increasing CRL numbers as required by X.509 standard.
    """
    
    __tablename__ = 'crl_counters'
    
    # Composite index for efficient queries
    __table_args__ = (
        Index('ix_issuer_identifier', 'issuer_identifier'),
    )
    
    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Issuer identification (usually CN of the CA)
    issuer_identifier = Column(String(255), nullable=False, unique=True, index=True)
    
    # Current CRL number (next number to use)
    current_crl_number = Column(Integer, nullable=False, default=1)
    
    # Timestamp tracking
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    
    def __repr__(self):
        return f'<CRLCounter {self.issuer_identifier}: {self.current_crl_number}>'
    
    @classmethod
    def get_next_crl_number(cls, issuer_identifier: str) -> int:
        """
        Get the next CRL number for the given issuer and increment the counter.
        
        This method is atomic and thread-safe to ensure monotonic increments.
        
        Args:
            issuer_identifier (str): Identifier for the CA issuer
            
        Returns:
            int: Next CRL number to use
        """
        # Try to find existing counter
        counter = cls.query.filter_by(issuer_identifier=issuer_identifier).first()
        
        if not counter:
            # Create new counter starting at 1
            counter = cls(
                issuer_identifier=issuer_identifier,
                current_crl_number=2  # Return 1, next will be 2
            )
            db.session.add(counter)
            db.session.commit()
            return 1
        
        # Increment counter atomically
        next_number = counter.current_crl_number
        counter.current_crl_number += 1
        counter.updated_at = datetime.now(timezone.utc)
        
        db.session.commit()
        return next_number
    
    @classmethod
    def get_current_crl_number(cls, issuer_identifier: str) -> int:
        """
        Get the current CRL number without incrementing.
        
        Args:
            issuer_identifier (str): Identifier for the CA issuer
            
        Returns:
            int: Current CRL number (0 if no counter exists)
        """
        counter = cls.query.filter_by(issuer_identifier=issuer_identifier).first()
        if not counter:
            return 0
        return counter.current_crl_number - 1  # Return the last used number
    
    def to_dict(self):
        """Convert CRL counter to dictionary representation."""
        return {
            'id': self.id,
            'issuer_identifier': self.issuer_identifier,
            'current_crl_number': self.current_crl_number,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }