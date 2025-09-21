"""
Unit tests for CRL Counter model.
"""

import pytest
from datetime import datetime, timezone
from app.models.crl_counter import CRLCounter
from app.extensions import db


class TestCRLCounterModel:
    """Test suite for CRLCounter model."""

    def test_repr(self):
        """Test string representation of CRLCounter."""
        counter = CRLCounter(
            issuer_identifier="Test CA",
            current_crl_number=42
        )
        assert repr(counter) == '<CRLCounter Test CA: 42>'

    def test_get_next_crl_number_new_issuer(self, app):
        """Test getting CRL number for new issuer."""
        with app.app_context():
            # Test new issuer starts at CRL number 1
            crl_number = CRLCounter.get_next_crl_number("New Test CA")
            assert crl_number == 1

            # Verify counter was created
            counter = CRLCounter.query.filter_by(issuer_identifier="New Test CA").first()
            assert counter is not None
            assert counter.current_crl_number == 2  # Next number to use

    def test_get_next_crl_number_existing_issuer(self, app):
        """Test getting CRL number for existing issuer."""
        with app.app_context():
            # Create initial counter
            counter = CRLCounter(
                issuer_identifier="Existing CA",
                current_crl_number=5
            )
            db.session.add(counter)
            db.session.commit()

            # Get next number
            crl_number = CRLCounter.get_next_crl_number("Existing CA")
            assert crl_number == 5

            # Verify counter was incremented
            counter = CRLCounter.query.filter_by(issuer_identifier="Existing CA").first()
            assert counter.current_crl_number == 6

    def test_get_current_crl_number_no_counter(self, app):
        """Test getting current CRL number when no counter exists."""
        with app.app_context():
            current_number = CRLCounter.get_current_crl_number("Nonexistent CA")
            assert current_number == 0

    def test_get_current_crl_number_existing_counter(self, app):
        """Test getting current CRL number for existing counter."""
        with app.app_context():
            # Create counter
            counter = CRLCounter(
                issuer_identifier="Test CA",
                current_crl_number=10
            )
            db.session.add(counter)
            db.session.commit()

            # Get current number (last used number)
            current_number = CRLCounter.get_current_crl_number("Test CA")
            assert current_number == 9  # current_crl_number - 1

    def test_to_dict(self, app):
        """Test converting CRL counter to dictionary."""
        with app.app_context():
            counter = CRLCounter(
                issuer_identifier="Test CA",
                current_crl_number=7
            )
            db.session.add(counter)
            db.session.commit()

            counter_dict = counter.to_dict()
            
            assert counter_dict['issuer_identifier'] == "Test CA"
            assert counter_dict['current_crl_number'] == 7
            assert 'id' in counter_dict
            assert 'created_at' in counter_dict
            assert 'updated_at' in counter_dict

    def test_monotonic_increment_sequence(self, app):
        """Test that CRL numbers are always monotonically increasing."""
        with app.app_context():
            issuer = "Sequential CA"
            
            # Get multiple CRL numbers and ensure they increment
            numbers = []
            for _ in range(5):
                numbers.append(CRLCounter.get_next_crl_number(issuer))
            
            # Verify sequence is monotonic
            assert numbers == [1, 2, 3, 4, 5]

    def test_unique_issuer_constraint(self, app):
        """Test that issuer_identifier is unique."""
        with app.app_context():
            # Create first counter
            counter1 = CRLCounter(
                issuer_identifier="Unique CA",
                current_crl_number=1
            )
            db.session.add(counter1)
            db.session.commit()

            # Try to create second counter with same identifier
            counter2 = CRLCounter(
                issuer_identifier="Unique CA",
                current_crl_number=2
            )
            db.session.add(counter2)
            
            with pytest.raises(Exception):  # Should raise database integrity error
                db.session.commit()