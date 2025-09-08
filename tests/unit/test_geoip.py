"""
Unit tests for GeoIP utility functionality.
"""

import os
import tempfile
import pytest
import logging
from unittest.mock import patch, MagicMock, mock_open
import geoip2.errors
from app.utils.geoip import (
    get_geoip_database_path,
    lookup_country_code,
    is_geoip_available,
    get_geoip_status,
    GEOIP_DATABASE_PATH,
    GEOIP_DATABASE_ENV_VAR
)

# Configure logging for tests
logging.basicConfig(level=logging.DEBUG)

@pytest.fixture(autouse=True)
def configure_logging(caplog):
    """Configure logging to capture debug messages."""
    caplog.set_level(logging.DEBUG, logger="app.utils.geoip")


class TestGeoIPDatabasePath:
    """Tests for database path configuration."""
    
    def test_get_geoip_database_path_default(self):
        """Test default database path when no environment variable is set."""
        with patch.dict(os.environ, {}, clear=False):
            if GEOIP_DATABASE_ENV_VAR in os.environ:
                del os.environ[GEOIP_DATABASE_ENV_VAR]
            path = get_geoip_database_path()
            assert path == GEOIP_DATABASE_PATH
    
    def test_get_geoip_database_path_environment_override(self):
        """Test database path from environment variable."""
        custom_path = '/custom/path/to/geoip.mmdb'
        with patch.dict(os.environ, {GEOIP_DATABASE_ENV_VAR: custom_path}):
            path = get_geoip_database_path()
            assert path == custom_path


class TestLookupCountryCode:
    """Tests for IP address country lookup functionality."""
    
    def test_lookup_country_code_empty_ip(self, caplog):
        """Test handling of empty IP address."""
        result = lookup_country_code('')
        assert result is None
        assert "Empty IP address provided for GeoIP lookup" in caplog.text
    
    def test_lookup_country_code_none_ip(self, caplog):
        """Test handling of None IP address."""
        result = lookup_country_code(None)
        assert result is None
        assert "Empty IP address provided for GeoIP lookup" in caplog.text
    
    def test_lookup_country_code_whitespace_ip(self, caplog):
        """Test handling of whitespace-only IP address."""
        result = lookup_country_code('   ')
        assert result is None
        assert "Empty IP address provided for GeoIP lookup" in caplog.text
    
    def test_lookup_country_code_invalid_ip_format(self, caplog):
        """Test handling of invalid IP address format."""
        result = lookup_country_code('invalid.ip.address')
        assert result is None
        assert "Invalid IP address format for GeoIP lookup" in caplog.text
    
    def test_lookup_country_code_private_ipv4(self, caplog):
        """Test handling of private IPv4 address."""
        result = lookup_country_code('192.168.1.1')
        assert result is None
        assert "Skipping GeoIP lookup for private/reserved IP" in caplog.text
    
    def test_lookup_country_code_loopback_ipv4(self, caplog):
        """Test handling of loopback IPv4 address."""
        result = lookup_country_code('127.0.0.1')
        assert result is None
        assert "Skipping GeoIP lookup for private/reserved IP" in caplog.text
    
    def test_lookup_country_code_private_ipv6(self, caplog):
        """Test handling of private IPv6 address."""
        result = lookup_country_code('fe80::1')
        assert result is None
        assert "Skipping GeoIP lookup for private/reserved IP" in caplog.text
    
    def test_lookup_country_code_loopback_ipv6(self, caplog):
        """Test handling of loopback IPv6 address."""
        result = lookup_country_code('::1')
        assert result is None
        assert "Skipping GeoIP lookup for private/reserved IP" in caplog.text
    
    @patch('app.utils.geoip.os.path.exists')
    def test_lookup_country_code_database_not_found(self, mock_exists, caplog):
        """Test handling when GeoIP database file doesn't exist."""
        mock_exists.return_value = False
        
        result = lookup_country_code('8.8.8.8')
        assert result is None
        assert "GeoIP database not found" in caplog.text
    
    @patch('app.utils.geoip.get_geoip_database_path')
    @patch('app.utils.geoip.os.path.exists')
    @patch('app.utils.geoip.geoip2.database.Reader')
    def test_lookup_country_code_successful_lookup(self, mock_reader_class, mock_exists, mock_get_path, caplog):
        """Test successful country code lookup."""
        mock_get_path.return_value = '/test/path/geoip.mmdb'
        mock_exists.return_value = True
        
        # Mock the reader and response
        mock_reader = MagicMock()
        mock_reader_class.return_value.__enter__.return_value = mock_reader
        
        mock_response = MagicMock()
        mock_response.country.iso_code = 'US'
        mock_reader.country.return_value = mock_response
        
        result = lookup_country_code('8.8.8.8')
        assert result == 'US'
        assert "GeoIP lookup for 8.8.8.8: US" in caplog.text
    
    @patch('app.utils.geoip.get_geoip_database_path')
    @patch('app.utils.geoip.os.path.exists')
    @patch('app.utils.geoip.geoip2.database.Reader')
    def test_lookup_country_code_no_country_found(self, mock_reader_class, mock_exists, mock_get_path, caplog):
        """Test when no country code is found for IP."""
        mock_get_path.return_value = '/test/path/geoip.mmdb'
        mock_exists.return_value = True
        
        # Mock the reader and response with no country code
        mock_reader = MagicMock()
        mock_reader_class.return_value.__enter__.return_value = mock_reader
        
        mock_response = MagicMock()
        mock_response.country.iso_code = None
        mock_reader.country.return_value = mock_response
        
        result = lookup_country_code('8.8.8.8')
        assert result is None
        assert "No country code found for IP 8.8.8.8" in caplog.text
    
    @patch('app.utils.geoip.get_geoip_database_path')
    @patch('app.utils.geoip.os.path.exists')
    @patch('app.utils.geoip.geoip2.database.Reader')
    def test_lookup_country_code_address_not_found_error(self, mock_reader_class, mock_exists, mock_get_path, caplog):
        """Test handling of AddressNotFoundError."""
        mock_get_path.return_value = '/test/path/geoip.mmdb'
        mock_exists.return_value = True
        
        # Mock the reader to raise AddressNotFoundError
        mock_reader = MagicMock()
        mock_reader_class.return_value.__enter__.return_value = mock_reader
        mock_reader.country.side_effect = geoip2.errors.AddressNotFoundError("Address not found")
        
        result = lookup_country_code('8.8.8.8')
        assert result is None
        assert "IP address not found in GeoIP database" in caplog.text
    
    @patch('app.utils.geoip.get_geoip_database_path')
    @patch('app.utils.geoip.os.path.exists')
    @patch('app.utils.geoip.geoip2.database.Reader')
    def test_lookup_country_code_geoip_error(self, mock_reader_class, mock_exists, mock_get_path, caplog):
        """Test handling of GeoIP2Error."""
        mock_get_path.return_value = '/test/path/geoip.mmdb'
        mock_exists.return_value = True
        
        # Mock the reader to raise GeoIP2Error
        mock_reader = MagicMock()
        mock_reader_class.return_value.__enter__.return_value = mock_reader
        mock_reader.country.side_effect = geoip2.errors.GeoIP2Error("GeoIP error")
        
        result = lookup_country_code('8.8.8.8')
        assert result is None
        assert "GeoIP lookup error for 8.8.8.8" in caplog.text
    
    @patch('app.utils.geoip.get_geoip_database_path')
    @patch('app.utils.geoip.os.path.exists')
    @patch('app.utils.geoip.geoip2.database.Reader')
    def test_lookup_country_code_unexpected_error(self, mock_reader_class, mock_exists, mock_get_path, caplog):
        """Test handling of unexpected errors."""
        mock_get_path.return_value = '/test/path/geoip.mmdb'
        mock_exists.return_value = True
        
        # Mock the reader to raise unexpected error
        mock_reader = MagicMock()
        mock_reader_class.return_value.__enter__.return_value = mock_reader
        mock_reader.country.side_effect = RuntimeError("Unexpected error")
        
        result = lookup_country_code('8.8.8.8')
        assert result is None
        assert "Unexpected error during GeoIP lookup for 8.8.8.8" in caplog.text
    
    def test_lookup_country_code_whitespace_trimming(self):
        """Test that IP addresses with whitespace are trimmed properly."""
        with patch('app.utils.geoip.os.path.exists') as mock_exists:
            mock_exists.return_value = False  # Avoid actual database lookup
            
            # Should not raise ValueError for whitespace padding
            result = lookup_country_code('  192.168.1.1  ')
            assert result is None  # Will be None due to private IP, but shouldn't raise error


class TestGeoIPAvailability:
    """Tests for GeoIP availability checking."""
    
    @patch('app.utils.geoip.get_geoip_database_path')
    @patch('app.utils.geoip.os.path.exists')
    def test_is_geoip_available_file_not_exists(self, mock_exists, mock_get_path):
        """Test availability check when database file doesn't exist."""
        mock_get_path.return_value = '/test/path/geoip.mmdb'
        mock_exists.return_value = False
        
        result = is_geoip_available()
        assert result is False
    
    @patch('app.utils.geoip.get_geoip_database_path')
    @patch('app.utils.geoip.os.path.exists')
    @patch('app.utils.geoip.geoip2.database.Reader')
    def test_is_geoip_available_database_readable(self, mock_reader_class, mock_exists, mock_get_path):
        """Test availability check when database is readable."""
        mock_get_path.return_value = '/test/path/geoip.mmdb'
        mock_exists.return_value = True
        
        # Mock successful reader
        mock_reader = MagicMock()
        mock_reader_class.return_value.__enter__.return_value = mock_reader
        mock_reader.metadata.return_value = MagicMock()
        
        result = is_geoip_available()
        assert result is True
    
    @patch('app.utils.geoip.get_geoip_database_path')
    @patch('app.utils.geoip.os.path.exists')
    @patch('app.utils.geoip.geoip2.database.Reader')
    def test_is_geoip_available_database_error(self, mock_reader_class, mock_exists, mock_get_path, caplog):
        """Test availability check when database has read errors."""
        mock_get_path.return_value = '/test/path/geoip.mmdb'
        mock_exists.return_value = True
        
        # Mock reader that raises exception
        mock_reader_class.return_value.__enter__.side_effect = Exception("Database corrupt")
        
        result = is_geoip_available()
        assert result is False
        assert "GeoIP database not accessible" in caplog.text


class TestGeoIPStatus:
    """Tests for GeoIP status information."""
    
    @patch('app.utils.geoip.get_geoip_database_path')
    @patch('app.utils.geoip.os.path.exists')
    @patch('app.utils.geoip.is_geoip_available')
    def test_get_geoip_status_unavailable(self, mock_available, mock_exists, mock_get_path):
        """Test status when GeoIP is unavailable."""
        mock_get_path.return_value = '/test/path/geoip.mmdb'
        mock_exists.return_value = False
        mock_available.return_value = False
        
        status = get_geoip_status()
        
        expected = {
            'available': False,
            'database_path': '/test/path/geoip.mmdb',
            'database_exists': False
        }
        assert status == expected
    
    @patch('app.utils.geoip.get_geoip_database_path')
    @patch('app.utils.geoip.os.path.exists')
    @patch('app.utils.geoip.is_geoip_available')
    @patch('app.utils.geoip.geoip2.database.Reader')
    def test_get_geoip_status_available_with_metadata(self, mock_reader_class, mock_available, mock_exists, mock_get_path):
        """Test status when GeoIP is available with metadata."""
        mock_get_path.return_value = '/test/path/geoip.mmdb'
        mock_exists.return_value = True
        mock_available.return_value = True
        
        # Mock reader with metadata
        mock_reader = MagicMock()
        mock_reader_class.return_value.__enter__.return_value = mock_reader
        
        mock_metadata = MagicMock()
        mock_metadata.build_epoch = 1640995200  # Example timestamp
        mock_metadata.languages = ['en']
        mock_metadata.description = {'en': 'GeoLite2 Country database'}
        mock_reader.metadata.return_value = mock_metadata
        
        status = get_geoip_status()
        
        expected = {
            'available': True,
            'database_path': '/test/path/geoip.mmdb',
            'database_exists': True,
            'database_build_epoch': 1640995200,
            'database_languages': ['en'],
            'database_description': {'en': 'GeoLite2 Country database'}
        }
        assert status == expected
    
    @patch('app.utils.geoip.get_geoip_database_path')
    @patch('app.utils.geoip.os.path.exists')
    @patch('app.utils.geoip.is_geoip_available')
    @patch('app.utils.geoip.geoip2.database.Reader')
    def test_get_geoip_status_metadata_error(self, mock_reader_class, mock_available, mock_exists, mock_get_path, caplog):
        """Test status when metadata reading fails."""
        mock_get_path.return_value = '/test/path/geoip.mmdb'
        mock_exists.return_value = True
        mock_available.return_value = True
        
        # Mock reader that raises exception on metadata
        mock_reader = MagicMock()
        mock_reader_class.return_value.__enter__.return_value = mock_reader
        mock_reader.metadata.side_effect = Exception("Metadata error")
        
        status = get_geoip_status()
        
        expected = {
            'available': True,
            'database_path': '/test/path/geoip.mmdb',
            'database_exists': True
        }
        assert status == expected
        assert "Error reading GeoIP database metadata" in caplog.text