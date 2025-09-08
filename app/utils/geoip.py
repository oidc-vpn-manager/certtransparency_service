"""
GeoIP utility for country lookup from IP addresses using MaxMind GeoLite2.

This module provides functionality to:
1. Download and update MaxMind GeoLite2 databases
2. Lookup country codes from IP addresses
3. Handle GeoIP errors gracefully
"""

import os
import geoip2.database
import geoip2.errors
import ipaddress
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Default path for GeoLite2 database
GEOIP_DATABASE_PATH = '/var/lib/geoip/GeoLite2-Country.mmdb'

# Environment variable to override database path
GEOIP_DATABASE_ENV_VAR = 'GEOIP_DATABASE_PATH'


def get_geoip_database_path() -> str:
    """
    Get the path to the GeoIP database, checking environment variable first.
    
    Returns:
        str: Path to the GeoLite2 Country database file
    """
    return os.environ.get(GEOIP_DATABASE_ENV_VAR, GEOIP_DATABASE_PATH)


def lookup_country_code(ip_address: str) -> Optional[str]:
    """
    Lookup the ISO country code for an IP address using MaxMind GeoLite2.
    
    Args:
        ip_address (str): The IP address to lookup (IPv4 or IPv6)
        
    Returns:
        Optional[str]: Two-letter ISO country code (e.g. 'US', 'GB') or None if lookup fails
    """
    if not ip_address or ip_address.strip() == '':
        logger.debug("Empty IP address provided for GeoIP lookup")
        return None
    
    # Clean and validate IP address
    try:
        ip_obj = ipaddress.ip_address(ip_address.strip())
        
        # Skip private, loopback, and reserved IP ranges
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
            logger.debug(f"Skipping GeoIP lookup for private/reserved IP: {ip_address}")
            return None
            
    except ValueError as e:
        logger.warning(f"Invalid IP address format for GeoIP lookup: {ip_address} - {e}")
        return None
    
    database_path = get_geoip_database_path()
    
    # Check if database file exists
    if not os.path.exists(database_path):
        logger.warning(f"GeoIP database not found at {database_path}. Country lookup disabled.")
        return None
    
    try:
        with geoip2.database.Reader(database_path) as reader:
            response = reader.country(str(ip_obj))
            country_code = response.country.iso_code
            
            if country_code:
                logger.debug(f"GeoIP lookup for {ip_address}: {country_code}")
                return country_code
            else:
                logger.debug(f"No country code found for IP {ip_address}")
                return None
                
    except geoip2.errors.AddressNotFoundError:
        logger.debug(f"IP address not found in GeoIP database: {ip_address}")
        return None
        
    except geoip2.errors.GeoIP2Error as e:
        logger.error(f"GeoIP lookup error for {ip_address}: {e}")
        return None
        
    except Exception as e:
        logger.error(f"Unexpected error during GeoIP lookup for {ip_address}: {e}")
        return None


def is_geoip_available() -> bool:
    """
    Check if GeoIP functionality is available (database file exists and is readable).
    
    Returns:
        bool: True if GeoIP database is available, False otherwise
    """
    database_path = get_geoip_database_path()
    
    if not os.path.exists(database_path):
        return False
        
    try:
        with geoip2.database.Reader(database_path) as reader:
            # Try a basic operation to verify the database is readable
            reader.metadata()
            return True
    except Exception as e:
        logger.error(f"GeoIP database not accessible: {e}")
        return False


def get_geoip_status() -> dict:
    """
    Get status information about GeoIP functionality.
    
    Returns:
        dict: Status information including availability, database path, etc.
    """
    database_path = get_geoip_database_path()
    available = is_geoip_available()
    
    status = {
        'available': available,
        'database_path': database_path,
        'database_exists': os.path.exists(database_path)
    }
    
    if available:
        try:
            with geoip2.database.Reader(database_path) as reader:
                metadata = reader.metadata()
                status['database_build_epoch'] = metadata.build_epoch
                status['database_languages'] = list(metadata.languages)
                status['database_description'] = dict(metadata.description)
        except Exception as e:
            logger.error(f"Error reading GeoIP database metadata: {e}")
    
    return status