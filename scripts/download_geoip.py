#!/usr/bin/env python3
"""
MaxMind GeoLite2 Database Download Script

This script downloads the MaxMind GeoLite2-Country database for use with
the Certificate Transparency service's geolocation functionality.

Usage:
    python download_geoip.py [--license-key LICENSE_KEY] [--output-dir OUTPUT_DIR]

Requirements:
    - MaxMind GeoLite2 account and license key (free registration required)
    - Register at: https://www.maxmind.com/en/geolite2/signup
    - Create license key at: https://www.maxmind.com/en/accounts/current/license-key

Environment Variables:
    MAXMIND_LICENSE_KEY: Your MaxMind license key
    GEOIP_DATABASE_PATH: Custom path for database file (default: /var/lib/geoip/GeoLite2-Country.mmdb)
"""

import os
import sys
import argparse
import urllib.request
import gzip
import tarfile
import shutil
import tempfile
import hashlib
from pathlib import Path

# Default configuration
DEFAULT_GEOIP_DIR = '/var/lib/geoip'
DEFAULT_DB_PATH = f'{DEFAULT_GEOIP_DIR}/GeoLite2-Country.mmdb'
MAXMIND_DOWNLOAD_URL = 'https://download.maxmind.com/app/geoip_download'


def get_license_key():
    """Get MaxMind license key from environment or command line."""
    return os.environ.get('MAXMIND_LICENSE_KEY')


def download_geoip_database(license_key, output_dir):
    """
    Download and extract the MaxMind GeoLite2-Country database.
    
    Args:
        license_key (str): MaxMind license key
        output_dir (str): Directory to save the database file
    """
    if not license_key:
        print("Error: MaxMind license key is required.", file=sys.stderr)
        print("Set MAXMIND_LICENSE_KEY environment variable or use --license-key option.", file=sys.stderr)
        print("Get a free license key at: https://www.maxmind.com/en/geolite2/signup", file=sys.stderr)
        return False
    
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    # Download URL with license key
    download_url = f"{MAXMIND_DOWNLOAD_URL}?edition_id=GeoLite2-Country&license_key={license_key}&suffix=tar.gz"
    
    print(f"Downloading GeoLite2-Country database...")
    print(f"Output directory: {output_dir}")
    
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            # Download the tar.gz file
            tar_path = os.path.join(temp_dir, 'GeoLite2-Country.tar.gz')
            
            print("Downloading from MaxMind...")
            urllib.request.urlretrieve(download_url, tar_path)
            
            # Extract the tar.gz file
            print("Extracting database...")
            with tarfile.open(tar_path, 'r:gz') as tar:
                tar.extractall(temp_dir)
            
            # Find the .mmdb file (it's inside a dated directory)
            mmdb_file = None
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    if file.endswith('.mmdb') and 'Country' in file:
                        mmdb_file = os.path.join(root, file)
                        break
                if mmdb_file:
                    break
            
            if not mmdb_file:
                print("Error: Could not find .mmdb file in downloaded archive.", file=sys.stderr)
                return False
            
            # Copy to final destination
            final_path = os.path.join(output_dir, 'GeoLite2-Country.mmdb')
            shutil.copy2(mmdb_file, final_path)
            
            # Set appropriate permissions
            os.chmod(final_path, 0o644)
            
            # Calculate file hash for verification
            with open(final_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            
            file_size = os.path.getsize(final_path)
            
            print(f"Success! Database downloaded and installed:")
            print(f"  Path: {final_path}")
            print(f"  Size: {file_size:,} bytes")
            print(f"  SHA256: {file_hash}")
            
            return True
            
    except urllib.error.HTTPError as e:
        if e.code == 401:
            print("Error: Invalid MaxMind license key.", file=sys.stderr)
            print("Check your license key at: https://www.maxmind.com/en/accounts/current/license-key", file=sys.stderr)
        else:
            print(f"Error: HTTP {e.code} - {e.reason}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"Error downloading database: {e}", file=sys.stderr)
        return False


def verify_geoip_installation(db_path):
    """
    Verify that the GeoIP database is correctly installed and accessible.
    
    Args:
        db_path (str): Path to the GeoLite2 database file
    """
    print(f"\nVerifying GeoIP installation...")
    
    if not os.path.exists(db_path):
        print(f"Error: Database file not found at {db_path}", file=sys.stderr)
        return False
    
    try:
        import geoip2.database
        
        with geoip2.database.Reader(db_path) as reader:
            # Test with a known IP address (Google DNS)
            test_ip = '8.8.8.8'
            response = reader.country(test_ip)
            
            print(f"Database verification successful!")
            print(f"  Test lookup ({test_ip}): {response.country.iso_code} - {response.country.name}")
            print(f"  Database build: {reader.metadata().build_epoch}")
            
            return True
            
    except ImportError:
        print("Warning: geoip2 library not installed. Install with: pip install geoip2", file=sys.stderr)
        print("Database file appears to be present but cannot be tested.", file=sys.stderr)
        return True  # File exists, even if we can't test it
        
    except Exception as e:
        print(f"Error verifying database: {e}", file=sys.stderr)
        return False


def main():
    parser = argparse.ArgumentParser(
        description='Download MaxMind GeoLite2-Country database',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    parser.add_argument(
        '--license-key',
        help='MaxMind license key (can also use MAXMIND_LICENSE_KEY env var)'
    )
    
    parser.add_argument(
        '--output-dir',
        default=os.environ.get('GEOIP_DATABASE_PATH', DEFAULT_GEOIP_DIR).rsplit('/', 1)[0],
        help=f'Output directory for database file (default: {DEFAULT_GEOIP_DIR})'
    )
    
    parser.add_argument(
        '--verify-only',
        action='store_true',
        help='Only verify existing installation without downloading'
    )
    
    args = parser.parse_args()
    
    # Get license key from args or environment
    license_key = args.license_key or get_license_key()
    
    # Determine database path
    db_path = os.path.join(args.output_dir, 'GeoLite2-Country.mmdb')
    
    if args.verify_only:
        success = verify_geoip_installation(db_path)
    else:
        # Download database
        success = download_geoip_database(license_key, args.output_dir)
        
        if success:
            # Verify installation
            verify_geoip_installation(db_path)
    
    if success:
        print(f"\nTo use this database with the Certificate Transparency service:")
        print(f"1. Set environment variable: GEOIP_DATABASE_PATH={db_path}")
        print(f"2. Ensure the service has read access to the database file")
        print(f"3. Restart the Certificate Transparency service")
    
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())