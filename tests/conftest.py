"""
Pytest fixtures for Certificate Transparency Service tests.
"""

# Set test environment variables FIRST, before any imports
import os
import secrets

import os, sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Generate secure test secrets if not already set
os.environ.setdefault('FLASK_SECRET_KEY', f'test-ct-{secrets.token_urlsafe(32)}')
os.environ.setdefault('FLASK_ENV', 'testing')
os.environ.setdefault('CT_SERVICE_API_SECRET', 'test-secret-key')

import pytest
import tempfile
import logging
from datetime import datetime, timezone

# Add certtransparency_service to the Python path for testing
import sys
from pathlib import Path
certtransparency_service_path = Path(__file__).parent.parent.parent / 'certtransparency_service'
sys.path.insert(0, str(certtransparency_service_path))

from app.app import create_app, db
from app.config import UnitTestConfig

def pytest_configure(config):
    """Configure pytest and set up test environment variables."""
    # Ensure we have a CT_SECRET_KEY for testing (should already be set above)
    if not os.environ.get('CT_SECRET_KEY'):
        os.environ['CT_SECRET_KEY'] = f'pytest-ct-{secrets.token_urlsafe(16)}'
    os.environ.setdefault('FLASK_ENV', 'testing')
    os.environ.setdefault('CT_SERVICE_API_SECRET', 'test-secret-key')


@pytest.fixture
def app():
    """Create and configure a new app instance for each test."""
    # Create a temporary file for the database
    db_fd, db_path = tempfile.mkstemp()
    
    # Configure for testing
    class TestingConfig(UnitTestConfig):
        def __init__(self):
            super().__init__()
            self.SQLALCHEMY_DATABASE_URI = f'sqlite:///{db_path}'
            self.TESTING = True
            self.WTF_CSRF_ENABLED = False
            self.CT_SERVICE_API_SECRET = 'test-secret-key'
    
    app = create_app(TestingConfig)
    
    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()
    
    # Clean up
    os.close(db_fd)
    os.unlink(db_path)


@pytest.fixture
def client(app):
    """A test client for the app."""
    return app.test_client()


@pytest.fixture
def runner(app):
    """A test runner for the app's Click commands."""
    return app.test_cli_runner()


@pytest.fixture
def sample_certificate_pem():
    """Sample root CA certificate PEM for testing."""
    return """-----BEGIN CERTIFICATE-----
MIIBqDCCAVqgAwIBAgIUZjD+tcLHqCz/oPNwLPdQjtKIW6wwBQYDK2VwMF8xCzAJ
BgNVBAYTAkdCMRAwDgYDVQQIDAdFbmdsYW5kMQ8wDQYDVQQHDAZMb25kb24xEDAO
BgNVBAoMB0RJQ0UuZm0xGzAYBgNVBAMMEmNhLm9wZW52cG4uZGljZS5mbTAgFw0y
NTA3MjQwODA3NDFaGA8yMDU1MDcxNzA4MDc0MVowXzELMAkGA1UEBhMCR0IxEDAO
BgNVBAgMB0VuZ2xhbmQxDzANBgNVBAcMBkxvbmRvbjEQMA4GA1UECgwHRElDRS5m
bTEbMBkGA1UEAwwSY2Eub3BlbnZwbi5kaWNlLmZtMCowBQYDK2VwAyEAmVyXmXaf
bbj/3amAeIu8bY3tzxho52T2B5oOtCzI3UmjJjAkMBIGA1UdEwEB/wQIMAYBAf8C
AQEwDgYDVR0PAQH/BAQDAgEGMAUGAytlcANBABi4q/VNQ05dWUtngEy7YC59yLoo
YdsHHWWjNQgYa+3vzpmmeXC8Iba74dniOTpl8X1RqOcyzBEgaQ50cVESBAg=
-----END CERTIFICATE-----"""


@pytest.fixture
def sample_intermediate_certificate_pem():
    """Sample intermediate CA certificate PEM for testing."""
    return """-----BEGIN CERTIFICATE-----
MIIBrzCCAWGgAwIBAgIUP8ZdnhMVQtQM2yX/m5KZ+Kq7ljowBQYDK2VwMF8xCzAJ
BgNVBAYTAkdCMRAwDgYDVQQIDAdFbmdsYW5kMQ8wDQYDVQQHDAZMb25kb24xEDAO
BgNVBAoMB0RJQ0UuZm0xGzAZBgNVBAMMEmNhLm9wZW52cG4uZGljZS5mbTAeFw0y
NTA3MjQwODA4MDZaFw0zNTA3MjIwODA4MDZaMGgxCzAJBgNVBAYTAkdCMRAwDgYD
VQQIDAdFbmdsYW5kMQ8wDQYDVQQHDAZMb25kb24xEDAOBgNVBAoMB0RJQ0UuZm0x
JDAiBgNVBAMMG2VuZ2luZWVyaW5nLm9wZW52cG4uZGljZS5mbTAqMAUGAytlcAMh
AO8ejYSK3cVH7iFDv8KDD2JlVRWYQ2V9DNc3NzNdODO4oyYwJDASBgNVHRMBAf8E
CDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAFBgMrZXADQQAR4AkZAtQ2l6MBzqLY
bK9Ql9BDf2846JREB1AMbExvHNhgPrXHbLDg+N3VXpejwKPblJjG+BopmNDoJTJy
PvEH
-----END CERTIFICATE-----"""


@pytest.fixture
def sample_cert_data():
    """Sample certificate data for testing."""
    return {
        'certificate_pem': """-----BEGIN CERTIFICATE-----
MIIBqDCCAVqgAwIBAgIUZjD+tcLHqCz/oPNwLPdQjtKIW6wwBQYDK2VwMF8xCzAJ
BgNVBAYTAkdCMRAwDgYDVQQIDAdFbmdsYW5kMQ8wDQYDVQQHDAZMb25kb24xEDAO
BgNVBAoMB0RJQ0UuZm0xGzAZBgNVBAMMEmNhLm9wZW52cG4uZGljZS5mbTAgFw0y
NTA3MjQwODA3NDFaGA8yMDU1MDcxNzA4MDc0MVowXzELMAkGA1UEBhMCR0IxEDAO
BgNVBAgMB0VuZ2xhbmQxDzANBgNVBAcMBkxvbmRvbjEQMA4GA1UECgwHRElDRS5m
bTEbMBkGA1UEAwwSY2Eub3BlbnZwbi5kaWNlLmZtMCowBQYDK2VwAyEAmVyXmXaf
bbj/3amAeIu8bY3tzxho52T2B5oOtCzI3UmjJjAkMBIGA1UdEwEB/wQIMAYBAf8C
AQEwDgYDVR0PAQH/BAQDAgEGMAUGAytlcANBABi4q/VNQ05dWUtngEy7YC59yLoo
YdsHHWWjNQgYa+3vzpmmeXC8Iba74dniOTpl8X1RqOcyzBEgaQ50cVESBAg=
-----END CERTIFICATE-----""",
        'certificate_type': 'client',
        'certificate_purpose': 'test-user-profile',
        'request_source': 'frontend_service'
    }


@pytest.fixture
def sample_server_cert_data():
    """Sample server certificate data for testing."""
    return {
        'certificate_pem': """-----BEGIN CERTIFICATE-----
MIIBrzCCAWGgAwIBAgIUP8ZdnhMVQtQM2yX/m5KZ+Kq7ljowBQYDK2VwMF8xCzAJ
BgNVBAYTAkdCMRAwDgYDVQQIDAdFbmdsYW5kMQ8wDQYDVQQHDAZMb25kb24xEDAO
BgNVBAoMB0RJQ0UuZm0xGzAZBgNVBAMMEmNhLm9wZW52cG4uZGljZS5mbTAeFw0y
NTA3MjQwODA4MDZaFw0zNTA3MjIwODA4MDZaMGgxCzAJBgNVBAYTAkdCMRAwDgYD
VQQIDAdFbmdsYW5kMQ8wDQYDVQQHDAZMb25kb24xEDAOBgNVBAoMB0RJQ0UuZm0x
JDAiBgNVBAMMG2VuZ2luZWVyaW5nLm9wZW52cG4uZGljZS5mbTAqMAUGAytlcAMh
AO8ejYSK3cVH7iFDv8KDD2JlVRWYQ2V9DNc3NzNdODO4oyYwJDASBgNVHRMBAf8E
CDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAFBgMrZXADQQAR4AkZAtQ2l6MBzqLY
bK9Ql9BDf2846JREB1AMbExvHNhgPrXHbLDg+N3VXpejwKPblJjG+BopmNDoJTJy
PvEH
-----END CERTIFICATE-----""",
        'certificate_type': 'server',
        'certificate_purpose': 'test-server-profile',
        'request_source': 'signing_service'
    }


@pytest.fixture(autouse=True)
def configure_logging_for_tests():
    """Configure logging for tests to ensure caplog works properly."""

    yield  # Let the test run first

    # After each test, reset logging configuration to ensure caplog works
    # Clear all existing handlers from all loggers
    loggers_to_clear = [
        logging.getLogger(),  # Root logger
        logging.getLogger('app.utils.geoip'),
        logging.getLogger('security_events'),
        logging.getLogger('flask.app'),
        logging.getLogger('gunicorn.access'),
        logging.getLogger('gunicorn.error'),
        logging.getLogger('app'),
        logging.getLogger('werkzeug')
    ]

    for logger in loggers_to_clear:
        logger.handlers.clear()
        logger.setLevel(logging.NOTSET)
        logger.propagate = True

    # Reset logging configuration completely
    logging.shutdown()

    # Reinitialize basic logging for next test
    logging.basicConfig(level=logging.DEBUG, format='%(message)s', force=True)