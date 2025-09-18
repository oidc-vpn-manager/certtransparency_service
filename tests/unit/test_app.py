"""
Tests for Flask application factory.
"""

import pytest
from unittest.mock import patch, MagicMock
import logging
import os

from app import create_app
from app.config import UnitTestConfig


def test_create_app_with_none_config_class():
    """Test create_app when config_class is None - line 34."""
    with patch('app.app.get_config') as mock_get_config:
        mock_config = UnitTestConfig()
        mock_get_config.return_value = mock_config
        
        app = create_app(config_class=None)
        
        # Verify get_config was called
        mock_get_config.assert_called_once()
        # Verify the config was applied correctly
        assert app.config['TESTING'] is True


def test_create_app_logging_configuration_not_debug_not_testing():
    """Test create_app logging configuration when not debug and not testing."""
    # Use a real config but disable debug and testing
    config = UnitTestConfig()
    config.DEBUG = False
    config.TESTING = False
    config.LOG_TO_STDOUT = True

    with patch('app.utils.logging_config.setup_logging') as mock_setup_logging:
        app = create_app(config_class=config)

        # Verify custom logging setup was called (since TESTING=False)
        mock_setup_logging.assert_called_once_with(app.config)


def test_create_app_logging_with_log_to_stdout_false():
    """Test create_app logging when LOG_TO_STDOUT is False."""
    config = UnitTestConfig()
    config.DEBUG = False
    config.TESTING = False
    config.LOG_TO_STDOUT = False
    
    with patch('app.app.logging') as mock_logging:
        mock_stream_handler = MagicMock()
        mock_stream_handler.level = logging.INFO  # Set handler level properly
        mock_logging.StreamHandler.return_value = mock_stream_handler
        mock_logging.INFO = logging.INFO  # Use real logging level
        
        app = create_app(config_class=config)
        
        # StreamHandler should not be created when LOG_TO_STDOUT is False
        mock_logging.StreamHandler.assert_not_called()


def test_create_app_with_explicit_config():
    """Test create_app with explicit config class."""
    app = create_app(config_class=UnitTestConfig)
    
    assert app.config['TESTING'] is True
    assert app.config['SQLALCHEMY_DATABASE_URI'] == 'sqlite:///:memory:'


def test_create_app_blueprints_registered():
    """Test that blueprints are properly registered."""
    app = create_app(config_class=UnitTestConfig)
    
    # Check that blueprints are registered
    blueprint_names = [bp.name for bp in app.blueprints.values()]
    assert 'api' in blueprint_names
    assert 'health' in blueprint_names


def test_create_app_extensions_initialized():
    """Test that extensions are properly initialized."""
    from app.app import db, migrate
    
    app = create_app(config_class=UnitTestConfig)
    
    # Check that extensions are initialized by checking they're in the app extensions
    assert 'sqlalchemy' in app.extensions
    assert 'migrate' in app.extensions


def test_swagger_spec_route():
    """Test swagger specification file serving route (line 75)."""
    app = create_app(config_class=UnitTestConfig)
    
    with app.test_client() as client:
        response = client.get('/swagger.yaml')
        
        # Should return the swagger.yaml file
        assert response.status_code == 200
        assert response.headers['Content-Type'].startswith('text/plain') or response.headers['Content-Type'].startswith('application/octet-stream')