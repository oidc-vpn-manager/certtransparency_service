"""
Tests for configuration module.
"""

import os
import pytest
from unittest.mock import patch, MagicMock

from app.config import Config, DevelopmentConfig, UnitTestConfig, ProductionConfig, get_config, build_database_string


def test_development_config_dev_database_uri_branch():
    """Test DevelopmentConfig with DEV_DATABASE_URI set - line 87."""
    with patch('app.config.loadConfigValueFromFileOrEnvironment') as mock_load:
        mock_load.side_effect = lambda key, default=None: {
            'DEV_DATABASE_URI': 'postgresql://dev:pass@localhost/devdb',
            'DATABASE_URL': None,
            'DATABASE_TYPE': None
        }.get(key, default)
        
        config = DevelopmentConfig()
        
        assert config.SQLALCHEMY_DATABASE_URI == 'postgresql://dev:pass@localhost/devdb'


def test_development_config_database_url_fallback():
    """Test DevelopmentConfig with DATABASE_URL fallback - lines 89-91."""
    with patch('app.config.loadConfigValueFromFileOrEnvironment') as mock_load:
        mock_load.side_effect = lambda key, default=None: {
            'DEV_DATABASE_URI': None,
            'DATABASE_URL': 'postgresql://prod:pass@localhost/proddb',
            'DATABASE_TYPE': None
        }.get(key, default)
        
        config = DevelopmentConfig()
        
        assert config.SQLALCHEMY_DATABASE_URI == 'postgresql://prod:pass@localhost/proddb'


def test_development_config_sqlite_fallback():
    """Test DevelopmentConfig sqlite fallback - lines 92-94."""
    with patch('app.config.loadConfigValueFromFileOrEnvironment') as mock_load:
        mock_load.side_effect = lambda key, default=None: {
            'DEV_DATABASE_URI': None,
            'DATABASE_URL': None,
            'DATABASE_TYPE': None
        }.get(key, default)
        
        config = DevelopmentConfig()
        
        assert config.SQLALCHEMY_DATABASE_URI == 'sqlite:///:memory:'


def test_development_config_sqlite_file_fallback():
    """Test DevelopmentConfig sqlite file fallback - line 96."""
    with patch('app.config.loadConfigValueFromFileOrEnvironment') as mock_load:
        mock_load.side_effect = lambda key, default=None: {
            'DEV_DATABASE_URI': None,
            'DATABASE_URL': None,
            'DATABASE_TYPE': 'postgresql'  # Set to non-None to trigger file fallback
        }.get(key, default)
        
        config = DevelopmentConfig()
        
        assert config.SQLALCHEMY_DATABASE_URI == 'sqlite:////data/sqlite/certtransparency_service.db'


def test_build_database_string_missing_variables():
    """Test build_database_string with missing DATABASE_* variables - lines 125-137."""
    config = Config()
    config.SQLALCHEMY_DATABASE_URI = None
    config.DATABASE_URL = None
    config.DATABASE_HOSTNAME = None
    config.DATABASE_NAME = 'testdb'
    config.DATABASE_USERNAME = 'user'
    config.DATABASE_PASSWORD = 'pass'
    
    with pytest.raises(RuntimeError, match='Environment variable DATABASE_URL was not defined'):
        build_database_string(config)


def test_build_database_string_with_database_url():
    """Test build_database_string with DATABASE_URL set."""
    config = Config()
    config.SQLALCHEMY_DATABASE_URI = None
    config.DATABASE_URL = 'postgresql://user:pass@localhost/testdb'
    
    build_database_string(config)
    
    assert config.SQLALCHEMY_DATABASE_URI == 'postgresql://user:pass@localhost/testdb'


def test_build_database_string_with_all_variables():
    """Test build_database_string with all DATABASE_* variables."""
    config = Config()
    config.SQLALCHEMY_DATABASE_URI = None
    config.DATABASE_URL = None
    config.DATABASE_TYPE = 'postgresql'
    config.DATABASE_HOSTNAME = 'localhost'
    config.DATABASE_PORT = '5432'
    config.DATABASE_NAME = 'testdb'
    config.DATABASE_USERNAME = 'user'
    config.DATABASE_PASSWORD = 'pass'
    
    build_database_string(config)
    
    assert config.SQLALCHEMY_DATABASE_URI == 'postgresql://user:pass@localhost:5432/testdb'


def test_get_config_development():
    """Test get_config with development environment - lines 148-161."""
    with patch('app.config.alwaysLoadConfigValueFromFileOrEnvironment') as mock_load:
        def mock_env_load(key, default=None):
            if key == 'ENVIRONMENT':
                return 'development'
            elif key == 'FLASK_SECRET_KEY':
                return 'test-secret'
            elif key == 'LOG_RETENTION_DAYS':
                return str(7 * 365)
            elif key == 'PAGE_SIZE':
                return '100'
            elif key == 'MAX_PAGE_SIZE':
                return '1000'
            elif key == 'LOG_LEVEL':
                return 'INFO'
            else:
                return default
        mock_load.side_effect = mock_env_load
        
        config = get_config()
        
        assert isinstance(config, DevelopmentConfig)


def test_get_config_testing():
    """Test get_config with testing environment."""
    with patch('app.config.alwaysLoadConfigValueFromFileOrEnvironment') as mock_load:
        def mock_env_load(key, default=None):
            if key == 'ENVIRONMENT':
                return 'testing'
            elif key == 'FLASK_SECRET_KEY':
                return 'test-secret'
            elif key == 'LOG_RETENTION_DAYS':
                return str(7 * 365)
            elif key == 'PAGE_SIZE':
                return '100'
            elif key == 'MAX_PAGE_SIZE':
                return '1000'
            elif key == 'LOG_LEVEL':
                return 'INFO'
            else:
                return default
        mock_load.side_effect = mock_env_load
        
        config = get_config()
        
        assert isinstance(config, UnitTestConfig)


def test_get_config_production():
    """Test get_config with production environment."""
    with patch('app.config.alwaysLoadConfigValueFromFileOrEnvironment') as mock_load, \
         patch('app.config.loadConfigValueFromFileOrEnvironment') as mock_load_optional:
        def mock_env_load(key, default=None):
            if key == 'ENVIRONMENT':
                return 'production'
            elif key == 'FLASK_SECRET_KEY':
                return 'prod-secret'
            elif key == 'LOG_RETENTION_DAYS':
                return str(7 * 365)
            elif key == 'PAGE_SIZE':
                return '100'
            elif key == 'MAX_PAGE_SIZE':
                return '1000'
            elif key == 'LOG_LEVEL':
                return 'INFO'
            else:
                return default
        mock_load.side_effect = mock_env_load
        
        def mock_load_opt(key, default=None):
            if key == 'DATABASE_URL':
                return 'postgresql://prod:pass@localhost/proddb'
            else:
                return default
        mock_load_optional.side_effect = mock_load_opt
        
        config = get_config()
        
        assert isinstance(config, ProductionConfig)


def test_get_config_unknown_environment():
    """Test get_config with unknown environment defaults to development."""
    with patch('app.config.alwaysLoadConfigValueFromFileOrEnvironment') as mock_load:
        def mock_env_load(key, default=None):
            if key == 'ENVIRONMENT':
                return 'unknown'
            elif key == 'FLASK_SECRET_KEY':
                return 'test-secret'
            elif key == 'LOG_RETENTION_DAYS':
                return str(7 * 365)
            elif key == 'PAGE_SIZE':
                return '100'
            elif key == 'MAX_PAGE_SIZE':
                return '1000'
            elif key == 'LOG_LEVEL':
                return 'INFO'
            else:
                return default
        mock_load.side_effect = mock_env_load
        
        config = get_config()
        
        assert isinstance(config, DevelopmentConfig)


def test_production_config_secret_key():
    """Test ProductionConfig calls alwaysLoadConfigValueFromFileOrEnvironment for FLASK_SECRET_KEY."""
    with patch('app.config.alwaysLoadConfigValueFromFileOrEnvironment') as mock_load:
        def mock_env_load(key, default=None):
            if key == 'FLASK_SECRET_KEY':
                return 'production-secret'
            elif key == 'LOG_RETENTION_DAYS':
                return str(7 * 365)
            elif key == 'PAGE_SIZE':
                return '100'
            elif key == 'MAX_PAGE_SIZE':
                return '1000'
            elif key == 'LOG_LEVEL':
                return 'INFO'
            else:
                return default
        mock_load.side_effect = mock_env_load
        
        config = ProductionConfig()
        
        # Verify FLASK_SECRET_KEY was loaded from environment in production
        calls = mock_load.call_args_list
        flask_secret_key_calls = [call for call in calls if call[0][0] == 'FLASK_SECRET_KEY']
        assert len(flask_secret_key_calls) >= 1  # At least one call for FLASK_SECRET_KEY


def test_missing_secret_key_raises_runtime_error():
    """
    Test that missing FLASK_SECRET_KEY raises a RuntimeError (line 32).
    """
    with patch('app.config.alwaysLoadConfigValueFromFileOrEnvironment') as mock_load:
        # Return None for FLASK_SECRET_KEY to trigger the RuntimeError
        mock_load.return_value = None
        
        with pytest.raises(RuntimeError, match="FLASK_SECRET_KEY must be set"):
            Config()