"""
Configuration classes for the Certificate Transparency Service.

This module provides configuration classes for different environments
(development, testing, production) with appropriate defaults and
environment variable overrides.
"""

import os
import logging
from typing import Optional

from .utils.environment import (
    alwaysLoadConfigValueFromFileOrEnvironment,
    loadConfigValueFromFileOrEnvironment,
    loadBoolConfigValue
)

logger = logging.getLogger('Config')
logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO').upper())

class Config:
    """Base configuration class with common settings."""
    
    def __init__(self):
        """Initialize configuration values from environment."""
        self.SQLALCHEMY_DATABASE_URI: Optional[str] = None

        # Flask settings - FLASK_SECRET_KEY is required
        self.SECRET_KEY = alwaysLoadConfigValueFromFileOrEnvironment('FLASK_SECRET_KEY')
        if not self.SECRET_KEY:
            raise RuntimeError(
                "FLASK_SECRET_KEY must be set. Generate with: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
            )

        # Database configuration
        self.DATABASE_TYPE = loadConfigValueFromFileOrEnvironment(
            'DATABASE_TYPE', 'postgresql'
        )
        self.DATABASE_HOSTNAME = loadConfigValueFromFileOrEnvironment(
            'DATABASE_HOSTNAME', None
        )
        self.DATABASE_PORT = loadConfigValueFromFileOrEnvironment(
            'DATABASE_PORT', '5432'
        )
        self.DATABASE_NAME = loadConfigValueFromFileOrEnvironment(
            'DATABASE_NAME', None
        )
        self.DATABASE_USERNAME = loadConfigValueFromFileOrEnvironment(
            'DATABASE_USERNAME', None
        )
        self.DATABASE_PASSWORD = loadConfigValueFromFileOrEnvironment(
            'DATABASE_PASSWORD', None
        )

        self.DATABASE_URL = loadConfigValueFromFileOrEnvironment('DATABASE_URL', None)

        self.SQLALCHEMY_TRACK_MODIFICATIONS = loadBoolConfigValue(
            'TRACK_MODIFICATIONS', 'False'
        )

        # Certificate Transparency specific settings
        self.CT_LOG_RETENTION_DAYS = int(alwaysLoadConfigValueFromFileOrEnvironment(
            'LOG_RETENTION_DAYS', str(7 * 365))
        )
        self.CT_PAGE_SIZE = int(
            alwaysLoadConfigValueFromFileOrEnvironment('PAGE_SIZE', "100")
        )
        self.CT_MAX_PAGE_SIZE = int(
            alwaysLoadConfigValueFromFileOrEnvironment('MAX_PAGE_SIZE', "1000")
        )

        # Logging configuration
        self.LOG_TO_STDOUT = loadBoolConfigValue('LOG_TO_STDOUT', "True")
        self.LOG_LEVEL = alwaysLoadConfigValueFromFileOrEnvironment('LOG_LEVEL', 'INFO')
        
        # API Authentication
        self.CT_SERVICE_API_SECRET = loadConfigValueFromFileOrEnvironment(
            'CT_SERVICE_API_SECRET', None
        )

        # Rate Limiting Configuration
        self.RATELIMIT_STORAGE_URI = loadConfigValueFromFileOrEnvironment(
            'RATELIMIT_STORAGE_URL', 'memory://'
        )

class DevelopmentConfig(Config):
    """Development configuration."""
    
    def __init__(self):
        """Initialize development configuration."""
        super().__init__()
        self.DEBUG = True

        # Use DEV_CT_DATABASE_URI if set, otherwise fall back to DATABASE_URL or in-memory for tests
        DEV_DATABASE_URI = loadConfigValueFromFileOrEnvironment(
            'DEV_DATABASE_URI', None
        )
        if DEV_DATABASE_URI:
            self.SQLALCHEMY_DATABASE_URI = DEV_DATABASE_URI
        elif loadConfigValueFromFileOrEnvironment('DATABASE_URL', None):
            self.SQLALCHEMY_DATABASE_URI = loadConfigValueFromFileOrEnvironment(
                'DATABASE_URL')
        elif not loadConfigValueFromFileOrEnvironment('DATABASE_TYPE', None):
            # No database config found, use in-memory SQLite for testing
            self.SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
        else:
            self.SQLALCHEMY_DATABASE_URI = 'sqlite:////data/sqlite/certtransparency_service.db'


class UnitTestConfig(Config):
    """Testing configuration."""
    
    def __init__(self):
        """Initialize testing configuration."""
        super().__init__()
        self.TESTING = True
        self.SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
        self.WTF_CSRF_ENABLED = False


class ProductionConfig(Config):
    """Production configuration."""
    
    def __init__(self):
        """Initialize production configuration."""
        super().__init__()
        self.DEBUG = False


def build_database_string(config: Config):
    if config.SQLALCHEMY_DATABASE_URI is not None:
        pass
    elif config.DATABASE_URL is not None:
        config.SQLALCHEMY_DATABASE_URI = config.DATABASE_URL
    else:
        if (
            config.DATABASE_HOSTNAME is None or 
            config.DATABASE_NAME is None or 
            config.DATABASE_USERNAME is None or
            config.DATABASE_PASSWORD is None
        ):
            raise RuntimeError(f'Environment variable DATABASE_URL was not defined, but one or more of the other DATABASE_* variables were also not defined.')
        
        config.SQLALCHEMY_DATABASE_URI = f'{config.DATABASE_TYPE}://{config.DATABASE_USERNAME}:{config.DATABASE_PASSWORD}@{config.DATABASE_HOSTNAME}:{config.DATABASE_PORT}/{config.DATABASE_NAME}'


def get_config():
    """
    Get the configuration class based on the environment.

    Returns:
        Config class appropriate for the current environment
    """
    env = alwaysLoadConfigValueFromFileOrEnvironment(
        'ENVIRONMENT', 'production').lower()

    config_map = {
        'development': DevelopmentConfig,
        'testing': UnitTestConfig,
        'production': ProductionConfig,
    }

    config_class = config_map.get(env, DevelopmentConfig)
    result = config_class()
    build_database_string(result)

    return result
