"""
Tests for environment utilities module.
"""

import os
import pytest
from unittest.mock import patch, mock_open, MagicMock
import tempfile

from app.utils.environment import (
    logReturningValue,
    loadConfigValueFromFileOrEnvironment,
    alwaysLoadConfigValueFromFileOrEnvironment,
    loadBoolConfigValue
)


def test_log_returning_value_password_masking():
    """Test logReturningValue with password masking - line 14."""
    with patch('app.utils.environment.logger') as mock_logger:
        logReturningValue('DATABASE_PASSWORD', 'secretpassword123')
        
        mock_logger.debug.assert_called_once()
        call_args = mock_logger.debug.call_args[0][0]
        assert 'DATABASE_PASSWORD is set to "s*****3"' == call_args


def test_log_returning_value_uri_password_masking():
    """Test logReturningValue with URI password masking - lines 16-18."""
    with patch('app.utils.environment.logger') as mock_logger:
        uri_with_password = 'postgresql://user:secretpass@localhost/db'
        logReturningValue('DATABASE_URI', uri_with_password)
        
        mock_logger.debug.assert_called_once()
        call_args = mock_logger.debug.call_args[0][0]
        assert 's*****s' in call_args  # Password should be masked


def test_log_returning_value_none():
    """Test logReturningValue with None value - line 11."""
    with patch('app.utils.environment.logger') as mock_logger:
        logReturningValue('TEST_KEY', None)
        
        mock_logger.debug.assert_called_once_with('TEST_KEY is set to "None-As-Defined"')


def test_load_config_value_default_path_fallback():
    """Test loadConfigValueFromFileOrEnvironment default_path fallback - line 29."""
    with patch('app.utils.environment.logger') as mock_logger:
        with patch('os.path.exists', return_value=True):
            with patch('os.path.isfile', return_value=True):
                with patch('builtins.open', mock_open(read_data='file_content')):
                    with patch.dict(os.environ, {}, clear=True):
                        result = loadConfigValueFromFileOrEnvironment('TEST_KEY', 'default_val', '/test/path')
        
        mock_logger.debug.assert_any_call('TEST_KEY_FILE is not set. Using "/test/path".')
        assert result == 'file_content'


def test_load_config_value_no_file_no_default():
    """Test loadConfigValueFromFileOrEnvironment with no file and no default - line 30."""
    with patch('app.utils.environment.logger') as mock_logger:
        with patch.dict(os.environ, {}, clear=True):
            result = loadConfigValueFromFileOrEnvironment('TEST_KEY', 'default_val', '')
        
        mock_logger.debug.assert_any_call('TEST_KEY_FILE is not set. Skipping.')


def test_load_config_value_file_operations():
    """Test loadConfigValueFromFileOrEnvironment file operations - lines 36-52."""
    # Test file not found
    with patch('app.utils.environment.logger') as mock_logger:
        with patch.dict(os.environ, {'TEST_KEY_FILE': '/nonexistent/file.txt'}, clear=True):
            with pytest.raises(FileNotFoundError):
                loadConfigValueFromFileOrEnvironment('TEST_KEY')
    
    # Test path is not a file
    with patch('app.utils.environment.logger') as mock_logger:
        with patch('os.path.exists', return_value=True):
            with patch('os.path.isfile', return_value=False):
                with patch.dict(os.environ, {'TEST_KEY_FILE': '/some/dir'}, clear=True):
                    with pytest.raises(FileNotFoundError):
                        loadConfigValueFromFileOrEnvironment('TEST_KEY')
    
    # Test successful file read
    with patch('app.utils.environment.logger') as mock_logger:
        with patch('os.path.exists', return_value=True):
            with patch('os.path.isfile', return_value=True):
                with patch('builtins.open', mock_open(read_data='  file_content  \n')):
                    with patch.dict(os.environ, {'TEST_KEY_FILE': '/test/file.txt'}, clear=True):
                        result = loadConfigValueFromFileOrEnvironment('TEST_KEY')
                        assert result == 'file_content'
    
    # Test empty file
    with patch('app.utils.environment.logger') as mock_logger:
        with patch('os.path.exists', return_value=True):
            with patch('os.path.isfile', return_value=True):
                with patch('builtins.open', mock_open(read_data='')):
                    with patch.dict(os.environ, {'TEST_KEY_FILE': '/test/empty.txt', 'TEST_KEY': 'env_value'}, clear=True):
                        result = loadConfigValueFromFileOrEnvironment('TEST_KEY', 'default_val')
                        assert result == 'env_value'


def test_always_load_config_value_runtime_error():
    """Test alwaysLoadConfigValueFromFileOrEnvironment RuntimeError - line 69."""
    with patch('app.utils.environment.loadConfigValueFromFileOrEnvironment', return_value=None):
        with pytest.raises(RuntimeError, match='Environment variable TEST_KEY resolved to a value of None'):
            alwaysLoadConfigValueFromFileOrEnvironment('TEST_KEY')


def test_load_bool_config_value_prefer_true():
    """Test loadBoolConfigValue with prefer=True - line 77."""
    with patch.dict(os.environ, {'TEST_BOOL': 'false'}, clear=True):
        result = loadBoolConfigValue('TEST_BOOL', 'true', prefer=True)
        assert result is False
    
    with patch.dict(os.environ, {'TEST_BOOL': 'true'}, clear=True):
        result = loadBoolConfigValue('TEST_BOOL', 'false', prefer=True)
        assert result is True
    
    with patch.dict(os.environ, {}, clear=True):
        result = loadBoolConfigValue('TEST_BOOL', 'false', prefer=True)
        assert result is False


def test_load_bool_config_value_prefer_false():
    """Test loadBoolConfigValue with prefer=False (default behavior)."""
    with patch.dict(os.environ, {'TEST_BOOL': 'true'}, clear=True):
        result = loadBoolConfigValue('TEST_BOOL', 'false', prefer=False)
        assert result is True
    
    with patch.dict(os.environ, {'TEST_BOOL': 'false'}, clear=True):
        result = loadBoolConfigValue('TEST_BOOL', 'true', prefer=False)
        assert result is False


def test_always_load_config_value_success():
    """Test alwaysLoadConfigValueFromFileOrEnvironment successful case."""
    with patch('app.utils.environment.loadConfigValueFromFileOrEnvironment', return_value='success_value'):
        result = alwaysLoadConfigValueFromFileOrEnvironment('TEST_KEY')
        assert result == 'success_value'