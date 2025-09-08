import os
import logging
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger('utils/environment')
logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO').upper())

def logReturningValue(key: str, value: Optional[str]):
    if value is None:
        logger.debug(f'{key} is set to "None-As-Defined"')
    else:
        if 'password' in key.lower():
            value = f'{value[:1]}*****{value[-1:]}'
        elif 'uri' in key.lower() or 'url' in key.lower():
            uri = urlparse(value)
            if uri.password is not None and len(uri.password) > 0:
                value = value.replace(uri.password, f'{uri.password[:1]}*****{uri.password[-1:]}')
        logger.debug(f'{key} is set to "{value}"')


def loadConfigValueFromFileOrEnvironment(key: str, default_value: Optional[str] = '', default_path: str = '') -> Optional[str]:
    """
    Load configuration values, by preference from a variable file (e.g. SECRET_FILE).
    This function reads the entire file content and strips leading/trailing whitespace.
    """
    VALUE_FILE = os.environ.get(f'{key}_FILE', None)
    if VALUE_FILE is None and default_path != '':
        logger.debug(f'{key}_FILE is not set. Using "{default_path}".')
        VALUE_FILE = default_path
    elif VALUE_FILE is None:
        logger.debug(f'{key}_FILE is not set. Skipping.')
        VALUE_FILE = default_path

    if VALUE_FILE != '':
        if not os.path.exists(VALUE_FILE):
            raise FileNotFoundError(f'{key}_FILE is set to {VALUE_FILE} but the path does not exist.')
        if not os.path.isfile(VALUE_FILE):
            raise FileNotFoundError(f'{key}_FILE is set to {VALUE_FILE} but the path is not a file.')
        
        logger.debug(f'Reading {VALUE_FILE}')
        with open(VALUE_FILE, 'r') as file:
            # Read the entire content of the file and strip whitespace
            file_content = file.read().strip()
    
        logger.debug(f'{VALUE_FILE} contains:')

        if file_content: # Use content if the file is not empty
            logReturningValue(key, file_content)
            return file_content
        
        logger.debug('---No Content---')
    
    VALUE = os.environ.get(key, None)
    if VALUE is None:
        logger.debug(f'{key} is not set. Using the default value.')
        VALUE = default_value

    logReturningValue(key, VALUE)
    return VALUE

def alwaysLoadConfigValueFromFileOrEnvironment(key: str, default_value: str = '', default_path: str = '') -> str:
    """
    Wrap the loadConfigValueFromFileOrEnvironment to raise an error when it returns a None value 
    """
    VALUE = loadConfigValueFromFileOrEnvironment(key, default_value, default_path)

    if VALUE is None:
        raise RuntimeError(f'Environment variable {key} resolved to a value of None')

    return VALUE

def loadBoolConfigValue(key: str, default: str, prefer: bool = False):
    false_strings = ['false', 'no', 'off', '0']
    true_strings = ['true', 'yes', 'on', '1']
    if prefer:
        return False if not str(os.environ.get(key, default)).lower() in true_strings else True
    else:
        return True if not str(os.environ.get(key, default)).lower() in false_strings else False
