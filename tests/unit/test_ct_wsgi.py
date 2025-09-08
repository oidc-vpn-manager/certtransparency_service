"""
Tests for CT Service WSGI entry point.
"""

import pytest
from unittest.mock import patch, MagicMock
import sys
import os


def test_wsgi_file_structure():
    """Test the WSGI file has the correct structure."""
    wsgi_file_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'wsgi.py')
    
    with open(wsgi_file_path, 'r') as f:
        content = f.read()
    
    # Verify the file contains the expected structure
    assert 'from app import create_app' in content
    assert 'application = create_app()' in content
    assert 'if __name__ == \'__main__\':' in content
    assert 'application.run(debug=True, host=\'0.0.0.0\', port=8800)' in content


def test_wsgi_module_coverage():
    """Test that we can import and verify WSGI module behavior."""
    # This test ensures the WSGI module lines are executed for coverage
    # We'll mock the dependencies to avoid configuration issues
    mock_app = MagicMock()
    
    with patch.dict('sys.modules', {
        'app': MagicMock(),
        'certtransparency_service.app': MagicMock()
    }):
        # Mock create_app at the module level
        import importlib.util
        
        # Load the WSGI module source code
        wsgi_file_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'wsgi.py')
        
        # Create a mock create_app function
        mock_create_app = MagicMock(return_value=mock_app)
        
        # Execute the WSGI code with mocked dependencies
        namespace = {
            '__name__': 'certtransparency_service.wsgi',
            'create_app': mock_create_app
        }
        
        with open(wsgi_file_path, 'r') as f:
            wsgi_code = f.read()
        
        # Replace the import line to use our mock
        modified_code = wsgi_code.replace('from app import create_app', 'pass # mocked')
        
        exec(modified_code, namespace)
        
        # Verify the application was created
        assert 'application' in namespace
        assert namespace['application'] == mock_app
        mock_create_app.assert_called_once()


def test_wsgi_main_block():
    """Test the main block execution path."""
    # This test covers the if __name__ == '__main__' block
    mock_app = MagicMock()
    
    # Load and execute the main block logic
    wsgi_file_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'wsgi.py')
    
    with open(wsgi_file_path, 'r') as f:
        content = f.read()
    
    # Extract the main block
    lines = content.split('\n')
    main_block_started = False
    main_block_lines = []
    
    for line in lines:
        if 'if __name__ == \'__main__\':' in line:
            main_block_started = True
            continue
        if main_block_started:
            main_block_lines.append(line)
    
    # Execute the main block with mocked application
    namespace = {
        '__name__': '__main__',
        'application': mock_app
    }
    
    # Remove indentation from main block lines
    main_code = '\n'.join(line.strip() for line in main_block_lines if line.strip())
    exec(main_code, namespace)
    
    # Verify run was called with correct parameters
    mock_app.run.assert_called_once_with(debug=True, host='0.0.0.0', port=8800)