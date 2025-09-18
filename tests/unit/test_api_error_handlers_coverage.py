"""
Test cases to achieve 100% coverage for blueprint error handlers in api.py.
"""

import pytest
from werkzeug.exceptions import NotFound, InternalServerError


class TestAPIErrorHandlersCoverage:
    """Tests to cover blueprint error handlers in api.py."""

    def test_api_blueprint_404_error_handler_coverage(self, app):
        """Test blueprint 404 error handler - covers api.py line 739."""
        from app.routes.api import api_bp
        from werkzeug.exceptions import NotFound

        # Get the blueprint error handler function directly
        error_handler = api_bp.error_handler_spec[None][404][NotFound]

        # Create a mock exception
        mock_exception = NotFound("Test not found error")

        # Call the error handler directly
        with app.test_request_context():
            result = error_handler(mock_exception)

            # Should return JSON response with 404 status code
            response_data, status_code = result
            assert status_code == 404
            assert response_data.json == {'error': 'Endpoint not found'}

    def test_api_blueprint_500_error_handler_coverage(self, app):
        """Test blueprint 500 error handler - covers api.py line 745."""
        from app.routes.api import api_bp
        from werkzeug.exceptions import InternalServerError

        # Get the blueprint error handler function directly
        error_handler = api_bp.error_handler_spec[None][500][InternalServerError]

        # Create a mock exception
        mock_exception = InternalServerError("Test internal server error")

        # Call the error handler directly
        with app.test_request_context():
            result = error_handler(mock_exception)

            # Should return JSON response with 500 status code
            response_data, status_code = result
            assert status_code == 500
            assert response_data.json == {'error': 'Internal server error'}