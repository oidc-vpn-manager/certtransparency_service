# Certificate Transparency Service

This file provides LLMs with guidance for working with the Certificate Transparency Service component of OpenVPN Manager.

## Service Overview

The Certificate Transparency Service is a specialized microservice that provides an unauthenticated, read-only audit log of all certificates issued by OpenVPN Manager. It operates on port 8800 and maintains a complete, append-only record of certificate operations for transparency and compliance.

## Architecture

### Flask Application Structure
- `app/` - Main application directory
  - `routes/` - API route handlers
    - `api.py` - Certificate transparency API endpoints
  - `models/` - SQLAlchemy database models
    - `certificate_log.py` - Main certificate logging model
    - `certificate_revocation.py` - Certificate revocation tracking
    - `crl_counter.py` - CRL sequence number management
  - `utils/` - Utility modules
    - `crl_generator.py` - Certificate revocation list generation
    - `geoip.py` - IP geolocation for request tracking
    - `log_client.py` - External CT log integration
    - `decorators.py` - Authentication and validation decorators
    - `environment.py` - Environment configuration handling
  - `config.py` - Application configuration
  - `app.py` - Flask application factory

### Database Design
- **Append-only logging**: No modification of existing records allowed
- **Certificate metadata**: Complete certificate information storage
- **Audit trail**: Request metadata including IP geolocation
- **Revocation tracking**: CRL generation and certificate status

## Key Dependencies

- **Flask**: Web framework
- **Flask-SQLAlchemy**: Database ORM
- **Flask-Migrate**: Database schema versioning
- **psycopg2-binary**: PostgreSQL adapter
- **cryptography**: Certificate parsing and validation
- **PyJWT**: JWT token handling for authentication
- **geoip2**: IP address geolocation
- **flask-swagger-ui**: API documentation
- **requests**: External service communication

## Development Workflow

### Local Development
```bash
cd services/certtransparency

# Install dependencies
pip install -r requirements.txt

# Run database migrations
./run_migrate.sh

# Run with Flask development server
export FLASK_APP=app
flask run --port 8800

# Run with Gunicorn (production-like)
gunicorn wsgi:app --bind 0.0.0.0:8800
```

### Testing
```bash
# Unit tests
python -m pytest tests/unit/ -v

# Integration tests
python -m pytest tests/integration/ -v

# All tests with coverage
python -m pytest tests/ --cov=app --cov-report=html
```

### Database Operations
```bash
# Create new migration
flask db migrate -m "Description of changes"

# Apply migrations
flask db upgrade

# Downgrade migrations (use with caution)
flask db downgrade
```

## API Endpoints

### Certificate Logging
- `POST /api/v1/certificates` - Log new certificate issuance
  - Accepts certificate details and metadata
  - Stores complete audit trail
  - Returns logging confirmation

### Certificate Queries
- `GET /api/v1/certificates` - Query certificate records
  - Supports filtering by serial number, subject, date ranges
  - Public read access (no authentication required)
  - Pagination support for large result sets

### Certificate Revocation
- `POST /api/v1/revocations` - Log certificate revocations
- `GET /api/v1/crl` - Download current certificate revocation list
- `GET /api/v1/crl/{sequence}` - Download specific CRL version

### Health & Monitoring
- `GET /health` - Service health check
- `GET /api` - API documentation (Swagger UI)

## Configuration

### Environment Variables
- `DATABASE_URL` - PostgreSQL connection string
- `CT_SERVICE_API_SECRET_FILE` - API authentication secret file
- `GEOIP_DATABASE_PATH` - Path to GeoIP database file
- `EXTERNAL_CT_LOG_URL` - External CT log service URL (optional)
- `CRL_SIGNING_KEY_FILE` - CRL signing private key (optional)

### Database Configuration
- PostgreSQL database for certificate records
- Indexes optimized for certificate serial number and date queries
- Retention policies for historical data
- Backup and recovery procedures

## Data Models

### Certificate Log Model
- **Certificate Details**: Serial number, subject, issuer, validity periods
- **Cryptographic Info**: Key type, algorithm, fingerprints
- **Metadata**: Issuance timestamp, requesting IP, user agent
- **Audit Fields**: Service version, processing time, external log status

### Revocation Model
- **Certificate Reference**: Links to certificate log entry
- **Revocation Details**: Revocation timestamp, reason code
- **CRL Integration**: Sequence numbers and CRL generation status

### GeoIP Integration
- **Request Tracking**: IP address geolocation for certificate requests
- **Privacy Compliance**: Configurable data retention periods
- **Audit Enhancement**: Geographic patterns for security monitoring

## Security & Compliance Features

### Audit Trail
- Complete record of all certificate operations
- Immutable logging (append-only database design)
- Request metadata for forensic analysis
- Integration with external certificate transparency logs

### Privacy Protection
- Configurable data retention policies
- Anonymous query support
- No personally identifiable information in logs
- GDPR compliance features

### Access Control
- Read-only public API for transparency
- Write access requires API authentication
- Rate limiting for query endpoints
- DDoS protection mechanisms

## Testing Standards

- **100% test coverage required**
- Unit tests for all data models and utilities
- Integration tests for API endpoints
- Functional tests for complete audit workflows
- Performance tests for high-volume scenarios
- **Comprehensive security testing** including:
  - Red team attack simulation (SQL injection, parameter pollution, resource exhaustion)
  - Blue team defensive validation (input sanitization, rate limiting)
  - Bug bounty vulnerability patterns (timing attacks, authentication bypass)
  - Real vulnerability discovery and remediation with timing attack prevention

## Common Operations

### Adding New Certificate Metadata
1. Update certificate log model in `models/certificate_log.py`
2. Create database migration for schema changes
3. Update certificate parsing logic in API handlers
4. Add validation for new metadata fields
5. Update tests and documentation

### CRL Generation
1. Configure CRL signing key in environment
2. Update CRL generation logic in `utils/crl_generator.py`
3. Implement CRL distribution points
4. Add CRL validation and testing
5. Configure automated CRL refresh

### External CT Log Integration
1. Configure external CT log URLs and credentials
2. Implement certificate submission in `utils/log_client.py`
3. Add retry logic and error handling
4. Monitor submission success rates
5. Implement certificate validation via external logs

## Debugging & Monitoring

### Logging
- Structured JSON logging for all operations
- Certificate operation event logging
- Query performance metrics
- Error tracking with request context

### Health Monitoring
- Database connectivity and performance
- External service availability
- Storage utilization and retention
- Query response times and throughput

### Audit Monitoring
- Certificate issuance rate anomalies
- Unusual query patterns
- Failed authentication attempts
- External CT log submission failures

## File Structure Notes

- `migrations/` - Flask-Migrate database schemas
- `scripts/` - Utility scripts for maintenance
- `run_migrate.sh` - Database migration helper
- `tests/` - Comprehensive test suite
- `wsgi.py` - WSGI application entry point
- `Dockerfile` - Container build configuration

## Compliance & Regulatory Notes

### Certificate Transparency Standards
- RFC 6962 compliance for CT log operations
- Merkle tree construction for log integrity
- Signed Certificate Timestamp (SCT) generation
- Integration with public CT log infrastructure

### Data Retention
- Configurable retention periods for certificate records
- Automated archiving of historical data
- Secure deletion procedures for expired data
- Backup and disaster recovery plans

### Audit Requirements
- Complete audit trail for all certificate operations
- Tamper-evident logging mechanisms
- Regular integrity checks and validation
- Compliance reporting and monitoring

## Performance Considerations

### Database Optimization
- Indexes on frequently queried fields
- Partitioning for large datasets
- Query optimization for complex searches
- Connection pooling and caching

### High Availability
- Database replication and failover
- Load balancing for read queries
- Monitoring and alerting systems
- Automated recovery procedures

### Scalability
- Horizontal scaling for read replicas
- Efficient pagination for large result sets
- Caching strategies for frequent queries
- Resource monitoring and auto-scaling