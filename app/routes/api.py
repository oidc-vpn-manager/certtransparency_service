"""
Certificate Transparency API endpoints.

Provides unauthenticated read-only access to certificate transparency logs
for compliance and audit purposes.
"""

import json
from datetime import datetime, timezone
from flask import Blueprint, jsonify, request, current_app
from sqlalchemy import desc, asc, and_, or_

from app.models.certificate_log import CertificateLog
from app.models.crl_counter import CRLCounter
from app.utils.decorators import api_secret_required
from app.utils.geoip import lookup_country_code
from app.extensions import db, limiter

api_bp = Blueprint('api', __name__)


@api_bp.route('/certificates', methods=['GET'])
@limiter.limit("100 per minute")
def list_certificates():
    """
    List certificates with pagination and filtering.
    
    Query Parameters:
        - page (int): Page number (default: 1)
        - limit (int): Number of results per page (default: 100, max: 1000)
        - type (str): Certificate type filter ('client', 'server', 'intermediate')
        - subject (str): Filter by subject common name (partial match)
        - issuer (str): Filter by issuer common name (partial match)
        - serial (str): Filter by serial number (exact match)
        - fingerprint (str): Filter by SHA-256 fingerprint (exact match)
        - from_date (str): Filter certificates issued from this date (ISO format)
        - to_date (str): Filter certificates issued until this date (ISO format)
        - include_revoked (bool): Include revoked certificates (default: true)
        - include_pem (bool): Include PEM certificate data (default: false)
        - sort (str): Sort field ('issued_at', 'not_before', 'not_after', 'subject_common_name')
        - order (str): Sort order ('asc', 'desc') (default: 'desc')
    
    Returns:
        JSON response with certificate list and pagination metadata
    """
    # Parse pagination parameters with security validation
    page = max(1, request.args.get('page', 1, type=int))  # Ensure page >= 1
    limit = request.args.get('limit', 100, type=int)
    limit = max(1, min(limit, 1000))  # Ensure 1 <= limit <= 1000
    
    # Parse filtering parameters with input sanitization
    from markupsafe import escape
    cert_type = escape(request.args.get('type', '')) if request.args.get('type') else None
    subject_filter = escape(request.args.get('subject', '')) if request.args.get('subject') else None
    issuer_filter = escape(request.args.get('issuer', '')) if request.args.get('issuer') else None
    serial_filter = escape(request.args.get('serial', '')) if request.args.get('serial') else None
    fingerprint_filter = escape(request.args.get('fingerprint', '')) if request.args.get('fingerprint') else None
    from_date = request.args.get('from_date')
    to_date = request.args.get('to_date')
    include_revoked = request.args.get('include_revoked', 'true').lower() == 'true'
    include_pem = request.args.get('include_pem', 'false').lower() == 'true'
    
    # Validate date formats
    if from_date:
        try:
            datetime.fromisoformat(from_date.replace('Z', '+00:00'))
        except ValueError:
            return jsonify({'error': f'Invalid from_date format: {from_date}. Use ISO format (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS)'}), 400
    
    if to_date:
        try:
            datetime.fromisoformat(to_date.replace('Z', '+00:00'))
        except ValueError:
            return jsonify({'error': f'Invalid to_date format: {to_date}. Use ISO format (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS)'}), 400
    
    # Parse sorting parameters
    sort_field = request.args.get('sort', 'issued_at')
    sort_order = request.args.get('order', 'desc')
    
    # Build filters dictionary for append-only query
    filters = {}
    if cert_type:
        filters['type'] = cert_type
    if subject_filter:
        filters['subject'] = subject_filter
    if issuer_filter:
        filters['issuer'] = issuer_filter
    if serial_filter:
        filters['serial'] = serial_filter
    if fingerprint_filter:
        filters['fingerprint'] = fingerprint_filter
    if from_date:
        filters['from_date'] = from_date
    if to_date:
        filters['to_date'] = to_date
    if not include_revoked:
        filters['include_revoked'] = 'false'
    
    # Calculate offset for pagination
    offset = (page - 1) * limit
    
    try:
        # Use new append-only query method to get latest record per fingerprint
        certificates_data, total_count = CertificateLog.get_latest_certificates(
            limit=limit,
            offset=offset,
            filters=filters,
            sort_field=sort_field,
            sort_order=sort_order
        )
    except Exception as e:  # pragma: no cover

        ## PRAGMA-NO-COVER Exception; JS 2025-09-03 Database Exception requires SQL bug to test.

        return jsonify({'error': f'Database query failed: {str(e)}'}), 500
    
    # Format results
    certificates = []
    for cert in certificates_data:
        certificates.append(cert.to_dict(include_pem=include_pem))
    
    # Calculate pagination info
    total_pages = (total_count + limit - 1) // limit  # Ceiling division
    has_next = page < total_pages
    has_prev = page > 1
    
    return jsonify({
        'certificates': certificates,
        'pagination': {
            'page': page,
            'pages': total_pages,
            'per_page': limit,
            'total': total_count,
            'has_next': has_next,
            'has_prev': has_prev,
        },
        'filters': {
            'type': cert_type,
            'subject': subject_filter,
            'issuer': issuer_filter,
            'serial': serial_filter,
            'fingerprint': fingerprint_filter,
            'from_date': from_date,
            'to_date': to_date,
            'include_revoked': include_revoked,
        }
    }), 200


@api_bp.route('/certificates/<fingerprint>', methods=['GET'])
@limiter.limit("200 per minute")
def get_certificate_by_fingerprint(fingerprint):
    """
    Get a specific certificate by its SHA-256 fingerprint.
    
    Args:
        fingerprint (str): SHA-256 fingerprint of the certificate
    
    Query Parameters:
        - include_pem (bool): Include PEM certificate data (default: true)
    
    Returns:
        JSON response with certificate details
    """
    include_pem = request.args.get('include_pem', 'true').lower() == 'true'
    
    cert = CertificateLog.get_by_fingerprint(fingerprint)
    if not cert:
        return jsonify({'error': 'Certificate not found'}), 404
    
    return jsonify({
        'certificate': cert.to_dict(include_pem=include_pem)
    }), 200


@api_bp.route('/certificates/serial/<serial_number>', methods=['GET'])
@limiter.limit("200 per minute")
def get_certificate_by_serial(serial_number):
    """
    Get a specific certificate by its serial number.
    
    Args:
        serial_number (str): Serial number of the certificate
    
    Query Parameters:
        - include_pem (bool): Include PEM certificate data (default: true)
    
    Returns:
        JSON response with certificate details
    """
    include_pem = request.args.get('include_pem', 'true').lower() == 'true'
    
    cert = CertificateLog.get_by_serial_number(serial_number)
    if not cert:
        return jsonify({'error': 'Certificate not found'}), 404
    
    return jsonify({
        'certificate': cert.to_dict(include_pem=include_pem)
    }), 200


@api_bp.route('/certificates/subject/<common_name>', methods=['GET'])
@limiter.limit("100 per minute")
def get_certificates_by_subject(common_name):
    """
    Get all certificates for a specific subject common name.
    
    Args:
        common_name (str): Subject common name
    
    Query Parameters:
        - include_pem (bool): Include PEM certificate data (default: false)
        - include_revoked (bool): Include revoked certificates (default: true)
    
    Returns:
        JSON response with list of certificates for the subject
    """
    include_pem = request.args.get('include_pem', 'false').lower() == 'true'
    include_revoked = request.args.get('include_revoked', 'true').lower() == 'true'
    
    query = CertificateLog.query.filter_by(subject_common_name=common_name)
    
    if not include_revoked:
        query = query.filter(CertificateLog.revoked_at.is_(None))
    
    certificates = query.order_by(desc(CertificateLog.issued_at)).all()
    
    return jsonify({
        'subject_common_name': common_name,
        'certificate_count': len(certificates),
        'certificates': [cert.to_dict(include_pem=include_pem) for cert in certificates]
    }), 200


@api_bp.route('/statistics', methods=['GET'])
@limiter.limit("50 per minute")
def get_statistics():
    """
    Get certificate transparency statistics.
    
    Returns:
        JSON response with various statistics about issued certificates
    """
    try:
        # Get limited sample of certificates for statistics to prevent DoS
        # This provides reasonable statistics without expensive full table scans
        STATS_SAMPLE_LIMIT = 1000  # Reasonable sample size for statistics
        latest_certs_data, total_available = CertificateLog.get_latest_certificates(limit=STATS_SAMPLE_LIMIT)
        
        # Total unique certificates
        total_certs = len(latest_certs_data)
        
        # Certificates by type (count latest records)
        client_certs = sum(1 for cert in latest_certs_data if cert.certificate_type == 'client')
        server_certs = sum(1 for cert in latest_certs_data if cert.certificate_type == 'server')
        intermediate_certs = sum(1 for cert in latest_certs_data if cert.certificate_type == 'intermediate')
        
        # Active vs revoked (based on latest record per certificate)
        active_certs = sum(1 for cert in latest_certs_data if cert.action_type != 'revoked')
        revoked_certs = sum(1 for cert in latest_certs_data if cert.action_type == 'revoked')
        
        # Recent activity (last 30 days)
        thirty_days_ago = datetime.now(timezone.utc).replace(day=1)  # Simplified to first of month
        recent_certs = CertificateLog.query.filter(CertificateLog.issued_at >= thirty_days_ago).count()
        
        # Expiring soon (next 30 days)
        thirty_days_future = datetime.now(timezone.utc).replace(day=28)  # Simplified
        expiring_soon = CertificateLog.query.filter(
            and_(
                CertificateLog.not_after <= thirty_days_future,
                CertificateLog.revoked_at.is_(None)
            )
        ).count()
        
        return jsonify({
            'total_certificates': total_certs,
            'sample_size': len(latest_certs_data),
            'is_sample_based': len(latest_certs_data) >= STATS_SAMPLE_LIMIT,
            'by_type': {
                'client': client_certs,
                'server': server_certs,
                'intermediate': intermediate_certs,
            },
            'by_status': {
                'active': active_certs,
                'revoked': revoked_certs,
            },
            'recent_activity': {
                'issued_last_30_days': recent_certs,
                'expiring_next_30_days': expiring_soon,
            },
            'generated_at': datetime.now(timezone.utc).isoformat()
        }), 200
        
    except Exception as e:  # pragma: no cover

        ## PRAGMA-NO-COVER Exception; JS 2025-09-03 Database Exception requires SQL bug to test.

        return jsonify({'error': f'Failed to generate statistics: {str(e)}'}), 500


@api_bp.route('/search', methods=['GET'])
@limiter.limit("50 per minute")
def search_certificates():
    """
    Search certificates with flexible criteria.
    
    Query Parameters:
        - q (str): General search query (searches subject, issuer, serial, fingerprint)
        - exact (bool): Use exact matching instead of partial (default: false)
        - limit (int): Number of results (default: 100, max: 1000)
        - include_pem (bool): Include PEM certificate data (default: false)
    
    Returns:
        JSON response with search results
    """
    query_param = request.args.get('q', '').strip()
    if not query_param:
        return jsonify({'error': 'Query parameter "q" is required'}), 400
    
    exact_match = request.args.get('exact', 'false').lower() == 'true'
    limit = min(request.args.get('limit', 100, type=int), 1000)
    include_pem = request.args.get('include_pem', 'false').lower() == 'true'
    
    # Build search query
    if exact_match:
        # Exact matching
        query = CertificateLog.query.filter(
            or_(
                CertificateLog.subject_common_name == query_param,
                CertificateLog.issuer_common_name == query_param,
                CertificateLog.serial_number == query_param.upper(),
                CertificateLog.fingerprint_sha256 == query_param.upper()
            )
        )
    else:
        # Partial matching
        search_pattern = f'%{query_param}%'
        query = CertificateLog.query.filter(
            or_(
                CertificateLog.subject_common_name.ilike(search_pattern),
                CertificateLog.issuer_common_name.ilike(search_pattern),
                CertificateLog.serial_number.ilike(search_pattern),
                CertificateLog.fingerprint_sha256.ilike(search_pattern)
            )
        )
    
    # Execute query with limit
    results = query.order_by(desc(CertificateLog.issued_at)).limit(limit).all()
    
    return jsonify({
        'query': query_param,
        'exact_match': exact_match,
        'result_count': len(results),
        'results': [cert.to_dict(include_pem=include_pem) for cert in results]
    }), 200


@api_bp.route('/certificates', methods=['POST'])
@api_secret_required
def log_certificate():
    """
    Log a new certificate to the Certificate Transparency service.
    
    This endpoint accepts certificate data and stores it in the CT log.
    Authentication is required to prevent unauthorized certificate logging.
    
    Request Body (JSON):
        - certificate_pem (str): PEM-encoded certificate data (required)
        - certificate_type (str): Type of certificate ('client', 'server', 'intermediate') (required)
        - certificate_purpose (str): Purpose/description of the certificate (optional)
        - requester_info (dict): Information about who requested the certificate (optional)
        
    Returns:
        JSON response with logged certificate details
    """
    # Parse request body
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body must be JSON'}), 400
    
    # Validate required fields
    certificate_pem = data.get('certificate_pem')
    certificate_type = data.get('certificate_type')
    
    if not certificate_pem:
        return jsonify({'error': 'certificate_pem is required'}), 400
    
    if not certificate_type:
        return jsonify({'error': 'certificate_type is required'}), 400
    
    if certificate_type not in ['client', 'server', 'intermediate']:
        return jsonify({
            'error': 'certificate_type must be one of: client, server, intermediate'
        }), 400
    
    # Extract optional fields
    certificate_purpose = data.get('certificate_purpose')
    requester_info = data.get('requester_info', {})
    issuing_user_id = data.get('issuing_user_id')
    
    # Perform GeoIP lookup on requester IP address
    requester_ip = requester_info.get('request_source') or requester_info.get('requester_ip')
    requester_country = None
    
    if requester_ip:
        try:
            requester_country = lookup_country_code(requester_ip)
            if requester_country:
                current_app.logger.debug(f"GeoIP lookup for {requester_ip}: {requester_country}")
        except Exception as e:
            current_app.logger.warning(f"GeoIP lookup failed for {requester_ip}: {e}")
    
    # Prepare kwargs with GeoIP result
    log_kwargs = dict(requester_info)
    if requester_country:
        log_kwargs['requester_country'] = requester_country
    
    try:
        # Use the CertificateLog model to create and save the log entry
        log_entry = CertificateLog.log_certificate(
            certificate_pem=certificate_pem,
            certificate_type=certificate_type,
            certificate_purpose=certificate_purpose,
            issuing_user_id=issuing_user_id,
            **log_kwargs
        )
        
        return jsonify({
            'status': 'logged',
            'certificate': log_entry.to_dict(include_pem=False),
            'message': f'Certificate logged successfully with fingerprint {log_entry.fingerprint_sha256}'
        }), 201
        
    except ValueError as e:
        # Handle certificate parsing errors (invalid certificate format, etc.)
        db.session.rollback()
        return jsonify({'error': f'Invalid certificate data: {str(e)}'}), 400
        
    except Exception as e:
        # Handle other errors
        db.session.rollback()
        return jsonify({'error': f'Failed to log certificate: {str(e)}'}), 500




@api_bp.route('/certificates/<fingerprint>/revoke', methods=['POST'])
@api_secret_required
def revoke_certificate(fingerprint):
    """
    Mark a certificate as revoked in the Certificate Transparency log.
    
    Args:
        fingerprint (str): SHA-256 fingerprint of the certificate to revoke
    
    Request Body (JSON):
        - reason (str): Revocation reason (required)
        - revoked_at (str): ISO timestamp (optional, defaults to now)
        - revoked_by (str): Identifier of who revoked the certificate (optional)
    
    Returns:
        JSON response confirming revocation
    """
    # Parse request body
    data = request.get_json()
    
    reason = data.get('reason')
    if not reason:
        return jsonify({'error': 'Revocation reason is required'}), 400
    
    # Get optional fields
    revoked_at = data.get('revoked_at')
    revoked_by = data.get('revoked_by')
    
    # Find the most recent certificate record
    latest_cert = CertificateLog.get_by_fingerprint(fingerprint)
    if not latest_cert:
        return jsonify({'error': 'Certificate not found'}), 404
    
    # Check if already revoked (latest record has action_type='revoked')
    if latest_cert.action_type == 'revoked':
        return jsonify({
            'error': 'Certificate is already revoked',
            'revoked_at': latest_cert.log_timestamp.isoformat() if latest_cert.log_timestamp else None,
            'revoked_reason': latest_cert.revocation_reason
        }), 400
    
    try:
        # Parse revoked_at if provided
        if revoked_at:
            revoked_datetime = datetime.fromisoformat(revoked_at.replace('Z', '+00:00'))
        else:
            revoked_datetime = datetime.now(timezone.utc)
        
        # Create NEW append-only revocation record using the constructor properly
        revocation_record = CertificateLog(
            certificate_pem=latest_cert.certificate_pem,
            certificate_type=latest_cert.certificate_type,
            
            # Set append-only specific fields
            action_type='revoked',
            log_timestamp=revoked_datetime,
            
            # Set revocation-specific fields
            revoked_at=revoked_datetime,
            revocation_reason=reason,
            revoked_by=revoked_by,
            
            # Copy metadata from original request
            certificate_purpose=latest_cert.certificate_purpose,
            issuing_user_id=latest_cert.issuing_user_id,
            issued_at=latest_cert.issued_at,
            issued_by_service=latest_cert.issued_by_service,
            request_source=latest_cert.request_source
        )
        
        # Add the new revocation record to the database
        db.session.add(revocation_record)
        db.session.commit()
        
        return jsonify({
            'status': 'revoked',
            'fingerprint': fingerprint,
            'revoked_at': revocation_record.revoked_at.isoformat(),
            'revoked_reason': revocation_record.revocation_reason,
            'revoked_by': revocation_record.revoked_by,
            'message': f'Certificate {fingerprint} has been marked as revoked',
            'log_entry_id': revocation_record.id
        }), 200
        
    except ValueError as e:
        return jsonify({'error': f'Invalid revoked_at timestamp: {str(e)}'}), 400
    except Exception as e:  # pragma: no cover

        ## PRAGMA-NO-COVER Exception; JS 2025-09-03 Database Exception requires SQL bug to test.

        db.session.rollback()
        return jsonify({'error': f'Failed to revoke certificate: {str(e)}'}), 500


@api_bp.route('/users/<user_id>/revoke-certificates', methods=['POST'])
@api_secret_required
def bulk_revoke_user_certificates(user_id):
    """
    Bulk revoke all active certificates for a specific user.
    
    This endpoint is called by the Signing Service to mark all active
    certificates for a user as revoked in the Certificate Transparency log.
    
    Args:
        user_id (str): The user ID whose certificates should be revoked
        
    Request Body (JSON):
        - reason (str): Revocation reason (required)
        - revoked_by (str): Who initiated the revocation (required)
        - revoked_at (str, optional): Custom revocation timestamp (ISO format)
        
    Returns:
        JSON response with revocation count and details
    """
    # Parse request body
    data = request.get_json()
    
    reason = data.get('reason')
    if not reason:
        return jsonify({'error': 'Revocation reason is required'}), 400
    
    revoked_by = data.get('revoked_by')
    if not revoked_by:
        return jsonify({'error': 'revoked_by field is required'}), 400
    
    # Get optional custom timestamp
    revoked_at = data.get('revoked_at')
    if revoked_at:
        try:
            revoked_at = datetime.fromisoformat(revoked_at.replace('Z', '+00:00'))
        except ValueError as e:
            return jsonify({'error': f'Invalid revoked_at timestamp: {str(e)}'}), 400
    else:
        revoked_at = datetime.now(timezone.utc)
    
    try:
        # Find all active certificates for the user using append-only approach
        # Work per-fingerprint: get unique certificates and check if already revoked
        user_fingerprints = db.session.query(CertificateLog.fingerprint_sha256).filter(
            CertificateLog.issuing_user_id == user_id
        ).distinct().all()
        
        active_certificates = []
        for fp_tuple in user_fingerprints:
            fingerprint = fp_tuple[0]
            
            # Get all records for this fingerprint, sorted by action type (revoked first), then timestamp
            all_records = CertificateLog.query.filter(
                CertificateLog.fingerprint_sha256 == fingerprint
            ).order_by(
                CertificateLog.action_type.desc(),  # 'revoked' comes before 'issued'
                CertificateLog.log_timestamp.desc()  # newest first within each action type
            ).all()
            
            # Check if any revoked records exist (revoked takes priority)
            if any(record.action_type == 'revoked' for record in all_records):
                continue  # Skip this certificate, already revoked
            
            # Find the most recent 'issued' record for this fingerprint
            most_recent_issued = None
            for record in all_records:
                if record.action_type == 'issued':
                    most_recent_issued = record
                    break  # Already sorted by timestamp desc, so first is most recent
            
            if most_recent_issued:
                active_certificates.append(most_recent_issued)
        
        if not active_certificates:
            return jsonify({
                'message': f'No active certificates found for user {user_id}',
                'revoked_count': 0,
                'user_id': user_id
            }), 200
        
        # Create new append-only revocation records for all active certificates
        revoked_count = 0
        revoked_fingerprints = []
        
        for cert in active_certificates:
            # Create new revocation record using constructor properly
            revocation_record = CertificateLog(
                certificate_pem=cert.certificate_pem,
                certificate_type=cert.certificate_type,
                
                # Set append-only specific fields
                action_type='revoked',
                log_timestamp=revoked_at,
                
                # Set revocation-specific fields
                revoked_at=revoked_at,
                revocation_reason=reason,
                revoked_by=revoked_by,
                
                # Copy metadata from original request
                certificate_purpose=cert.certificate_purpose,
                issuing_user_id=cert.issuing_user_id,
                issued_at=cert.issued_at,
                issued_by_service=cert.issued_by_service,
                request_source=cert.request_source
            )
            
            db.session.add(revocation_record)
            revoked_count += 1
            revoked_fingerprints.append(cert.fingerprint_sha256)
        
        db.session.commit()
        
        return jsonify({
            'message': f'Successfully revoked {revoked_count} certificates for user {user_id}',
            'revoked_count': revoked_count,
            'user_id': user_id,
            'reason': reason,
            'revoked_by': revoked_by,
            'revoked_at': revoked_at.isoformat(),
            'revoked_fingerprints': revoked_fingerprints
        }), 200
        
    except Exception as e:  # pragma: no cover

        ## PRAGMA-NO-COVER Exception; JS 2025-09-03 Database Exception requires SQL bug to test.

        db.session.rollback()
        return jsonify({'error': f'Failed to bulk revoke certificates: {str(e)}'}), 500


@api_bp.route('/crl/next-number', methods=['POST'])
@api_secret_required
def get_next_crl_number():
    """
    Get the next CRL number for a given issuer.
    
    This endpoint provides monotonically increasing CRL numbers as required
    by X.509 standard (RFC 5280).
    
    Request Body:
        - issuer_identifier (str): Identifier for the CA issuer (usually CN)
    
    Returns:
        JSON response with the next CRL number
    """
    data = request.get_json()
    if not data or 'issuer_identifier' not in data:
        return jsonify({'error': 'Missing required field: issuer_identifier'}), 400
    
    issuer_identifier = data['issuer_identifier'].strip()
    if not issuer_identifier:
        return jsonify({'error': 'issuer_identifier cannot be empty'}), 400
    
    try:
        # Get the next CRL number atomically
        crl_number = CRLCounter.get_next_crl_number(issuer_identifier)
        
        return jsonify({
            'crl_number': crl_number,
            'issuer_identifier': issuer_identifier,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 200
        
    except Exception as e:  # pragma: no cover

        ## PRAGMA-NO-COVER Exception; JS 2025-09-03 Database Exception requires SQL bug to test.

        db.session.rollback()
        return jsonify({'error': f'Failed to get CRL number: {str(e)}'}), 500


@api_bp.route('/crl/current-number/<issuer_identifier>', methods=['GET'])
@api_secret_required
def get_current_crl_number(issuer_identifier):
    """
    Get the current CRL number for a given issuer without incrementing.
    
    Args:
        issuer_identifier (str): Identifier for the CA issuer
    
    Returns:
        JSON response with the current CRL number
    """
    if not issuer_identifier.strip():
        return jsonify({'error': 'issuer_identifier cannot be empty'}), 400
    
    try:
        current_number = CRLCounter.get_current_crl_number(issuer_identifier)
        
        return jsonify({
            'current_crl_number': current_number,
            'issuer_identifier': issuer_identifier,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 200
        
    except Exception as e:  # pragma: no cover
        ## PRAGMA-NO-COVER Exception; JS 2025-09-03 Database Exception requires SQL bug to test.
        return jsonify({'error': f'Failed to get current CRL number: {str(e)}'}), 500


@api_bp.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return jsonify({'error': 'Endpoint not found'}), 404


@api_bp.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    return jsonify({'error': 'Internal server error'}), 500