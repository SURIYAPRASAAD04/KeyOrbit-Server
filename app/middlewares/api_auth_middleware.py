from flask import request, jsonify
from app.services.token_service import TokenService
from app.utils.security import verify_jwt
import functools

def api_token_required(required_permissions=None, required_scopes=None):
    """
    Decorator to validate API tokens and check permissions/scopes
    Usage: @api_token_required(required_permissions=['key:read'])
    """
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            # Get token from Authorization header
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return jsonify({
                    "error": "Missing or invalid authorization header",
                    "message": "Authorization header must be: Bearer <token>"
                }), 401
            
            token = auth_header[7:]  # Remove 'Bearer ' prefix
            
            # Get client IP
            client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
            if ',' in client_ip:
                client_ip = client_ip.split(',')[0].strip()
            
            # Validate token and check permissions
            is_valid, message, token_info = TokenService.validate_token_access(
                token, required_permissions, required_scopes, client_ip
            )
            
            if not is_valid:
                # Return specific error message for different cases
                error_code = "INVALID_TOKEN"
                if "expired" in message.lower():
                    error_code = "TOKEN_EXPIRED"
                elif "ip address" in message.lower():
                    error_code = "IP_RESTRICTED"
                elif "permissions" in message.lower():
                    error_code = "INSUFFICIENT_PERMISSIONS"
                
                return jsonify({
                    "error": "Authentication failed",
                    "message": message,
                    "code": error_code
                }), 401
            
            # Add token info to request context
            request.token_info = token_info
            request.auth_type = 'api_token'
            request.client_ip = client_ip
            
            return f(*args, **kwargs)
        return wrapper
    return decorator

def hybrid_auth(f):
    """
    Hybrid authentication that accepts either JWT or API token
    """
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "Missing authorization header"}), 401
        
        token = auth_header[7:]
        
        # Get client IP for API token validation
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ',' in client_ip:
            client_ip = client_ip.split(',')[0].strip()
        
        # Try API token first
        is_valid, message, token_info = TokenService.validate_token_access(
            token, None, None, client_ip
        )
        
        if is_valid:
            # It's an API token
            request.token_info = token_info
            request.auth_type = 'api_token'
            request.client_ip = client_ip
            return f(*args, **kwargs)
        
        # If not API token, try JWT
        jwt_payload = verify_jwt(token)
        
        if jwt_payload:
            # It's a JWT
            request.token_info = jwt_payload
            request.auth_type = 'jwt'
            return f(*args, **kwargs)
        
        # Neither worked
        return jsonify({
            "error": "Invalid token",
            "message": "Token is not a valid JWT or API token",
            "code": "INVALID_TOKEN"
        }), 401
    
    return wrapper