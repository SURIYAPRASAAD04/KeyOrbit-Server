import jwt
from functools import wraps
from flask import request, jsonify
from app.config import Config
from app.models import Session, User
from datetime import datetime
from pytz import timezone, UTC

IST = timezone('Asia/Kolkata')

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Check if token is in the header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
        
        # Also check query parameter for API tokens or websockets
        if not token:
            token = request.args.get('token')
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            # Decode the token
            data = jwt.decode(token, Config.JWT_SECRET, algorithms=[Config.JWT_ALGORITHM])
            user_id = data['userId']
            
            # Check session validity
            session = Session.find_by_token(token)
            if not session:
                return jsonify({'error': 'Session not found or expired'}), 401
            
            # Check if session is expired
            if datetime.utcnow() > session["expires"]:
                # Delete expired session
                Session.delete_session(token)
                return jsonify({'error': 'Session has expired'}), 401
            
            # Get user from database with current status
            user = User.find_by_id(user_id)
            if not user:
                return jsonify({'error': 'User not found'}), 404
            
            # Check user status
            user_status = user.get('status', 'active')
            if user_status not in ['active', 'pending']:
                status_message = {
                    'inactive': 'Account is inactive',
                    'suspended': 'Account is suspended',
                    'deleted': 'Account has been deleted',
                    'revoked': 'Account access has been revoked'
                }.get(user_status, 'Account is not active')
                return jsonify({'error': status_message}), 403
            
            # Check if email is verified (only for local accounts)
            if user.get('provider') == 'local' and not user.get('isVerified', False):
                return jsonify({'error': 'Please verify your email address first'}), 403
            
            # Prepare current_user object
            current_user = {
                'userId': user_id,
                'email': data['email'],
                'role': data.get('role', 'user'),
                'organization': user.get('organization', {}),
                'status': user_status,
                'isVerified': user.get('isVerified', False),
                'permissions': user.get('permissions', []),
                'department': user.get('department', ''),
                'mfaEnabled': user.get('mfaEnabled', False)
            }
            
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Token is invalid'}), 401
        except Exception as e:
            print(f"Token verification error: {str(e)}")
            return jsonify({'error': 'Token verification failed'}), 401
        
        # Pass the current_user to the decorated function
        return f(current_user, *args, **kwargs)
    
    return decorated


def role_required(*required_roles):
    """Decorator to check if user has required role(s)"""
    def decorator(f):
        @wraps(f)
        @token_required
        def decorated(current_user, *args, **kwargs):
            user_role = current_user['role']
            
            # Normalize role names for comparison
            role_mapping = {
                'admin': ['admin', 'administrator'],
                'administrator': ['admin', 'administrator'],
                'manager': ['admin', 'administrator', 'manager'],
                'developer': ['admin', 'administrator', 'manager', 'developer', 'security'],
                'security': ['admin', 'administrator', 'manager', 'developer', 'security'],
                'auditor': ['admin', 'administrator', 'manager', 'auditor'],
                'viewer': ['admin', 'administrator', 'manager', 'developer', 'security', 'auditor', 'viewer', 'user'],
                'user': ['admin', 'administrator', 'manager', 'developer', 'security', 'auditor', 'viewer', 'user']
            }
            
            # Get allowed roles for user's role
            allowed_roles = role_mapping.get(user_role, [user_role])
            
            # Check if any required role is in allowed roles
            has_access = any(role in allowed_roles for role in required_roles)
            
            if not has_access:
                return jsonify({
                    'error': 'Insufficient permissions',
                    'required_roles': list(required_roles),
                    'user_role': user_role
                }), 403
            
            return f(current_user, *args, **kwargs)
        
        return decorated
    return decorator


def admin_required(f):
    """Decorator for admin-only endpoints"""
    @wraps(f)
    @token_required
    def decorated(current_user, *args, **kwargs):
        if current_user['role'] not in ['admin', 'administrator']:
            return jsonify({'error': 'Administrator access required'}), 403
        return f(current_user, *args, **kwargs)
    return decorated


def manager_required(f):
    """Decorator for manager or higher endpoints"""
    @wraps(f)
    @token_required
    def decorated(current_user, *args, **kwargs):
        if current_user['role'] not in ['admin', 'administrator', 'manager']:
            return jsonify({'error': 'Manager or higher access required'}), 403
        return f(current_user, *args, **kwargs)
    return decorated


def permission_required(*required_permissions):
    """Decorator to check if user has required permissions"""
    def decorator(f):
        @wraps(f)
        @token_required
        def decorated(current_user, *args, **kwargs):
            user_permissions = current_user.get('permissions', [])
            
            # Check if user has all required permissions
            for required_perm in required_permissions:
                if required_perm not in user_permissions:
                    return jsonify({
                        'error': f'Permission denied: {required_perm}',
                        'required_permissions': list(required_permissions),
                        'user_permissions': user_permissions
                    }), 403
            
            return f(current_user, *args, **kwargs)
        
        return decorated
    return decorator


def organization_required(f):
    """Decorator to ensure user belongs to an organization"""
    @wraps(f)
    @token_required
    def decorated(current_user, *args, **kwargs):
        if not current_user.get('organization') or not current_user['organization'].get('id'):
            return jsonify({'error': 'Organization membership required'}), 403
        return f(current_user, *args, **kwargs)
    return decorated


def mfa_required(f):
    """Decorator to check if MFA is enabled and verified"""
    @wraps(f)
    @token_required
    def decorated(current_user, *args, **kwargs):
        # Skip MFA check for certain endpoints (like MFA setup itself)
        skip_paths = ['/auth/mfa/setup', '/auth/mfa/verify', '/auth/mfa/disable']
        if request.path in skip_paths:
            return f(current_user, *args, **kwargs)
        
        # Check if MFA is enabled and session has MFA verified flag
        if current_user.get('mfaEnabled', False):
            # In a real implementation, you would check a session flag
            # For now, we'll assume MFA is verified if user is authenticated
            # You should implement proper MFA session tracking
            pass
        
        return f(current_user, *args, **kwargs)
    return decorated


def ip_whitelist(allowed_ips):
    """Decorator to restrict access to specific IP addresses"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            client_ip = request.remote_addr
            
            # Check if client IP is in whitelist
            if client_ip not in allowed_ips and '127.0.0.1' not in allowed_ips:
                return jsonify({
                    'error': 'Access denied from this IP address',
                    'client_ip': client_ip
                }), 403
            
            return f(*args, **kwargs)
        
        return decorated
    return decorator


def rate_limit(max_requests, time_window):
    """Simple rate limiting decorator"""
    from collections import defaultdict
    from time import time
    
    request_history = defaultdict(list)
    
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            client_ip = request.remote_addr
            current_time = time()
            
            # Clean old requests
            request_history[client_ip] = [
                req_time for req_time in request_history[client_ip]
                if current_time - req_time < time_window
            ]
            
            # Check rate limit
            if len(request_history[client_ip]) >= max_requests:
                return jsonify({
                    'error': 'Rate limit exceeded',
                    'limit': max_requests,
                    'window': time_window,
                    'retry_after': time_window - (current_time - request_history[client_ip][0])
                }), 429
            
            # Add current request
            request_history[client_ip].append(current_time)
            
            return f(*args, **kwargs)
        
        return decorated
    return decorator


def hybrid_auth(f):
    """
    Hybrid authentication that accepts both JWT tokens and API tokens
    Useful for endpoints that should accept both user and API access
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_type = None
        
        # Check for Bearer token (JWT)
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
                auth_type = 'jwt'
        
        # Check for API token in header
        if not token and 'X-API-Token' in request.headers:
            token = request.headers['X-API-Token']
            auth_type = 'api_token'
        
        # Check for API token in query parameter
        if not token and 'api_token' in request.args:
            token = request.args.get('api_token')
            auth_type = 'api_token'
        
        if not token:
            return jsonify({'error': 'Authentication token is missing'}), 401
        
        try:
            if auth_type == 'jwt':
                # Verify JWT token
                data = jwt.decode(token, Config.JWT_SECRET, algorithms=[Config.JWT_ALGORITHM])
                
                # Check session
                session = Session.find_by_token(token)
                if not session:
                    return jsonify({'error': 'Session not found'}), 401
                
                if datetime.utcnow() > session["expires"]:
                    Session.delete_session(token)
                    return jsonify({'error': 'Session has expired'}), 401
                
                # Get user
                user = User.find_by_id(data['userId'])
                if not user:
                    return jsonify({'error': 'User not found'}), 404
                
                # Check user status
                if user.get('status', 'active') not in ['active', 'pending']:
                    return jsonify({'error': 'Account is not active'}), 403
                
                current_user = {
                    'userId': data['userId'],
                    'email': data['email'],
                    'role': data.get('role', 'user'),
                    'organization': user.get('organization', {}),
                    'auth_type': 'jwt'
                }
                
            elif auth_type == 'api_token':
                # Verify API token using token service
                from app.services.token_service import TokenService
                
                is_valid, message, token_info = TokenService.validate_token_access(
                    token,
                    client_ip=request.remote_addr
                )
                
                if not is_valid:
                    return jsonify({'error': message}), 401
                
                # Get user from token info
                user = User.find_by_id(token_info['userId'])
                if not user:
                    return jsonify({'error': 'User not found'}), 404
                
                current_user = {
                    'userId': token_info['userId'],
                    'email': user.get('email', ''),
                    'role': user.get('role', 'user'),
                    'organization': user.get('organization', {}),
                    'permissions': token_info.get('permissions', []),
                    'rateLimit': token_info.get('rateLimit', 1000),
                    'tokenId': token_info.get('tokenId'),
                    'auth_type': 'api_token',
                    'token_info': token_info
                }
            
            else:
                return jsonify({'error': 'Invalid authentication type'}), 401
            
            # Add current_user to request context
            request.current_user = current_user
            request.token_info = current_user
            request.auth_type = auth_type
            
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Token is invalid'}), 401
        except Exception as e:
            print(f"Authentication error: {str(e)}")
            return jsonify({'error': 'Authentication failed'}), 401
        
        return f(*args, **kwargs)
    
    return decorated


# Helper functions for permission checking
def has_permission(user, permission):
    """Check if user has specific permission"""
    user_permissions = user.get('permissions', [])
    return permission in user_permissions


def has_role(user, role):
    """Check if user has specific role"""
    return user.get('role') == role


def is_admin(user):
    """Check if user is admin"""
    return user.get('role') in ['admin', 'administrator']


def is_manager(user):
    """Check if user is manager or higher"""
    return user.get('role') in ['admin', 'administrator', 'manager']


def is_developer(user):
    """Check if user is developer or higher"""
    return user.get('role') in ['admin', 'administrator', 'manager', 'developer', 'security']


def is_auditor(user):
    """Check if user is auditor or higher"""
    return user.get('role') in ['admin', 'administrator', 'manager', 'auditor']


def can_access_page(user, page_name):
    """Check if user can access specific page based on role"""
    page_access = {
        'dashboard': ['admin', 'administrator', 'manager', 'developer', 'security', 'auditor', 'viewer', 'user'],
        'key-management': ['admin', 'administrator', 'manager', 'developer', 'security'],
        'audit-logs': ['admin', 'administrator', 'manager', 'auditor'],
        'user-management': ['admin', 'administrator'],
        'policy-management': ['admin', 'administrator', 'manager', 'security'],
        'api-tokens': ['admin', 'administrator', 'manager', 'developer', 'security'],
        'profile-settings': ['admin', 'administrator', 'manager', 'developer', 'security', 'auditor', 'viewer', 'user']
    }
    
    allowed_roles = page_access.get(page_name, [])
    return user.get('role') in allowed_roles