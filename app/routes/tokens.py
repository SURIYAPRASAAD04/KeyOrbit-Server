from flask import Blueprint, request, jsonify
from app.middlewares.auth_middleware import token_required
from app.services.token_service import TokenService
from datetime import datetime
from app.utils.security import parse_expiration_date, get_current_ist_time
import re

tokens_bp = Blueprint('tokens', __name__)

@tokens_bp.route('/api-tokens', methods=['GET'])
@token_required
def get_user_tokens(current_user):
    """Get all API tokens for the current user"""
    try:
        tokens = TokenService.get_user_tokens(current_user['userId'])
        stats = TokenService.get_token_stats(current_user['userId'])
        return jsonify({
            "tokens": tokens,
            "stats": stats,
            "timestamp": datetime.utcnow().isoformat(),
            "timezone": "Asia/Kolkata (IST)",
            "serverTimeIST": get_current_ist_time().isoformat()
        }), 200
    except Exception as e:
        print(f"Error getting user tokens: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@tokens_bp.route('/api-tokens', methods=['POST'])
@token_required
def create_api_token(current_user):
    """Create a new API token"""
    try:
        data = request.get_json()
        
        # Validate required fields
        if 'name' not in data or not data['name']:
            return jsonify({"error": "Token name is required"}), 400
        
        if 'permissions' not in data or not data['permissions']:
            return jsonify({"error": "At least one permission is required"}), 400
        
        # Validate permissions
        valid_permissions = [
            'key:read', 'key:write', 'key:delete', 'key:rotate',
            'audit:read', 'admin:all', 'user:read', 'user:write',
            'policy:read', 'policy:write', 'token:read', 'token:write'
        ]
        
        for perm in data['permissions']:
            if perm not in valid_permissions:
                return jsonify({"error": f"Invalid permission: {perm}"}), 400
        
        # Validate rate limit
        if 'rateLimit' in data:
            try:
                rate_limit = int(data['rateLimit'])
                if rate_limit < 1 or rate_limit > 10000:
                    return jsonify({"error": "Rate limit must be between 1 and 10000"}), 400
            except ValueError:
                return jsonify({"error": "Rate limit must be a number"}), 400
        
        # Validate expiration date if provided
        if 'expiresAt' in data and data['expiresAt']:
            try:
                expires_at = parse_expiration_date(data['expiresAt'])
                current_ist = get_current_ist_time()
                if expires_at <= current_ist:
                    return jsonify({"error": "Expiration date must be in the future"}), 400
            except ValueError as e:
                return jsonify({"error": str(e)}), 400
        
        # Validate IP restrictions if provided
        if 'ipRestrictions' in data:
            if not isinstance(data['ipRestrictions'], list):
                return jsonify({"error": "IP restrictions must be an array"}), 400
            
            # Enhanced IP validation with CIDR support
            ipv4_pattern = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(\/(\d{1,2}))?$')
            
            for ip in data['ipRestrictions']:
                match = ipv4_pattern.match(ip)
                if not match:
                    return jsonify({"error": f"Invalid IP address format: {ip}. Use format: 192.168.1.1 or 192.168.1.0/24"}), 400
                
                # Validate IP octets
                octets = match.groups()[:4]
                for octet in octets:
                    if int(octet) > 255:
                        return jsonify({"error": f"Invalid IP address: {ip}. Octet must be between 0-255"}), 400
                
                # Validate CIDR if present
                if match.group(6):  # CIDR part
                    cidr = int(match.group(6))
                    if cidr < 0 or cidr > 32:
                        return jsonify({"error": f"Invalid CIDR: {ip}. CIDR must be between 0-32"}), 400
        
        # Create the token
        token_data = {
            "name": data['name'],
            "description": data.get('description', ''),
            "permissions": data['permissions'],
            "scopes": data.get('scopes', []),
            "rateLimit": data.get('rateLimit', 1000),
            "ipRestrictions": data.get('ipRestrictions', []),
            "expiresAt": data.get('expiresAt')
        }
        
        result = TokenService.create_api_token(current_user['userId'], token_data)
        
        return jsonify({
            "message": "API token created successfully",
            "token": result,
            "timestamp": datetime.utcnow().isoformat(),
            "timezone": "Asia/Kolkata (IST)",
            "createdAtIST": get_current_ist_time().isoformat()
        }), 201
        
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        print(f"Error creating API token: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@tokens_bp.route('/api-tokens/<token_id>', methods=['GET'])
@token_required
def get_token_details(current_user, token_id):
    """Get details of a specific API token"""
    try:
        token_details = TokenService.get_token_details(current_user['userId'], token_id)
        if not token_details:
            return jsonify({"error": "Token not found"}), 404
        
        return jsonify({
            "token": token_details,
            "timestamp": datetime.utcnow().isoformat()
        }), 200
    except Exception as e:
        print(f"Error getting token details: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@tokens_bp.route('/api-tokens/<token_id>/regenerate', methods=['POST'])
@token_required
def regenerate_token(current_user, token_id):
    """Regenerate/rotate an API token"""
    try:
        result, error = TokenService.regenerate_api_token(current_user['userId'], token_id)
        if error:
            return jsonify({"error": error}), 400
        
        return jsonify({
            "message": "Token regenerated successfully",
            "token": result,
            "timestamp": datetime.utcnow().isoformat()
        }), 200
    except Exception as e:
        print(f"Error regenerating token: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@tokens_bp.route('/api-tokens/<token_id>/revoke', methods=['POST'])
@token_required
def revoke_token(current_user, token_id):
    """Revoke an API token"""
    try:
        success, error = TokenService.revoke_api_token(current_user['userId'], token_id)
        if error:
            return jsonify({"error": error}), 400
        
        return jsonify({
            "message": "Token revoked successfully",
            "timestamp": datetime.utcnow().isoformat()
        }), 200
    except Exception as e:
        print(f"Error revoking token: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@tokens_bp.route('/api-tokens/<token_id>/permissions', methods=['PUT'])
@token_required
def update_token_permissions(current_user, token_id):
    """Update token permissions"""
    try:
        data = request.get_json()
        
        if 'permissions' not in data:
            return jsonify({"error": "Permissions are required"}), 400
        
        if not isinstance(data['permissions'], list):
            return jsonify({"error": "Permissions must be an array"}), 400
        
        # Validate permissions
        valid_permissions = [
            'key:read', 'key:write', 'key:delete', 'key:rotate',
            'audit:read', 'admin:all', 'user:read', 'user:write',
            'policy:read', 'policy:write', 'token:read', 'token:write'
        ]
        
        for perm in data['permissions']:
            if perm not in valid_permissions:
                return jsonify({"error": f"Invalid permission: {perm}"}), 400
        
        scopes = data.get('scopes')
        
        success, error = TokenService.update_token_permissions(
            current_user['userId'], token_id, data['permissions'], scopes
        )
        
        if error:
            return jsonify({"error": error}), 400
        
        return jsonify({
            "message": "Token permissions updated successfully",
            "timestamp": datetime.utcnow().isoformat()
        }), 200
    except Exception as e:
        print(f"Error updating token permissions: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@tokens_bp.route('/api-tokens/<token_id>/usage', methods=['GET'])
@token_required
def get_token_usage(current_user, token_id):
    """Get usage statistics for a token"""
    try:
        token = TokenService.get_token_details(current_user['userId'], token_id)
        if not token:
            return jsonify({"error": "Token not found"}), 404
        
        # Calculate hourly usage (simplified)
        import random
        hourly_usage = {
            "currentHour": random.randint(0, token.get("rateLimit", 1000) // 10),
            "today": token.get("apiCalls", 0),
            "last7Days": token.get("apiCalls", 0) * 2,
            "peakHour": min(token.get("apiCalls", 0), token.get("rateLimit", 1000))
        }
        
        usage_stats = {
            "totalCalls": token.get("apiCalls", 0),
            "lastUsed": token.get("lastUsed"),
            "lastUsedIp": token.get("lastUsedIp"),
            "status": token.get("status"),
            "rateLimit": token.get("rateLimit", 1000),
            "hourlyUsage": hourly_usage,
            "successRate": 99.2,  # In real app, calculate from logs
            "averageResponseTime": 145  # ms
        }
        
        return jsonify({
            "usage": usage_stats,
            "timestamp": datetime.utcnow().isoformat()
        }), 200
    except Exception as e:
        print(f"Error getting token usage: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@tokens_bp.route('/api-tokens/stats', methods=['GET'])
@token_required
def get_token_stats(current_user):
    """Get token statistics"""
    try:
        stats = TokenService.get_token_stats(current_user['userId'])
        return jsonify({
            "stats": stats,
            "timestamp": datetime.utcnow().isoformat()
        }), 200
    except Exception as e:
        print(f"Error getting token stats: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@tokens_bp.route('/api-tokens/test', methods=['POST'])
def test_token():
    """Test if an API token works (for debugging)"""
    try:
        data = request.get_json()
        
        if 'token' not in data:
            return jsonify({"error": "Token is required"}), 400
        
        token_value = data['token']
        
        # Test the token
        is_valid, message, token_info = TokenService.validate_token_access(token_value)
        
        if is_valid:
            return jsonify({
                "valid": True,
                "message": message,
                "token_info": token_info,
                "timestamp": datetime.utcnow().isoformat()
            }), 200
        else:
            return jsonify({
                "valid": False,
                "error": message,
                "timestamp": datetime.utcnow().isoformat()
            }), 401
            
    except Exception as e:
        print(f"Error testing token: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@tokens_bp.route('/api-tokens/<token_id>/realtime', methods=['GET'])
@token_required
def get_token_realtime_details(current_user, token_id):
    """Get real-time detailed information about a specific token"""
    try:
        token_details = TokenService.get_token_details(current_user['userId'], token_id)
        if not token_details:
            return jsonify({"error": "Token not found"}), 404
        
        return jsonify({
            "token": token_details,
            "timestamp": datetime.utcnow().isoformat(),
            "serverTimeIST": get_current_ist_time().isoformat(),
            "timezone": "Asia/Kolkata (IST)"
        }), 200
    except Exception as e:
        print(f"Error getting token realtime details: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500