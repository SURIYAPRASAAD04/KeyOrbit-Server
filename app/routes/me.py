from flask import Blueprint, request, jsonify
from app.middlewares.auth_middleware import token_required
from app.middlewares.api_auth_middleware import hybrid_auth, api_token_required
from app.models import User

me_bp = Blueprint('me', __name__)

@me_bp.route('/me', methods=['GET'])
@hybrid_auth
def get_current_user_hybrid():
    """Get current user information (accepts both JWT and API tokens)"""
    try:
        token_info = request.token_info
        auth_type = getattr(request, 'auth_type', 'unknown')
        
        user_id = token_info.get('userId')
        if not user_id:
            return jsonify({"error": "User ID not found in token"}), 401
        
        user = User.find_by_id(user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        user_data = {
            "id": str(user["_id"]),
            "firstName": user["firstName"],
            "lastName": user["lastName"],
            "email": user["email"],
            "role": user.get("role", "user"),
            "organization": user.get("organization", {}),
            "isVerified": user.get("isVerified", False),
            "authType": auth_type
        }
        
        # Add permissions if it's an API token
        if auth_type == 'api_token':
            user_data["permissions"] = token_info.get("permissions", [])
            user_data["rateLimit"] = token_info.get("rateLimit", 1000)
        
        return jsonify({"user": user_data}), 200
        
    except Exception as e:
        print(f"Error in get_current_user_hybrid: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@me_bp.route('/api/me', methods=['GET'])
@api_token_required()
def get_api_user_info():
    """Get user info using API token only"""
    try:
        token_info = request.token_info
        user_id = token_info.get('userId')
        
        user = User.find_by_id(user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        user_data = {
            "id": str(user["_id"]),
            "firstName": user["firstName"],
            "lastName": user["lastName"],
            "email": user["email"],
            "role": user.get("role", "user"),
            "organization": user.get("organization", {}),
            "permissions": token_info.get("permissions", []),
            "rateLimit": token_info.get("rateLimit", 1000),
            "tokenId": token_info.get("tokenId")
        }
        
        return jsonify({"user": user_data}), 200
        
    except Exception as e:
        print(f"Error in get_api_user_info: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@me_bp.route('/auth/profile', methods=['GET'])
@token_required
def get_profile(current_user):
    """Get current user information (JWT only - for backward compatibility)"""
    try:
        user = User.find_by_id(current_user['userId'])
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        user_data = {
            "id": str(user["_id"]),
            "firstName": user["firstName"],
            "lastName": user["lastName"],
            "email": user["email"],
            "role": user.get("role", "user"),
            "organization": user.get("organization", {}),
            "isVerified": user.get("isVerified", False)
        }
        
        return jsonify({"user": user_data}), 200
        
    except Exception as e:
        print(f"Error in get_profile: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@me_bp.route('/me/api-tokens', methods=['GET'])
@token_required
def get_my_tokens(current_user):
    """Get current user's API tokens (JWT only)"""
    try:
        from app.services.token_service import TokenService
        tokens = TokenService.get_user_tokens(current_user['userId'])
        return jsonify({"tokens": tokens}), 200
    except Exception as e:
        print(f"Error getting user tokens: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500