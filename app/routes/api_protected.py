from flask import Blueprint, request, jsonify
from app.middlewares.api_auth_middleware import api_token_required

api_protected_bp = Blueprint('api_protected', __name__)

# Example protected endpoints using API tokens

@api_protected_bp.route('/api/v1/me', methods=['GET'])
@api_token_required()  # No specific permissions required, just valid token
def get_api_user_info():
    """Get user info using API token"""
    from app.models import User
    
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
        "permissions": token_info.get("permissions", [])
    }
    
    return jsonify({"user": user_data}), 200

