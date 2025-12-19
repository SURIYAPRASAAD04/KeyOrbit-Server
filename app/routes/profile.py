from flask import Blueprint, request, jsonify
from app.middlewares.auth_middleware import token_required

profile_bp = Blueprint('profile', __name__)

@profile_bp.route('/auth/profile', methods=['GET'])
@token_required
def get_profile(current_user):
    try:
        from app.models import User
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