from flask import Blueprint, request, jsonify
from app.services.password_service import PasswordService

password_bp = Blueprint('password', __name__)

@password_bp.route('/auth/forgot-password', methods=['POST'])
def forgot_password():
    """Initiate password reset process"""
    try:
        data = request.get_json()
        
        if 'email' not in data or not data['email']:
            return jsonify({"error": "Email is required"}), 400
        
        success, message = PasswordService.initiate_password_reset(data['email'])
        
        if success:
            return jsonify({"message": message}), 200
        else:
            # Still return 200 to prevent email enumeration
            return jsonify({"message": message}), 200
            
    except Exception as e:
        print(f"Forgot password error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@password_bp.route('/auth/reset-password', methods=['POST'])
def reset_password():
    """Reset password using token"""
    try:
        data = request.get_json()
        
        required_fields = ['token', 'newPassword']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({"error": f"{field} is required"}), 400
        
        # Validate password strength
        if len(data['newPassword']) < 8:
            return jsonify({"error": "Password must be at least 8 characters"}), 400
        
        success, message = PasswordService.reset_password(data['token'], data['newPassword'])
        
        if success:
            return jsonify({"message": message}), 200
        else:
            return jsonify({"error": message}), 400
            
    except Exception as e:
        print(f"Reset password error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@password_bp.route('/auth/validate-reset-token/<token>', methods=['GET'])
def validate_reset_token(token):
    """Validate if reset token is valid"""
    try:
        if not token:
            return jsonify({"error": "Token is required"}), 400
        
        is_valid, message = PasswordService.validate_reset_token(token)
        
        if is_valid:
            return jsonify({"valid": True, "message": "Token is valid"}), 200
        else:
            return jsonify({"valid": False, "error": message}), 400
            
    except Exception as e:
        print(f"Validate token error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500