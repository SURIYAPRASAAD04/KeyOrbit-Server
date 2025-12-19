import secrets
from datetime import datetime, timedelta
from app.models import User, PasswordReset
from app.utils.security import hash_password
from app.services.email_service import EmailService
from app.config import Config

class PasswordService:
    @staticmethod
    def generate_reset_token():
        """Generate a secure random token for password reset"""
        return secrets.token_urlsafe(32)

    @staticmethod
    def initiate_password_reset(email):
        """Initiate password reset process"""
        user = User.find_by_email(email)
        if not user:
            return False, "If this email exists in our system, you'll receive a reset link shortly"
        
        # Generate reset token
        token = PasswordService.generate_reset_token()
        expires_at = datetime.utcnow() + timedelta(hours=1)  # Token expires in 1 hour
        
        # Store reset token
        PasswordReset.create_reset_token(
            user_id=str(user["_id"]),
            token=token,
            expires_at=expires_at
        )
        
        # Send reset email
        name = f"{user['firstName']} {user['lastName']}".strip()
        EmailService.send_password_reset_email(user["email"], token, name)
        
        return True, "Password reset instructions sent to your email"

    @staticmethod
    def validate_reset_token(token):
        """Validate if reset token is valid and not expired"""
        reset_record = PasswordReset.find_by_token(token)
        if not reset_record:
            return False, "Invalid reset token"
        
        if datetime.utcnow() > reset_record["expiresAt"]:
            return False, "Reset token has expired"
        
        if reset_record.get("used", False):
            return False, "Reset token has already been used"
        
        return True, reset_record

    @staticmethod
    def reset_password(token, new_password):
        """Reset password using valid token"""
        # Validate token
        is_valid, result = PasswordService.validate_reset_token(token)
        if not is_valid:
            return False, result
        
        reset_record = result
        
        # Hash new password
        hashed_password = hash_password(new_password)
        
        # Update user password
        User.update_user(reset_record["userId"], {
            "password": hashed_password,
            "updatedAt": datetime.utcnow()
        })
        
        # Mark token as used
        PasswordReset.mark_token_used(reset_record["_id"])
        
        return True, "Password reset successfully"

    @staticmethod
    def cleanup_expired_tokens():
        """Clean up expired reset tokens (can be run as a scheduled task)"""
        expired_time = datetime.utcnow()
        return PasswordReset.collection.delete_many({
            "expiresAt": {"$lt": expired_time}
        })