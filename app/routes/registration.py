from flask import Blueprint, request, jsonify
from app.models import PendingRegistration
from datetime import datetime, timedelta
from bson import ObjectId
from app.services.email_service import EmailService
from app.utils.security import generate_verification_code
from app.models import AuditLog
import traceback

registration_bp = Blueprint('registration', __name__)

@registration_bp.route('/auth/registration/<pending_id>', methods=['GET'])
def get_pending_registration(pending_id):
    """Get pending registration details"""
    try:
        pending = PendingRegistration.collection.find_one({"_id": ObjectId(pending_id)})
        if not pending:
            return jsonify({"error": "Registration not found"}), 404
        
        # Remove sensitive data
        pending_data = {
            "id": str(pending["_id"]),
            "email": pending["email"],
            "firstName": pending.get("firstName", ""),
            "lastName": pending.get("lastName", ""),
            "createdAt": pending.get("createdAt"),
            "hasOrganizationData": "organizationData" in pending and pending["organizationData"]
        }
        
        return jsonify(pending_data), 200
        
    except Exception as e:
        print(f"Error getting pending registration: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@registration_bp.route('/auth/registration/<pending_id>/organization', methods=['POST'])
def update_registration_organization(pending_id):
    """Update pending registration with organization data"""
    try:
        data = request.get_json()
        
        # Find pending registration
        pending = PendingRegistration.collection.find_one({"_id": ObjectId(pending_id)})
        if not pending:
            return jsonify({"error": "Registration not found"}), 404
        
        # Update with organization data
        update_data = {
            "organizationData": data,
            "updatedAt": datetime.utcnow()
        }
        
        PendingRegistration.collection.update_one(
            {"_id": ObjectId(pending_id)},
            {"$set": update_data}
        )
        
        return jsonify({
            "success": True, 
            "message": "Organization details saved",
            "pendingId": pending_id
        }), 200
        
    except Exception as e:
        print(f"Error updating organization data: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@registration_bp.route('/auth/resend-verification', methods=['POST'])
def resend_verification():
    """Resend verification email - ALWAYS returns success for security"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({"error": "Request body is required"}), 400
        
        # Get IP and User-Agent for audit logging
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent')
        
        # Find pending registration
        pending = None
        
        if 'pendingId' in data:
            try:
                pending = PendingRegistration.collection.find_one({"_id": ObjectId(data['pendingId'])})
            except Exception as e:
                # Invalid ObjectId format - still return success for security
                print(f"Invalid pendingId format: {data['pendingId']}")
                AuditLog.log_auth_attempt(
                    user_id=None,
                    action_type="VERIFICATION_RESENT_FAILED",
                    ip_address=ip_address,
                    user_agent=user_agent,
                    metadata={"reason": "Invalid pendingId format"}
                )
                return jsonify({
                    "success": True,  # ALWAYS return success for security
                    "message": "If a registration exists, verification email has been sent"
                }), 200
                
        elif 'email' in data:
            pending = PendingRegistration.find_by_email(data['email'])
        
        if not pending:
            # ALWAYS return success to prevent email enumeration
            AuditLog.log_auth_attempt(
                user_id=None,
                action_type="VERIFICATION_RESENT_FAILED",
                ip_address=ip_address,
                user_agent=user_agent,
                metadata={"reason": "Pending registration not found"}
            )
            return jsonify({
                "success": True,  # ALWAYS return success for security
                "message": "If a registration exists, verification email has been sent"
            }), 200
        
        # Check if verification code is still valid (less than 25 minutes old)
        current_time = datetime.utcnow()
        code_expires = pending.get("verificationCodeExpires")
        
        if code_expires and current_time < code_expires and (code_expires - current_time).total_seconds() > 300:  # 5 minutes
            # Code is still valid, resend the same code
            verification_code = pending.get("verificationCode")
            print(f"Resending existing verification code for {pending['email']}: {verification_code}")
        else:
            # Generate new verification code
            verification_code = generate_verification_code()
            expires = datetime.utcnow() + timedelta(minutes=30)  # 30 minutes
            
            print(f"Generating new verification code for {pending['email']}: {verification_code}")
            
            # Update pending registration with new code
            PendingRegistration.collection.update_one(
                {"_id": pending["_id"]},
                {"$set": {
                    "verificationCode": verification_code,
                    "verificationCodeExpires": expires,
                    "updatedAt": datetime.utcnow()
                }}
            )
        
        # Send verification email
        name = f"{pending.get('firstName', '')} {pending.get('lastName', '')}".strip()
        email_sent = EmailService.send_verification_email(pending["email"], verification_code, name)
        
        if not email_sent:
            print(f"Failed to send email to {pending['email']}")
            # Still return success for security
            return jsonify({
                "success": True,
                "message": "If a registration exists, verification email has been sent",
                "pendingId": str(pending["_id"])
            }), 200
        
        # Log successful resend
        AuditLog.log_auth_attempt(
            user_id=None,
            action_type="VERIFICATION_RESENT",
            ip_address=ip_address,
            user_agent=user_agent,
            metadata={
                "email": pending["email"],
                "pendingId": str(pending["_id"]),
                "newCode": verification_code != pending.get("verificationCode")
            }
        )
        
        return jsonify({
            "success": True,
            "message": "Verification email sent successfully",
            "pendingId": str(pending["_id"])
        }), 200
        
    except Exception as e:
        print(f"Error resending verification: {traceback.format_exc()}")
        
        # Log error but still return success for security
        try:
            AuditLog.log_auth_attempt(
                user_id=None,
                action_type="VERIFICATION_RESENT_FAILED",
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent'),
                metadata={"error": str(e)}
            )
        except:
            pass
            
        # ALWAYS return success for security (prevents email enumeration)
        return jsonify({
            "success": True,
            "message": "If a registration exists, verification email has been sent"
        }), 200