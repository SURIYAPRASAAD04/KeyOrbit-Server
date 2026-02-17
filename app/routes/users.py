from flask import Blueprint, request, jsonify
from app.middlewares.auth_middleware import token_required
from app.services.user_service import UserService
from app.services.email_service import EmailService
from app.models import AuditLog
from datetime import datetime
from bson import ObjectId
import re

users_bp = Blueprint('users', __name__)

@users_bp.route('/users', methods=['GET'])
@token_required
def get_users(current_user):
    """Get all users in the organization (admin only)"""
    try:
        # Check if user is admin
        if current_user['role'] not in ['admin', 'administrator']:
            return jsonify({"error": "Insufficient permissions"}), 403
        
        organization_id = current_user.get('organization', {}).get('id')
        if not organization_id:
            return jsonify({"error": "Organization not found"}), 404
        
        users = UserService.get_organization_users(organization_id)
        
        return jsonify({
            "users": users,
            "count": len(users),
            "organization": current_user.get('organization', {})
        }), 200
        
    except Exception as e:
        print(f"Error getting users: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@users_bp.route('/users/invite', methods=['POST'])
@token_required
def invite_user(current_user):
    """Invite a new user to the organization"""
    try:
        print(f"=== INVITE USER START ===")
        print(f"Current user: {current_user}")
        
        # Check if user is admin or manager
        if current_user['role'] not in ['admin', 'administrator', 'manager']:
            print(f"Permission denied for role: {current_user['role']}")
            return jsonify({"error": "Insufficient permissions"}), 403
        
        data = request.get_json()
        print(f"Request data: {data}")
        
        if not data:
            print("No data received")
            return jsonify({"error": "No data provided"}), 400
        
        # Validate required fields
        required_fields = ['email', 'role']
        for field in required_fields:
            if field not in data or not data[field]:
                print(f"Missing required field: {field}")
                return jsonify({"error": f"{field} is required"}), 400
        
        # Validate email format
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_regex, data['email']):
            print(f"Invalid email format: {data['email']}")
            return jsonify({"error": "Invalid email format"}), 400
        
        # Normalize role to lowercase for validation
        role_lower = data['role'].lower()
        
        # Validate role - accept both capitalized and lowercase
        valid_roles = ['admin', 'administrator', 'manager', 'developer', 'auditor', 'viewer', 'user']
        valid_roles_display = ['Admin', 'Administrator', 'Manager', 'Developer', 'Auditor', 'Viewer', 'User']
        
        if role_lower not in valid_roles:
            print(f"Invalid role: {data['role']}")
            return jsonify({
                "error": f"Invalid role. Valid roles: {', '.join(valid_roles_display)}",
                "valid_roles": valid_roles_display
            }), 400
        
        organization_id = current_user.get('organization', {}).get('id')
        print(f"Organization ID: {organization_id}")
        
        if not organization_id:
            print("No organization ID found")
            return jsonify({"error": "Organization not found"}), 404
        
        # Check if user already exists in organization
        existing_user = UserService.find_user_by_email_and_org(data['email'], organization_id)
        if existing_user:
            print(f"User already exists in organization: {data['email']}")
            return jsonify({"error": "User already exists in this organization"}), 400
        
        # Create invitation - use lowercase role for storage
        invitation, error = UserService.create_invitation(
            inviter_id=current_user['userId'],
            email=data['email'],
            role=role_lower,
            organization_id=organization_id,
            department=data.get('department', ''),
            name=data.get('name', ''),
            phone=data.get('phone', ''),
            permissions=data.get('permissions', []),
            message=data.get('message', '')
        )
        
        if error:
            print(f"Error creating invitation: {error}")
            return jsonify({"error": error}), 400
        
        print(f"Invitation created: {invitation}")
        
        # Log the invitation
        AuditLog.log_auth_attempt(
            user_id=current_user['userId'],
            action_type="USER_INVITED",
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            metadata={
                "invited_email": data['email'],
                "role": data['role'],
                "normalized_role": role_lower,
                "invitation_id": str(invitation['_id'])
            }
        )
        
        print("=== INVITE USER SUCCESS ===")
        
        return jsonify({
            "message": "Invitation sent successfully",
            "invitation": {
                "id": str(invitation['_id']),
                "email": invitation['email'],
                "role": data['role'],
                "normalized_role": role_lower,
                "status": invitation['status'],
                "expiresAt": invitation['expiresAt'].isoformat() if invitation.get('expiresAt') else None,
                "invitedBy": str(invitation['invitedBy']),
                "invitedAt": invitation['invitedAt'].isoformat()
            }
        }), 201
        
    except Exception as e:
        print(f"=== INVITE USER ERROR ===")
        print(f"Error: {str(e)}")
        import traceback
        traceback.print_exc()
        print(f"=== END ERROR ===")
        return jsonify({"error": "Internal server error"}), 500
        
@users_bp.route('/users/<user_id>', methods=['GET'])
@token_required
def get_user_details(current_user, user_id):
    """Get details of a specific user"""
    try:
        organization_id = current_user.get('organization', {}).get('id')
        if not organization_id:
            return jsonify({"error": "Organization not found"}), 404
        
        # Users can view their own details, admins can view anyone
        if current_user['userId'] != user_id and current_user['role'] not in ['admin', 'administrator', 'manager']:
            return jsonify({"error": "Insufficient permissions"}), 403
        
        user = UserService.get_user_details(user_id, organization_id)
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Include activity logs for admins/managers
        if current_user['role'] in ['admin', 'administrator', 'manager']:
            activity_logs = UserService.get_user_activity(user_id, limit=10)
            user['activityLogs'] = activity_logs
        
        return jsonify({"user": user}), 200
        
    except Exception as e:
        print(f"Error getting user details: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@users_bp.route('/users/<user_id>', methods=['PUT'])
@token_required
def update_user(current_user, user_id):
    """Update user information"""
    try:
        # Check if user is admin/manager or updating their own profile
        if current_user['userId'] != user_id and current_user['role'] not in ['admin', 'administrator', 'manager']:
            return jsonify({"error": "Insufficient permissions"}), 403
        
        data = request.get_json()
        
        organization_id = current_user.get('organization', {}).get('id')
        if not organization_id:
            return jsonify({"error": "Organization not found"}), 404
        
        # Prepare updates
        updates = {}
        
        # Anyone can update their own profile info
        if 'name' in data:
            updates['name'] = data['name']
        if 'phone' in data:
            updates['phone'] = data['phone']
        if 'department' in data:
            updates['department'] = data['department']
        
        # Only admins can update role and status
        if current_user['role'] in ['admin', 'administrator']:
            if 'role' in data:
                valid_roles = ['admin', 'administrator', 'manager', 'developer', 'auditor', 'viewer', 'user']
                role_lower = data['role'].lower()
                if role_lower not in valid_roles:
                    return jsonify({"error": f"Invalid role. Valid roles: {', '.join(valid_roles)}"}), 400
                updates['role'] = role_lower
            
            if 'status' in data:
                valid_statuses = ['active', 'inactive', 'suspended', 'pending']
                status_lower = data['status'].lower()
                if status_lower not in valid_statuses:
                    return jsonify({"error": f"Invalid status. Valid statuses: {', '.join(valid_statuses)}"}), 400
                updates['status'] = status_lower
        
        # If user is updating their own profile and not admin, only allow basic updates
        if current_user['userId'] == user_id and current_user['role'] not in ['admin', 'administrator']:
            # Remove role and status updates if present
            updates.pop('role', None)
            updates.pop('status', None)
        
        # If no updates, return early
        if not updates:
            return jsonify({"error": "No valid updates provided"}), 400
        
        success, error = UserService.update_user(user_id, organization_id, updates)
        if not success:
            return jsonify({"error": error}), 400
        
        # Log the update
        AuditLog.log_auth_attempt(
            user_id=current_user['userId'],
            action_type="USER_UPDATED",
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            metadata={
                "updated_user_id": user_id,
                "updates": updates
            }
        )
        
        # Get updated user
        updated_user = UserService.get_user_details(user_id, organization_id)
        
        return jsonify({
            "message": "User updated successfully",
            "user": updated_user,
            "updates": updates
        }), 200
        
    except Exception as e:
        print(f"Error updating user: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@users_bp.route('/users/<user_id>/status', methods=['POST'])
@token_required
def update_user_status(current_user, user_id):
    """Update user status (activate, deactivate, suspend)"""
    try:
        # Only admins can update user status
        if current_user['role'] not in ['admin', 'administrator']:
            return jsonify({"error": "Insufficient permissions"}), 403
        
        data = request.get_json()
        if 'status' not in data:
            return jsonify({"error": "Status is required"}), 400
        
        valid_statuses = ['active', 'inactive', 'suspended', 'pending']
        status_lower = data['status'].lower()
        if status_lower not in valid_statuses:
            return jsonify({"error": f"Invalid status. Valid statuses: {', '.join(valid_statuses)}"}), 400
        
        # Prevent self-suspension
        if current_user['userId'] == user_id and status_lower == 'suspended':
            return jsonify({"error": "Cannot suspend your own account"}), 400
        
        organization_id = current_user.get('organization', {}).get('id')
        if not organization_id:
            return jsonify({"error": "Organization not found"}), 404
        
        success, error = UserService.update_user_status(user_id, organization_id, status_lower)
        if not success:
            return jsonify({"error": error}), 400
        
        # Log the status change
        AuditLog.log_auth_attempt(
            user_id=current_user['userId'],
            action_type="USER_STATUS_CHANGED",
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            metadata={
                "user_id": user_id,
                "new_status": status_lower
            }
        )
        
        return jsonify({
            "message": f"User status updated to {status_lower}",
            "status": status_lower
        }), 200
        
    except Exception as e:
        print(f"Error updating user status: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@users_bp.route('/users/<user_id>/role', methods=['POST'])
@token_required
def update_user_role(current_user, user_id):
    """Update user role"""
    try:
        # Only admins can update user role
        if current_user['role'] not in ['admin', 'administrator']:
            return jsonify({"error": "Insufficient permissions"}), 403
        
        data = request.get_json()
        if 'role' not in data:
            return jsonify({"error": "Role is required"}), 400
        
        valid_roles = ['admin', 'administrator', 'manager', 'developer', 'auditor', 'viewer', 'user']
        role_lower = data['role'].lower()
        if role_lower not in valid_roles:
            return jsonify({"error": f"Invalid role. Valid roles: {', '.join(valid_roles)}"}), 400
        
        organization_id = current_user.get('organization', {}).get('id')
        if not organization_id:
            return jsonify({"error": "Organization not found"}), 404
        
        success, error = UserService.update_user_role(user_id, organization_id, role_lower)
        if not success:
            return jsonify({"error": error}), 400
        
        # Log the role change
        AuditLog.log_auth_attempt(
            user_id=current_user['userId'],
            action_type="USER_ROLE_CHANGED",
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            metadata={
                "user_id": user_id,
                "new_role": role_lower
            }
        )
        
        return jsonify({
            "message": f"User role updated to {role_lower}",
            "role": role_lower
        }), 200
        
    except Exception as e:
        print(f"Error updating user role: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@users_bp.route('/users/<user_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, user_id):
    """Delete a user from the organization"""
    try:
        # Only admins can delete users
        if current_user['role'] not in ['admin', 'administrator']:
            return jsonify({"error": "Insufficient permissions"}), 403
        
        # Prevent self-deletion
        if current_user['userId'] == user_id:
            return jsonify({"error": "Cannot delete your own account"}), 400
        
        organization_id = current_user.get('organization', {}).get('id')
        if not organization_id:
            return jsonify({"error": "Organization not found"}), 404
        
        success, error = UserService.delete_user(user_id, organization_id)
        if not success:
            return jsonify({"error": error}), 400
        
        # Log the deletion
        AuditLog.log_auth_attempt(
            user_id=current_user['userId'],
            action_type="USER_DELETED",
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            metadata={
                "deleted_user_id": user_id
            }
        )
        
        return jsonify({
            "message": "User deleted successfully"
        }), 200
        
    except Exception as e:
        print(f"Error deleting user: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@users_bp.route('/users/bulk/actions', methods=['POST'])
@token_required
def bulk_user_actions(current_user):
    """Perform bulk actions on users"""
    try:
        # Only admins/managers can perform bulk actions
        if current_user['role'] not in ['admin', 'administrator', 'manager']:
            return jsonify({"error": "Insufficient permissions"}), 403
        
        data = request.get_json()
        
        if 'userIds' not in data or not data['userIds']:
            return jsonify({"error": "User IDs are required"}), 400
        
        if 'action' not in data:
            return jsonify({"error": "Action is required"}), 400
        
        valid_actions = ['activate', 'deactivate', 'suspend', 'changeRole', 'changeDepartment', 'delete']
        if data['action'] not in valid_actions:
            return jsonify({"error": f"Invalid action. Valid actions: {', '.join(valid_actions)}"}), 400
        
        organization_id = current_user.get('organization', {}).get('id')
        if not organization_id:
            return jsonify({"error": "Organization not found"}), 404
        
        # Handle specific actions
        result = None
        if data['action'] in ['activate', 'deactivate', 'suspend']:
            status_map = {
                'activate': 'active',
                'deactivate': 'inactive',
                'suspend': 'suspended'
            }
            result = UserService.bulk_update_status(
                data['userIds'], 
                organization_id, 
                status_map[data['action']]
            )
        
        elif data['action'] == 'changeRole' and 'role' in data:
            # Validate role
            valid_roles = ['admin', 'administrator', 'manager', 'developer', 'auditor', 'viewer', 'user']
            role_lower = data['role'].lower()
            if role_lower not in valid_roles:
                return jsonify({"error": f"Invalid role. Valid roles: {', '.join(valid_roles)}"}), 400
            
            result = UserService.bulk_update_role(
                data['userIds'], 
                organization_id, 
                role_lower
            )
        
        elif data['action'] == 'changeDepartment' and 'department' in data:
            result = UserService.bulk_update_department(
                data['userIds'], 
                organization_id, 
                data['department']
            )
        
        elif data['action'] == 'delete':
            result = UserService.bulk_delete_users(
                data['userIds'], 
                organization_id
            )
        
        if not result or not result.get('success', False):
            return jsonify({"error": result.get('error', 'Action failed')}), 400
        
        # Log bulk action
        AuditLog.log_auth_attempt(
            user_id=current_user['userId'],
            action_type=f"BULK_{data['action'].upper()}",
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            metadata={
                "user_ids": data['userIds'],
                "action": data['action'],
                "affected_count": result.get('affected_count', 0)
            }
        )
        
        return jsonify({
            "message": f"Bulk action '{data['action']}' completed successfully",
            "affected_count": result.get('affected_count', 0)
        }), 200
        
    except Exception as e:
        print(f"Error performing bulk action: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@users_bp.route('/invitations', methods=['GET'])
@token_required
def get_invitations(current_user):
    """Get all pending invitations for the organization"""
    try:
        # Only admins/managers can view invitations
        if current_user['role'] not in ['admin', 'administrator', 'manager']:
            return jsonify({"error": "Insufficient permissions"}), 403
        
        organization_id = current_user.get('organization', {}).get('id')
        if not organization_id:
            return jsonify({"error": "Organization not found"}), 404
        
        invitations = UserService.get_pending_invitations(organization_id)
        
        return jsonify({
            "invitations": invitations,
            "count": len(invitations)
        }), 200
        
    except Exception as e:
        print(f"Error getting invitations: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@users_bp.route('/invitations/<invitation_id>/resend', methods=['POST'])
@token_required
def resend_invitation(current_user, invitation_id):
    """Resend an invitation"""
    try:
        # Only admins/managers can resend invitations
        if current_user['role'] not in ['admin', 'administrator', 'manager']:
            return jsonify({"error": "Insufficient permissions"}), 403
        
        organization_id = current_user.get('organization', {}).get('id')
        if not organization_id:
            return jsonify({"error": "Organization not found"}), 404
        
        success, error = UserService.resend_invitation(invitation_id, organization_id)
        if not success:
            return jsonify({"error": error}), 400
        
        return jsonify({
            "message": "Invitation resent successfully"
        }), 200
        
    except Exception as e:
        print(f"Error resending invitation: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@users_bp.route('/invitations/<invitation_id>/cancel', methods=['POST'])
@token_required
def cancel_invitation(current_user, invitation_id):
    """Cancel an invitation"""
    try:
        # Only admins/managers can cancel invitations
        if current_user['role'] not in ['admin', 'administrator', 'manager']:
            return jsonify({"error": "Insufficient permissions"}), 403
        
        organization_id = current_user.get('organization', {}).get('id')
        if not organization_id:
            return jsonify({"error": "Organization not found"}), 404
        
        success, error = UserService.cancel_invitation(invitation_id, organization_id)
        if not success:
            return jsonify({"error": error}), 400
        
        return jsonify({
            "message": "Invitation cancelled successfully"
        }), 200
        
    except Exception as e:
        print(f"Error cancelling invitation: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@users_bp.route('/users/<user_id>/reset-password', methods=['POST'])
@token_required
def admin_reset_password(current_user, user_id):
    """Admin-initiated password reset for a user"""
    try:
        # Only admins/managers can reset passwords
        if current_user['role'] not in ['admin', 'administrator', 'manager']:
            return jsonify({"error": "Insufficient permissions"}), 403
        
        organization_id = current_user.get('organization', {}).get('id')
        if not organization_id:
            return jsonify({"error": "Organization not found"}), 404
        
        success, error = UserService.admin_reset_password(user_id, organization_id)
        if not success:
            return jsonify({"error": error}), 400
        
        # Log the password reset
        AuditLog.log_auth_attempt(
            user_id=current_user['userId'],
            action_type="ADMIN_PASSWORD_RESET",
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            metadata={
                "reset_user_id": user_id
            }
        )
        
        return jsonify({
            "message": "Password reset email sent successfully"
        }), 200
        
    except Exception as e:
        print(f"Error resetting password: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@users_bp.route('/users/stats', methods=['GET'])
@token_required
def get_user_stats(current_user):
    """Get user statistics for the organization"""
    try:
        # Only admins/managers can view stats
        if current_user['role'] not in ['admin', 'administrator', 'manager']:
            return jsonify({"error": "Insufficient permissions"}), 403
        
        organization_id = current_user.get('organization', {}).get('id')
        if not organization_id:
            return jsonify({"error": "Organization not found"}), 404
        
        stats = UserService.get_organization_stats(organization_id)
        
        return jsonify({
            "stats": stats,
            "organization": current_user.get('organization', {})
        }), 200
        
    except Exception as e:
        print(f"Error getting user stats: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

# Add bulk password reset endpoint
@users_bp.route('/users/bulk/reset-passwords', methods=['POST'])
@token_required
def bulk_reset_passwords(current_user):
    """Bulk reset passwords for selected users"""
    try:
        # Only admins/managers can reset passwords
        if current_user['role'] not in ['admin', 'administrator', 'manager']:
            return jsonify({"error": "Insufficient permissions"}), 403
        
        data = request.get_json()
        
        if 'userIds' not in data or not data['userIds']:
            return jsonify({"error": "User IDs are required"}), 400
        
        organization_id = current_user.get('organization', {}).get('id')
        if not organization_id:
            return jsonify({"error": "Organization not found"}), 404
        
        # Import PasswordService
        from app.services.password_service import PasswordService
        
        success_count = 0
        failed_users = []
        
        for user_id in data['userIds']:
            # Get user to check if exists and is active
            user = UserService.get_user_details(user_id, organization_id)
            if not user:
                failed_users.append({"id": user_id, "error": "User not found"})
                continue
            
            if user['status'] not in ['active', 'pending']:
                failed_users.append({"id": user_id, "error": f"User is {user['status']}"})
                continue
            
            # Send password reset email
            success, message = PasswordService.initiate_password_reset(user['email'])
            if success:
                success_count += 1
                
                # Log individual reset
                AuditLog.log_auth_attempt(
                    user_id=current_user['userId'],
                    action_type="ADMIN_PASSWORD_RESET",
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent'),
                    metadata={
                        "reset_user_id": user_id,
                        "reset_email": user['email']
                    }
                )
            else:
                failed_users.append({"id": user_id, "error": message})
        
        # Log bulk action
        AuditLog.log_auth_attempt(
            user_id=current_user['userId'],
            action_type="BULK_PASSWORD_RESET",
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            metadata={
                "user_ids": data['userIds'],
                "success_count": success_count,
                "failed_count": len(failed_users)
            }
        )
        
        return jsonify({
            "message": f"Password reset emails sent to {success_count} users",
            "success_count": success_count,
            "failed_count": len(failed_users),
            "failed_users": failed_users
        }), 200
        
    except Exception as e:
        print(f"Error in bulk password reset: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

# Add bulk invite endpoint
@users_bp.route('/users/bulk/invite', methods=['POST'])
@token_required
def bulk_invite_users(current_user):
    """Bulk invite multiple users"""
    try:
        # Only admins/managers can invite users
        if current_user['role'] not in ['admin', 'administrator', 'manager']:
            return jsonify({"error": "Insufficient permissions"}), 403
        
        data = request.get_json()
        
        if 'invites' not in data or not data['invites']:
            return jsonify({"error": "Invites are required"}), 400
        
        organization_id = current_user.get('organization', {}).get('id')
        if not organization_id:
            return jsonify({"error": "Organization not found"}), 404
        
        success_count = 0
        failed_invites = []
        
        for invite in data['invites']:
            try:
                # Validate required fields
                if not invite.get('email'):
                    failed_invites.append({"email": invite.get('email'), "error": "Email is required"})
                    continue
                
                if not invite.get('role'):
                    failed_invites.append({"email": invite.get('email'), "error": "Role is required"})
                    continue
                
                # Validate email format
                email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
                if not re.match(email_regex, invite['email']):
                    failed_invites.append({"email": invite.get('email'), "error": "Invalid email format"})
                    continue
                
                # Validate role
                role_lower = invite['role'].lower()
                valid_roles = ['admin', 'administrator', 'manager', 'developer', 'auditor', 'viewer', 'user']
                if role_lower not in valid_roles:
                    failed_invites.append({"email": invite.get('email'), "error": f"Invalid role: {invite['role']}"})
                    continue
                
                # Check if user already exists
                existing_user = UserService.find_user_by_email_and_org(invite['email'], organization_id)
                if existing_user:
                    failed_invites.append({"email": invite.get('email'), "error": "User already exists in organization"})
                    continue
                
                # Create invitation
                invitation, error = UserService.create_invitation(
                    inviter_id=current_user['userId'],
                    email=invite['email'],
                    role=role_lower,
                    organization_id=organization_id,
                    department=invite.get('department', ''),
                    name=invite.get('name', ''),
                    phone=invite.get('phone', ''),
                    permissions=invite.get('permissions', []),
                    message=invite.get('message', '')
                )
                
                if error:
                    failed_invites.append({"email": invite.get('email'), "error": error})
                else:
                    success_count += 1
                    
            except Exception as e:
                failed_invites.append({"email": invite.get('email'), "error": str(e)})
        
        # Log bulk invitation
        AuditLog.log_auth_attempt(
            user_id=current_user['userId'],
            action_type="BULK_INVITE_USERS",
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            metadata={
                "invites_count": len(data['invites']),
                "success_count": success_count,
                "failed_count": len(failed_invites)
            }
        )
        
        return jsonify({
            "message": f"Invitations sent to {success_count} users",
            "success_count": success_count,
            "failed_count": len(failed_invites),
            "failed_invites": failed_invites
        }), 201
        
    except Exception as e:
        print(f"Error in bulk invite: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500