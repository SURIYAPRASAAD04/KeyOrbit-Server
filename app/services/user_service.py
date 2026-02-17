import secrets
from datetime import datetime, timedelta
from bson import ObjectId
from app.models import User, Organization, AuditLog, Invitation
from app.utils.security import hash_password, generate_verification_code
from app.services.email_service import EmailService
from app.config import Config
from pytz import timezone, UTC

IST = timezone('Asia/Kolkata')

class UserService:
    collection = User.collection
    invitations_collection = Invitation.collection
    
    @staticmethod
    def get_organization_users(organization_id):
        """Get all users in an organization"""
        users = list(User.collection.find({
            "organization.id": organization_id,
            "status": {"$ne": "deleted"}
        }).sort("createdAt", -1))
        
        formatted_users = []
        for user in users:
            # Skip sensitive data
            if 'password' in user:
                del user['password']
            if 'verificationCode' in user:
                del user['verificationCode']
            if 'verificationCodeExpires' in user:
                del user['verificationCodeExpires']
            
            # Calculate last activity
            last_activity = "Never"
            if user.get('lastLogin'):
                last_login = user['lastLogin']
                if isinstance(last_login, datetime):
                    if last_login.tzinfo is None:
                        last_login = UTC.localize(last_login).astimezone(IST)
                    else:
                        last_login = last_login.astimezone(IST)
                    
                    now = datetime.now(IST)
                    diff = now - last_login
                    
                    if diff.days > 0:
                        last_activity = f"{diff.days}d ago"
                    elif diff.seconds > 3600:
                        last_activity = f"{diff.seconds // 3600}h ago"
                    elif diff.seconds > 60:
                        last_activity = f"{diff.seconds // 60}m ago"
                    else:
                        last_activity = "Just now"
            
            formatted_users.append({
                "id": str(user["_id"]),
                "firstName": user.get("firstName", ""),
                "lastName": user.get("lastName", ""),
                "name": f"{user.get('firstName', '')} {user.get('lastName', '')}".strip(),
                "email": user.get("email", ""),
                "phone": user.get("phone", ""),
                "role": user.get("role", "user"),
                "status": user.get("status", "active"),
                "department": user.get("department", ""),
                "isVerified": user.get("isVerified", False),
                "lastLogin": user.get("lastLogin"),
                "lastActivity": last_activity,
                "createdAt": user.get("createdAt"),
                "permissions": UserService._get_role_permissions(user.get("role", "user")),
                "joinDate": user.get("createdAt").date().isoformat() if user.get("createdAt") else None
            })
        
        return formatted_users
    
    @staticmethod
    def _normalize_role(role):
        """Normalize role to lowercase and handle variations"""
        if not role:
            return 'user'
        
        role_lower = role.lower()
        
        # Handle role variations
        role_mapping = {
            'administrator': 'admin',
            'admin': 'admin',
            'manager': 'manager',
            'developer': 'developer',
            'programmer': 'developer',
            'engineer': 'developer',
            'security': 'developer',
            'auditor': 'auditor',
            'viewer': 'viewer',
            'user': 'user',
            'member': 'user'
        }
        
        return role_mapping.get(role_lower, 'user')
    
    @staticmethod
    def _get_role_permissions(role):
        """Get permissions based on role"""
        normalized_role = UserService._normalize_role(role)
        
        permissions_map = {
            'admin': ['Read', 'Write', 'Admin', 'Audit', 'Manage', 'Delete', 'Configure'],
            'administrator': ['Read', 'Write', 'Admin', 'Audit', 'Manage', 'Delete', 'Configure'],
            'manager': ['Read', 'Write', 'Manage', 'Audit'],
            'developer': ['Read', 'Write', 'Execute'],
            'security': ['Read', 'Write', 'Execute', 'Audit'],
            'auditor': ['Read', 'Audit', 'Export'],
            'viewer': ['Read'],
            'user': ['Read']
        }
        return permissions_map.get(normalized_role, ['Read'])
    
    @staticmethod
    def find_user_by_email_and_org(email, organization_id):
        """Find user by email in specific organization"""
        return User.collection.find_one({
            "email": email.lower(),
            "organization.id": organization_id,
            "status": {"$ne": "deleted"}
        })
    
    @staticmethod
    def create_invitation(inviter_id, email, role, organization_id, **kwargs):
        """Create a user invitation"""
        try:
            print(f"=== CREATE INVITATION START ===")
            print(f"Email: {email}, Role: {role}, Org: {organization_id}")
            
            # Check if invitation already exists
            existing_invitation = UserService.invitations_collection.find_one({
                "email": email.lower(),
                "organizationId": ObjectId(organization_id),
                "status": "pending"
            })
            
            if existing_invitation:
                print(f"Existing invitation found: {existing_invitation}")
                return None, "Invitation already sent to this email"
            
            # Generate invitation token
            invitation_token = secrets.token_urlsafe(32)
            print(f"Generated token: {invitation_token[:20]}...")
            
            # Create invitation data with IST timezone
            invitation_data = {
                "email": email.lower(),
                "role": role,
                "organizationId": ObjectId(organization_id),
                "invitedBy": ObjectId(inviter_id),
                "invitationToken": invitation_token,
                "status": "pending",
                "department": kwargs.get('department', ''),
                "name": kwargs.get('name', ''),
                "phone": kwargs.get('phone', ''),
                "permissions": kwargs.get('permissions', []),
                "message": kwargs.get('message', ''),
                "invitedAt": datetime.now(IST),
                "expiresAt": datetime.now(IST) + timedelta(days=7),
                "createdAt": datetime.now(IST),
                "updatedAt": datetime.now(IST)
            }
            
            print(f"Invitation data: {invitation_data}")
            
            # Insert invitation
            result = UserService.invitations_collection.insert_one(invitation_data)
            invitation_data['_id'] = result.inserted_id
            print(f"Inserted invitation ID: {result.inserted_id}")
            
            # Get organization details
            organization = Organization.find_by_id(organization_id)
            print(f"Organization: {organization}")
            
            inviter = User.find_by_id(inviter_id)
            print(f"Inviter: {inviter}")
            
            # Send invitation email
            email_sent = EmailService.send_user_invitation_email(
                email=email,
                invitation_token=invitation_token,
                organization_name=organization.get('name', 'KeyOrbit Organization') if organization else 'KeyOrbit Organization',
                inviter_name=f"{inviter.get('firstName', '')} {inviter.get('lastName', '')}".strip() if inviter else 'Admin',
                role=role,
                message=kwargs.get('message', '')
            )
            
            print(f"Email sent: {email_sent}")
            
            if not email_sent:
                print("Warning: Email sending failed, but invitation was created")
            
            print("=== CREATE INVITATION SUCCESS ===")
            return invitation_data, None
            
        except Exception as e:
            print(f"=== CREATE INVITATION ERROR ===")
            print(f"Error: {str(e)}")
            import traceback
            traceback.print_exc()
            print(f"=== END ERROR ===")
            return None, str(e)
    
    @staticmethod
    def get_user_details(user_id, organization_id):
        """Get detailed user information"""
        user = User.collection.find_one({
            "_id": ObjectId(user_id),
            "organization.id": organization_id,
            "status": {"$ne": "deleted"}
        })
        
        if not user:
            return None
        
        # Format user data
        formatted_user = {
            "id": str(user["_id"]),
            "firstName": user.get("firstName", ""),
            "lastName": user.get("lastName", ""),
            "name": f"{user.get('firstName', '')} {user.get('lastName', '')}".strip(),
            "email": user.get("email", ""),
            "phone": user.get("phone", ""),
            "role": user.get("role", "user"),
            "status": user.get("status", "active"),
            "department": user.get("department", ""),
            "isVerified": user.get("isVerified", False),
            "lastLogin": user.get("lastLogin"),
            "createdAt": user.get("createdAt"),
            "organization": user.get("organization", {}),
            "permissions": UserService._get_role_permissions(user.get("role", "user")),
            "mfaEnabled": user.get("mfaEnabled", False),
            "provider": user.get("provider", "local"),
            "joinDate": user.get("createdAt").date().isoformat() if user.get("createdAt") else None
        }
        
        return formatted_user
    
    @staticmethod
    def update_user(user_id, organization_id, updates):
        """Update user information"""
        try:
            # Ensure timezone aware
            updates['updatedAt'] = datetime.now(IST)
            
            # Handle role normalization
            if 'role' in updates:
                updates['role'] = UserService._normalize_role(updates['role'])
                updates['permissions'] = UserService._get_role_permissions(updates['role'])
            
            result = User.collection.update_one(
                {
                    "_id": ObjectId(user_id),
                    "organization.id": organization_id
                },
                {"$set": updates}
            )
            
            if result.modified_count == 0:
                return False, "User not found or no changes made"
            
            return True, None
            
        except Exception as e:
            print(f"Error updating user: {str(e)}")
            return False, str(e)
    
    @staticmethod
    def update_user_status(user_id, organization_id, status):
        """Update user status"""
        return UserService.update_user(user_id, organization_id, {"status": status})
    
    @staticmethod
    def update_user_role(user_id, organization_id, role):
        """Update user role"""
        normalized_role = UserService._normalize_role(role)
        updates = {"role": normalized_role}
        
        # Update permissions based on new role
        permissions = UserService._get_role_permissions(normalized_role)
        updates['permissions'] = permissions
        
        return UserService.update_user(user_id, organization_id, updates)
    
    @staticmethod
    def delete_user(user_id, organization_id):
        """Soft delete user (mark as deleted)"""
        try:
            result = User.collection.update_one(
                {
                    "_id": ObjectId(user_id),
                    "organization.id": organization_id
                },
                {
                    "$set": {
                        "status": "deleted",
                        "deletedAt": datetime.now(IST),
                        "updatedAt": datetime.now(IST)
                    }
                }
            )
            
            if result.modified_count == 0:
                return False, "User not found"
            
            return True, None
            
        except Exception as e:
            print(f"Error deleting user: {str(e)}")
            return False, str(e)
    
    @staticmethod
    def bulk_update_status(user_ids, organization_id, status):
        """Bulk update user statuses"""
        try:
            object_ids = [ObjectId(uid) for uid in user_ids]
            
            result = User.collection.update_many(
                {
                    "_id": {"$in": object_ids},
                    "organization.id": organization_id
                },
                {
                    "$set": {
                        "status": status,
                        "updatedAt": datetime.now(IST)
                    }
                }
            )
            
            return {
                "success": True,
                "affected_count": result.modified_count
            }
            
        except Exception as e:
            print(f"Error in bulk update status: {str(e)}")
            return {"success": False, "error": str(e)}
    
    @staticmethod
    def bulk_update_role(user_ids, organization_id, role):
        """Bulk update user roles"""
        try:
            object_ids = [ObjectId(uid) for uid in user_ids]
            normalized_role = UserService._normalize_role(role)
            permissions = UserService._get_role_permissions(normalized_role)
            
            result = User.collection.update_many(
                {
                    "_id": {"$in": object_ids},
                    "organization.id": organization_id
                },
                {
                    "$set": {
                        "role": normalized_role,
                        "permissions": permissions,
                        "updatedAt": datetime.now(IST)
                    }
                }
            )
            
            return {
                "success": True,
                "affected_count": result.modified_count
            }
            
        except Exception as e:
            print(f"Error in bulk update role: {str(e)}")
            return {"success": False, "error": str(e)}
    
    @staticmethod
    def bulk_update_department(user_ids, organization_id, department):
        """Bulk update user departments"""
        try:
            object_ids = [ObjectId(uid) for uid in user_ids]
            
            result = User.collection.update_many(
                {
                    "_id": {"$in": object_ids},
                    "organization.id": organization_id
                },
                {
                    "$set": {
                        "department": department,
                        "updatedAt": datetime.now(IST)
                    }
                }
            )
            
            return {
                "success": True,
                "affected_count": result.modified_count
            }
            
        except Exception as e:
            print(f"Error in bulk update department: {str(e)}")
            return {"success": False, "error": str(e)}
    
    @staticmethod
    def bulk_delete_users(user_ids, organization_id):
        """Bulk delete users"""
        try:
            object_ids = [ObjectId(uid) for uid in user_ids]
            
            result = User.collection.update_many(
                {
                    "_id": {"$in": object_ids},
                    "organization.id": organization_id
                },
                {
                    "$set": {
                        "status": "deleted",
                        "deletedAt": datetime.now(IST),
                        "updatedAt": datetime.now(IST)
                    }
                }
            )
            
            return {
                "success": True,
                "affected_count": result.modified_count
            }
            
        except Exception as e:
            print(f"Error in bulk delete users: {str(e)}")
            return {"success": False, "error": str(e)}
    
    # Update just the get_pending_invitations method:

    @staticmethod
    def get_pending_invitations(organization_id):
        """Get all pending invitations for organization"""
        try:
            invitations = list(UserService.invitations_collection.find({
                "organizationId": ObjectId(organization_id),
                "status": "pending"
            }).sort("invitedAt", -1))
            
            formatted_invitations = []
            now_ist = datetime.now(IST)
            
            for inv in invitations:
                # Ensure expiresAt has timezone info
                expires_at = inv.get("expiresAt")
                if expires_at:
                    # Convert to IST if it's naive (no timezone)
                    if isinstance(expires_at, datetime):
                        if expires_at.tzinfo is None:
                            # Assume it's stored as UTC in DB
                            expires_at = UTC.localize(expires_at).astimezone(IST)
                        else:
                            # Convert to IST
                            expires_at = expires_at.astimezone(IST)
                    else:
                        # If it's a string, parse it
                        try:
                            from dateutil import parser
                            expires_at = parser.parse(str(expires_at))
                            if expires_at.tzinfo is None:
                                expires_at = IST.localize(expires_at)
                            else:
                                expires_at = expires_at.astimezone(IST)
                        except:
                            # If parsing fails, skip this invitation
                            continue
                
                # Check if expired
                if expires_at and expires_at < now_ist:
                    # Mark as expired
                    try:
                        UserService.invitations_collection.update_one(
                            {"_id": inv["_id"]},
                            {"$set": {"status": "expired", "updatedAt": datetime.now(IST)}}
                        )
                    except:
                        pass
                    continue
                
                inviter = User.find_by_id(inv.get('invitedBy'))
                
                # Ensure invitedAt has timezone
                invited_at = inv.get("invitedAt")
                if invited_at and isinstance(invited_at, datetime) and invited_at.tzinfo is None:
                    invited_at = UTC.localize(invited_at).astimezone(IST)
                
                formatted_invitations.append({
                    "id": str(inv["_id"]),
                    "email": inv["email"],
                    "role": inv.get("role", "user"),
                    "name": inv.get("name", ""),
                    "department": inv.get("department", ""),
                    "status": inv.get("status", "pending"),
                    "invitedBy": {
                        "id": str(inviter["_id"]) if inviter else None,
                        "name": f"{inviter.get('firstName', '')} {inviter.get('lastName', '')}".strip() if inviter else "Unknown"
                    } if inviter else None,
                    "invitedAt": invited_at.isoformat() if invited_at else None,
                    "expiresAt": expires_at.isoformat() if expires_at else None,
                    "expiresIn": UserService._calculate_time_until(expires_at, now_ist),
                    "message": inv.get("message", "")
                })
            
            return formatted_invitations
            
        except Exception as e:
            print(f"Error getting pending invitations: {str(e)}")
            import traceback
            traceback.print_exc()
            return []

    @staticmethod
    def _calculate_time_until(expires_at, now_ist=None):
        """Calculate time until expiration with proper timezone handling"""
        if not expires_at:
            return "Never"
        
        if now_ist is None:
            now_ist = datetime.now(IST)
        
        # Ensure expires_at has timezone
        if expires_at.tzinfo is None:
            expires_at = IST.localize(expires_at)
        
        diff = expires_at - now_ist
        
        if diff.total_seconds() <= 0:
            return "Expired"
        
        days = diff.days
        hours = diff.seconds // 3600
        
        if days > 0:
            return f"{days}d {hours}h"
        elif hours > 0:
            minutes = (diff.seconds % 3600) // 60
            return f"{hours}h {minutes}m"
        else:
            minutes = diff.seconds // 60
            return f"{minutes}m"
        
    @staticmethod
    def resend_invitation(invitation_id, organization_id):
        """Resend an invitation with proper timezone handling"""
        try:
            invitation = UserService.invitations_collection.find_one({
                "_id": ObjectId(invitation_id),
                "organizationId": ObjectId(organization_id),
                "status": "pending"
            })
            
            if not invitation:
                return False, "Invitation not found"
            
            # Check if expired with proper timezone handling
            expires_at = invitation.get('expiresAt')
            if expires_at:
                # Ensure expires_at has timezone
                if isinstance(expires_at, datetime):
                    if expires_at.tzinfo is None:
                        expires_at = IST.localize(expires_at)
                    
                    now_ist = datetime.now(IST)
                    if expires_at < now_ist:
                        return False, "Invitation has expired"
            
            # Get organization and inviter details
            organization = Organization.find_by_id(organization_id)
            inviter = User.find_by_id(invitation.get('invitedBy'))
            
            # Send invitation email
            email_sent = EmailService.send_user_invitation_email(
                email=invitation['email'],
                invitation_token=invitation['invitationToken'],
                organization_name=organization.get('name', 'KeyOrbit Organization') if organization else 'KeyOrbit Organization',
                inviter_name=f"{inviter.get('firstName', '')} {inviter.get('lastName', '')}".strip() if inviter else 'Admin',
                role=invitation.get('role', 'user'),
                message=invitation.get('message', ''),
                is_resend=True
            )
            
            if not email_sent:
                return False, "Failed to send invitation email"
            
            # Update invitation
            UserService.invitations_collection.update_one(
                {"_id": ObjectId(invitation_id)},
                {
                    "$set": {
                        "updatedAt": datetime.now(IST),
                        "resendCount": invitation.get('resendCount', 0) + 1,
                        "lastResentAt": datetime.now(IST)
                    }
                }
            )
            
            return True, None
            
        except Exception as e:
            print(f"Error resending invitation: {str(e)}")
            return False, str(e)
    
    @staticmethod
    def cancel_invitation(invitation_id, organization_id):
        """Cancel an invitation"""
        try:
            result = UserService.invitations_collection.update_one(
                {
                    "_id": ObjectId(invitation_id),
                    "organizationId": ObjectId(organization_id),
                    "status": "pending"
                },
                {
                    "$set": {
                        "status": "cancelled",
                        "cancelledAt": datetime.now(IST),
                        "updatedAt": datetime.now(IST)
                    }
                }
            )
            
            if result.modified_count == 0:
                return False, "Invitation not found or already cancelled"
            
            return True, None
            
        except Exception as e:
            print(f"Error cancelling invitation: {str(e)}")
            return False, str(e)
    
    @staticmethod
    def admin_reset_password(user_id, organization_id):
        """Admin-initiated password reset"""
        try:
            user = User.collection.find_one({
                "_id": ObjectId(user_id),
                "organization.id": organization_id,
                "status": {"$in": ["active", "pending"]}
            })
            
            if not user:
                return False, "User not found"
            
            # Generate reset token
            from app.services.password_service import PasswordService
            success, message = PasswordService.initiate_password_reset(user['email'])
            
            if not success:
                return False, message
            
            return True, None
            
        except Exception as e:
            print(f"Error in admin reset password: {str(e)}")
            return False, str(e)
    
    @staticmethod
    def get_user_activity(user_id, limit=10):
        """Get user activity logs"""
        logs = list(AuditLog.collection.find({
            "userId": ObjectId(user_id)
        }).sort("timestamp", -1).limit(limit))
        
        formatted_logs = []
        for log in logs:
            formatted_logs.append({
                "id": str(log["_id"]),
                "actionType": log.get("actionType", ""),
                "timestamp": log.get("timestamp").isoformat() if log.get("timestamp") else None,
                "ipAddress": log.get("ipAddress"),
                "userAgent": log.get("userAgent"),
                "metadata": log.get("metadata", {})
            })
        
        return formatted_logs
    
    @staticmethod
    def get_organization_stats(organization_id):
        """Get organization user statistics"""
        # Get total users
        total_users = User.collection.count_documents({
            "organization.id": organization_id,
            "status": {"$ne": "deleted"}
        })
        
        # Get users by status
        active_users = User.collection.count_documents({
            "organization.id": organization_id,
            "status": "active"
        })
        
        inactive_users = User.collection.count_documents({
            "organization.id": organization_id,
            "status": "inactive"
        })
        
        suspended_users = User.collection.count_documents({
            "organization.id": organization_id,
            "status": "suspended"
        })
        
        pending_users = User.collection.count_documents({
            "organization.id": organization_id,
            "status": "pending"
        })
        
        # Get users by role
        users_by_role = {}
        pipeline = [
            {"$match": {"organization.id": organization_id, "status": {"$ne": "deleted"}}},
            {"$group": {"_id": "$role", "count": {"$sum": 1}}}
        ]
        
        role_results = list(User.collection.aggregate(pipeline))
        for result in role_results:
            users_by_role[result['_id']] = result['count']
        
        # Get pending invitations
        pending_invitations = UserService.invitations_collection.count_documents({
            "organizationId": ObjectId(organization_id),
            "status": "pending"
        })
        
        # Filter out expired invitations for display
        active_invitations = 0
        invitations = list(UserService.invitations_collection.find({
            "organizationId": ObjectId(organization_id),
            "status": "pending"
        }))
        
        for inv in invitations:
            expires_at = inv.get('expiresAt')
            if expires_at:
                if isinstance(expires_at, datetime) and expires_at.tzinfo is None:
                    expires_at = IST.localize(expires_at)
                if expires_at >= datetime.now(IST):
                    active_invitations += 1
        
        # Get recent activity (last 7 days)
        seven_days_ago = datetime.now(IST) - timedelta(days=7)
        recent_activity = AuditLog.collection.count_documents({
            "organizationId": ObjectId(organization_id),
            "timestamp": {"$gte": seven_days_ago}
        })
        
        return {
            "totalUsers": total_users,
            "activeUsers": active_users,
            "inactiveUsers": inactive_users,
            "suspendedUsers": suspended_users,
            "pendingUsers": pending_users,
            "usersByRole": users_by_role,
            "pendingInvitations": active_invitations,
            "recentActivity": recent_activity,
            "verifiedUsers": User.collection.count_documents({
                "organization.id": organization_id,
                "isVerified": True,
                "status": {"$ne": "deleted"}
            })
        }
    @staticmethod
    def is_invitation_expired(invitation):
        """Check if invitation is expired"""
        expires_at = invitation.get('expiresAt')
        if not expires_at:
            return False
        
        # Ensure timezone aware
        expires_at = UserService._ensure_timezone_aware(expires_at)
        if not expires_at:
            return False
        
        now_ist = datetime.now(IST)
        return expires_at < now_ist
    
    @staticmethod
    def find_valid_invitation(token):
        """Find a valid (non-expired) invitation by token"""
        from datetime import datetime
        from pytz import UTC
        
        # First find the invitation
        invitation = UserService.invitations_collection.find_one({
            "invitationToken": token,
            "status": "pending"
        })
        
        if not invitation:
            return None
        
        # Check expiration
        expires_at = invitation.get('expiresAt')
        if expires_at:
            # Convert to timezone aware for comparison
            if isinstance(expires_at, datetime):
                if expires_at.tzinfo is None:
                    # Assume IST if naive
                    from pytz import timezone as tz
                    IST = tz('Asia/Kolkata')
                    expires_at = IST.localize(expires_at)
                
                now_ist = datetime.now(IST)
                
                if expires_at < now_ist:
                    # Mark as expired
                    UserService.invitations_collection.update_one(
                        {"_id": invitation['_id']},
                        {"$set": {"status": "expired", "updatedAt": datetime.now(IST)}}
                    )
                    return None
        
        return invitation
    
    @staticmethod
    def accept_invitation(invitation_token, user_data):
        """Accept an invitation and create user account"""
        try:
            # Find valid invitation
            invitation = UserService.find_valid_invitation(invitation_token)
            
            if not invitation:
                return None, "Invalid or expired invitation"
            
            # Check if user already exists with this email
            existing_user = User.find_by_email(invitation['email'])
            if existing_user:
                # Check if user is already in this organization
                if existing_user.get('organization', {}).get('id') == str(invitation['organizationId']):
                    return None, "User already exists in this organization"
            
            # Create user
            hashed_password = hash_password(user_data['password'])
            
            user_create_data = {
                "firstName": user_data.get('firstName', invitation.get('name', '').split(' ')[0] if invitation.get('name') else ''),
                "lastName": user_data.get('lastName', ' '.join(invitation.get('name', '').split(' ')[1:]) if invitation.get('name') and len(invitation.get('name', '').split(' ')) > 1 else ''),
                "email": invitation['email'].lower(),
                "phone": user_data.get('phone', invitation.get('phone', '')),
                "password": hashed_password,
                "isVerified": True,  # Auto-verify since invited by admin
                "organizationId": invitation['organizationId'],
                "organization": {
                    "id": str(invitation['organizationId']),
                    "name": ""  # Will be populated from organization document
                },
                "role": invitation['role'],
                "department": invitation.get('department', ''),
                "status": "active",
                "permissions": UserService._get_role_permissions(invitation['role']),
                "provider": "local",
                "invitationId": invitation['_id'],
                "lastLogin": datetime.now(IST),
                "createdAt": datetime.now(IST),
                "updatedAt": datetime.now(IST)
            }
            
            # Get organization name
            organization = Organization.find_by_id(invitation['organizationId'])
            if organization:
                user_create_data['organization']['name'] = organization.get('name', '')
            
            # Insert user
            user_result = User.collection.insert_one(user_create_data)
            user_id = str(user_result.inserted_id)
            
            # Update invitation status
            UserService.invitations_collection.update_one(
                {"_id": invitation['_id']},
                {
                    "$set": {
                        "status": "accepted",
                        "acceptedAt": datetime.now(IST),
                        "acceptedBy": user_result.inserted_id,
                        "updatedAt": datetime.now(IST)
                    }
                }
            )
            
            # Generate JWT token
            from app.utils.security import generate_jwt
            token = generate_jwt({
                "userId": user_id,
                "email": invitation['email'],
                "role": invitation['role']
            })
            
            # Store session
            from app.models import Session
            expires = datetime.now(IST) + timedelta(minutes=Config.JWT_EXPIRE_MINUTES)
            Session.create_session(user_id, token, expires)
            
            # Log the acceptance
            AuditLog.log_auth_attempt(
                user_id=user_id,
                action_type="INVITATION_ACCEPTED",
                ip_address=user_data.get('ip_address'),
                user_agent=user_data.get('user_agent'),
                metadata={
                    "invitation_id": str(invitation['_id']),
                    "invited_by": str(invitation['invitedBy'])
                }
            )
            
            user_response = {
                "id": user_id,
                "firstName": user_create_data['firstName'],
                "lastName": user_create_data['lastName'],
                "email": user_create_data['email'],
                "role": user_create_data['role'],
                "organization": user_create_data['organization'],
                "isVerified": True,
                "department": user_create_data['department'],
                "status": "active"
            }
            
            return {"user": user_response, "token": token}, None
            
        except Exception as e:
            print(f"Error accepting invitation: {str(e)}")
            import traceback
            traceback.print_exc()
            return None, str(e)