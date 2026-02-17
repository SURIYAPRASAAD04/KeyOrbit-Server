from datetime import datetime, timedelta
import random
from bson import ObjectId
from pymongo import MongoClient
from app.config import Config

client = MongoClient(Config.MONGODB_URI)
db = client.keyorbit

class User:
    collection = db.users
    
    @staticmethod
    def create_user(data):
        user_data = {
            "firstName": data["firstName"],
            "lastName": data["lastName"],
            "email": data["email"].lower(),
            "phone": data.get("phone", ""),
            "password": data["password"],
            "isVerified": data.get("isVerified", False),
            "verificationCode": data.get("verificationCode"),
            "verificationCodeExpires": data.get("verificationCodeExpires"),
            "organizationId": ObjectId(data["organizationId"]) if data.get("organizationId") else None,
            "organization": data.get("organization", {}),
            "role": data.get("role", "admin"),  # Default to admin for UI registrations
            "provider": data.get("provider", "local"),
            "providerId": data.get("providerId"),
            "mfaEnabled": data.get("mfaEnabled", False),
            "mfaSecret": data.get("mfaSecret"),
            "lastLogin": data.get("lastLogin"),
            "status": data.get("status", "active"),  # Add status field
            "permissions": data.get("permissions", []),
            "department": data.get("department", ""),
            "createdAt": data.get("createdAt", datetime.utcnow()),
            "updatedAt": data.get("updatedAt", datetime.utcnow())
        }
        return User.collection.insert_one(user_data)
    
    @staticmethod
    def find_by_email(email):
        return User.collection.find_one({"email": email.lower()})
    
    @staticmethod
    def find_by_id(user_id):
        return User.collection.find_one({"_id": ObjectId(user_id)})
    
    @staticmethod
    def update_user(user_id, updates):
        updates["updatedAt"] = datetime.utcnow()
        return User.collection.update_one(
            {"_id": ObjectId(user_id)}, 
            {"$set": updates}
        )
    
    @staticmethod
    def set_verification_code(user_id, code):
        expires = datetime.utcnow() + timedelta(minutes=Config.VERIFICATION_CODE_EXPIRE_MINUTES)
        return User.collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {
                "verificationCode": code,
                "verificationCodeExpires": expires
            }}
        )
    
    @staticmethod
    def verify_user(user_id):
        return User.collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {
                "isVerified": True,
                "verificationCode": None,
                "verificationCodeExpires": None
            }}
        )
    
    @staticmethod
    def find_by_provider(provider, provider_id):
        return User.collection.find_one({
            "provider": provider,
            "providerId": provider_id
        })

class Organization:
    collection = db.organizations
    
    @staticmethod
    def create_organization(data):
        org_data = {
            "name": data["name"],
            "domain": data["domain"],
            "industry": data.get("industry", ""),
            "size": data.get("size", ""),
            "verified": data.get("verified", False),
            "ssoEnabled": data.get("ssoEnabled", False),
            "createdAt": datetime.utcnow(),
            "updatedAt": datetime.utcnow()
        }
        return Organization.collection.insert_one(org_data)
    
    @staticmethod
    def find_by_domain(domain):
        return Organization.collection.find_one({"domain": domain})
    
    @staticmethod
    def find_by_id(org_id):
        return Organization.collection.find_one({"_id": ObjectId(org_id)})
    
    @staticmethod
    def verify_organization(org_id):
        return Organization.collection.update_one(
            {"_id": ObjectId(org_id)},
            {"$set": {
                "verified": True,
                "updatedAt": datetime.utcnow()
            }}
        )

class Session:
    collection = db.sessions
    
    @staticmethod
    def create_session(user_id, token, expires):
        session_data = {
            "userId": ObjectId(user_id),
            "token": token,
            "expires": expires,
            "createdAt": datetime.utcnow()
        }
        return Session.collection.insert_one(session_data)
    
    @staticmethod
    def find_by_token(token):
        return Session.collection.find_one({"token": token})
    
    @staticmethod
    def delete_session(token):
        return Session.collection.delete_one({"token": token})
    
    @staticmethod
    def delete_user_sessions(user_id):
        return Session.collection.delete_many({"userId": ObjectId(user_id)})
    
class PasswordReset:
    collection = db.password_resets
    
    @staticmethod
    def create_reset_token(user_id, token, expires_at):
        reset_data = {
            "userId": ObjectId(user_id),
            "token": token,
            "expiresAt": expires_at,
            "used": False,
            "createdAt": datetime.utcnow()
        }
        return PasswordReset.collection.insert_one(reset_data)
    
    @staticmethod
    def find_by_token(token):
        return PasswordReset.collection.find_one({"token": token})
    
    @staticmethod
    def mark_token_used(reset_id):
        return PasswordReset.collection.update_one(
            {"_id": reset_id},
            {"$set": {"used": True, "usedAt": datetime.utcnow()}}
        )
    
    @staticmethod
    def delete_user_tokens(user_id):
        return PasswordReset.collection.delete_many({"userId": ObjectId(user_id)})

from datetime import datetime, timedelta
import random
from bson import ObjectId
from pymongo import MongoClient
from app.config import Config
from pytz import timezone, UTC

IST = timezone('Asia/Kolkata')

# ... (keep existing User, Organization, Session, PasswordReset classes) ...

class ApiToken:
    collection = db.api_tokens
    
    @staticmethod
    def create_token(data):
        """Create a new API token with IST timezone"""
        # Ensure all datetime fields are in IST
        created_at = data.get("createdAt", datetime.now(IST))
        updated_at = data.get("updatedAt", datetime.now(IST))
        expires_at = data.get("expiresAt")
        
        # Make sure datetimes are timezone aware
        if created_at and created_at.tzinfo is None:
            created_at = IST.localize(created_at)
        if updated_at and updated_at.tzinfo is None:
            updated_at = IST.localize(updated_at)
        if expires_at and isinstance(expires_at, datetime) and expires_at.tzinfo is None:
            expires_at = IST.localize(expires_at)
        
        token_data = {
            "userId": ObjectId(data["userId"]),
            "name": data["name"],
            "description": data.get("description", ""),
            "tokenHash": data["tokenHash"],
            "tokenPreview": data.get("tokenPreview", ""),
            "permissions": data.get("permissions", []),
            "scopes": data.get("scopes", []),
            "status": data.get("status", "active"),
            "rateLimit": data.get("rateLimit", 1000),
            "ipRestrictions": data.get("ipRestrictions", []),
            "expiresAt": expires_at,
            "lastUsed": data.get("lastUsed"),
            "lastUsedIp": data.get("lastUsedIp"),
            "apiCalls": data.get("apiCalls", 0),
            "createdAt": created_at,
            "updatedAt": updated_at
        }
        return ApiToken.collection.insert_one(token_data)
    
    @staticmethod
    def find_by_user(user_id, include_revoked=False):
        """Find all tokens for a user"""
        query = {"userId": ObjectId(user_id)}
        if not include_revoked:
            query["status"] = {"$ne": "revoked"}
        
        # Sort by creation date descending
        tokens = list(ApiToken.collection.find(query).sort("createdAt", -1))
        
        # Ensure all datetime objects have IST timezone info
        for token in tokens:
            for field in ['createdAt', 'updatedAt', 'lastUsed', 'expiresAt']:
                if field in token and token[field] and isinstance(token[field], datetime):
                    if token[field].tzinfo is None:
                        # Assume it's stored as UTC in DB, convert to IST for display
                        token[field] = UTC.localize(token[field]).astimezone(IST)
        
        return tokens
    
    @staticmethod
    def find_by_token_hash(token_hash):
        """Find token by its hash (direct lookup - for internal use)"""
        token = ApiToken.collection.find_one({"tokenHash": token_hash})
        if token and 'createdAt' in token and isinstance(token['createdAt'], datetime) and token['createdAt'].tzinfo is None:
            token['createdAt'] = IST.localize(token['createdAt'])
        return token
    
    @staticmethod
    def find_by_token_value(token_value):
        """Find token by verifying the token value against all hashes"""
        from app.utils.security import verify_password
        
        # Get all active and expired tokens (to check expiration)
        tokens = list(ApiToken.collection.find({"status": {"$in": ["active", "expired"]}}))
        
        for token in tokens:
            if verify_password(token_value, token.get("tokenHash", "")):
                # Ensure datetime fields have timezone info
                for field in ['createdAt', 'updatedAt', 'lastUsed', 'expiresAt']:
                    if field in token and token[field] and isinstance(token[field], datetime) and token[field].tzinfo is None:
                        token[field] = IST.localize(token[field])
                return token
        return None
    
    @staticmethod
    def find_by_id(token_id):
        """Find token by ID"""
        token = ApiToken.collection.find_one({"_id": ObjectId(token_id)})
        if token and 'createdAt' in token and isinstance(token['createdAt'], datetime) and token['createdAt'].tzinfo is None:
            token['createdAt'] = IST.localize(token['createdAt'])
        return token
    
    @staticmethod
    def find_by_user_and_id(user_id, token_id):
        """Find token by user ID and token ID"""
        token = ApiToken.collection.find_one({
            "_id": ObjectId(token_id),
            "userId": ObjectId(user_id)
        })
        if token and 'createdAt' in token and isinstance(token['createdAt'], datetime) and token['createdAt'].tzinfo is None:
            token['createdAt'] = IST.localize(token['createdAt'])
        return token
    
    @staticmethod
    def update_token(token_id, updates):
        """Update token information"""
        updates["updatedAt"] = datetime.now(IST)
        return ApiToken.collection.update_one(
            {"_id": ObjectId(token_id)},
            {"$set": updates}
        )
    
    @staticmethod
    def increment_api_calls(token_id, ip_address=None):
        """Increment API call count and update last used timestamp"""
        update_data = {
            "$inc": {"apiCalls": 1},
            "$set": {
                "lastUsed": datetime.now(IST),
                "updatedAt": datetime.now(IST)
            }
        }
        
        if ip_address:
            update_data["$set"]["lastUsedIp"] = ip_address
        
        return ApiToken.collection.update_one(
            {"_id": ObjectId(token_id)},
            update_data
        )
    
    @staticmethod
    def revoke_token(token_id):
        """Revoke/delete a token"""
        return ApiToken.collection.update_one(
            {"_id": ObjectId(token_id)},
            {"$set": {
                "status": "revoked",
                "updatedAt": datetime.now(IST)
            }}
        )
    
    @staticmethod
    def regenerate_token(token_id, new_token_hash, new_token_preview):
        """Regenerate token with new value"""
        return ApiToken.collection.update_one(
            {"_id": ObjectId(token_id)},
            {"$set": {
                "tokenHash": new_token_hash,
                "tokenPreview": new_token_preview,
                "lastUsed": None,
                "lastUsedIp": None,
                "apiCalls": 0,
                "updatedAt": datetime.now(IST)
            }}
        )
    
    @staticmethod
    def delete_expired_tokens():
        """Delete expired tokens (can be run as cron job)"""
        from app.utils.security import is_token_expired
        
        tokens = list(ApiToken.collection.find({"status": "active", "expiresAt": {"$exists": True}}))
        
        expired_count = 0
        for token in tokens:
            expires_at = token.get("expiresAt")
            # Ensure datetime has timezone
            if expires_at and isinstance(expires_at, datetime) and expires_at.tzinfo is None:
                expires_at = IST.localize(expires_at)
            
            if expires_at and is_token_expired(expires_at):
                ApiToken.collection.update_one(
                    {"_id": token["_id"]},
                    {"$set": {"status": "expired"}}
                )
                expired_count += 1
        
        return expired_count
    
    @staticmethod
    def is_token_valid(token_value):
        """Check if token is valid and not expired/revoked"""
        from app.utils.security import is_token_expired
        
        token = ApiToken.find_by_token_value(token_value)
        if not token:
            return False
        
        if token.get("status") != "active":
            return False
        
        expires_at = token.get("expiresAt")
        if expires_at and is_token_expired(expires_at):
            # Auto-mark as expired
            ApiToken.collection.update_one(
                {"_id": token["_id"]},
                {"$set": {"status": "expired"}}
            )
            return False
        
        return True
    
    @staticmethod
    def get_token_info(token_value):
        """Get token information by value"""
        return ApiToken.find_by_token_value(token_value)

# Add these classes to your existing models.py

class Organization:
    collection = db.organizations
    
    @staticmethod
    def create_organization(data):
        """Create a new organization - only after email verification"""
        org_data = {
            "name": data["name"],
            "domain": data.get("domain", ""),
            "industry": data.get("industry", ""),
            "size": data.get("size", ""),
            "createdBy": ObjectId(data["createdBy"]),
            "verified": data.get("verified", False),
            "ssoEnabled": data.get("ssoEnabled", False),
            "createdAt": datetime.utcnow(),
            "updatedAt": datetime.utcnow()
        }
        return Organization.collection.insert_one(org_data)
    
    @staticmethod
    def find_by_domain(domain):
        return Organization.collection.find_one({"domain": domain})
    
    @staticmethod
    def find_by_id(org_id):
        return Organization.collection.find_one({"_id": ObjectId(org_id)})


class PendingRegistration:
    """Temporary storage for registration data before verification"""
    collection = db.pending_registrations
    
    @staticmethod
    def create(data):
        pending_data = {
            "firstName": data["firstName"],
            "lastName": data["lastName"],
            "email": data["email"].lower(),
            "phone": data["phone"],
            "password": data["password"],
            "organizationData": data.get("organizationData", {}),
            "verificationCode": data["verificationCode"],
            "verificationCodeExpires": data["verificationCodeExpires"],
            "createdAt": datetime.utcnow(),
            "updatedAt": datetime.utcnow()
        }
        return PendingRegistration.collection.insert_one(pending_data)
    
    @staticmethod
    def find_by_email(email):
        return PendingRegistration.collection.find_one({"email": email.lower()})
    
    @staticmethod
    def find_by_code(code):
        return PendingRegistration.collection.find_one({"verificationCode": code})
    
    @staticmethod
    def delete_by_email(email):
        return PendingRegistration.collection.delete_one({"email": email.lower()})


class AuditLog:
    """Centralized audit logging system"""
    collection = db.audit_logs
    
    @staticmethod
    def create_log(data):
        log_data = {
            "userId": ObjectId(data["userId"]) if data.get("userId") else None,
            "organizationId": ObjectId(data["organizationId"]) if data.get("organizationId") else None,
            "actionType": data["actionType"],
            "ipAddress": data.get("ipAddress"),
            "userAgent": data.get("userAgent"),
            "metadata": data.get("metadata", {}),
            "timestamp": datetime.utcnow()
        }
        return AuditLog.collection.insert_one(log_data)
    
    @staticmethod
    def log_auth_attempt(user_id, action_type, ip_address, user_agent, metadata=None):
        """Helper method for auth-related logs"""
        return AuditLog.create_log({
            "userId": user_id,
            "actionType": action_type,
            "ipAddress": ip_address,
            "userAgent": user_agent,
            "metadata": metadata or {}
        })
    @staticmethod
    def create_indexes():
        """Create indexes for better query performance"""
        AuditLog.collection.create_index([("timestamp", -1)])
        AuditLog.collection.create_index([("organizationId", 1), ("timestamp", -1)])
        AuditLog.collection.create_index([("userId", 1), ("timestamp", -1)])
        AuditLog.collection.create_index([("actionType", 1), ("timestamp", -1)])
        AuditLog.collection.create_index([("organizationId", 1), ("actionType", 1)])

class Invitation:
    collection = db.invitations
    
    @staticmethod
    def create_invitation(data):
        """Create a new invitation"""
        invitation_data = {
            "email": data["email"].lower(),
            "role": data["role"],
            "organizationId": ObjectId(data["organizationId"]),
            "invitedBy": ObjectId(data["invitedBy"]),
            "invitationToken": data["invitationToken"],
            "status": data.get("status", "pending"),
            "department": data.get("department", ""),
            "name": data.get("name", ""),
            "phone": data.get("phone", ""),
            "permissions": data.get("permissions", []),
            "message": data.get("message", ""),
            "invitedAt": data.get("invitedAt", datetime.utcnow()),
            "expiresAt": data.get("expiresAt", datetime.utcnow() + timedelta(days=7)),
            "createdAt": data.get("createdAt", datetime.utcnow()),
            "updatedAt": data.get("updatedAt", datetime.utcnow())
        }
        return Invitation.collection.insert_one(invitation_data)
    
    @staticmethod
    def find_by_token(token):
        """Find invitation by token"""
        return Invitation.collection.find_one({"invitationToken": token})
    
    @staticmethod
    def find_by_email_and_org(email, organization_id):
        """Find pending invitation by email and organization"""
        return Invitation.collection.find_one({
            "email": email.lower(),
            "organizationId": ObjectId(organization_id),
            "status": "pending"
        })
    
    @staticmethod
    def update_status(invitation_id, status):
        """Update invitation status"""
        return Invitation.collection.update_one(
            {"_id": ObjectId(invitation_id)},
            {"$set": {
                "status": status,
                "updatedAt": datetime.utcnow()
            }}
        )
class Key:
    collection = db.keys
    
    @staticmethod
    def create_key(key_data):
        """Create a new key"""
        # Ensure ObjectId conversion
        if key_data.get('userId') and isinstance(key_data['userId'], str):
            key_data['userId'] = ObjectId(key_data['userId'])
        if key_data.get('organizationId') and isinstance(key_data['organizationId'], str):
            key_data['organizationId'] = ObjectId(key_data['organizationId'])
        
        # Ensure timestamps are timezone aware
        for field in ['createdAt', 'updatedAt', 'expiresAt', 'lastUsed']:
            if field in key_data and key_data[field] and isinstance(key_data[field], datetime):
                if key_data[field].tzinfo is None:
                    key_data[field] = IST.localize(key_data[field])
        
        return Key.collection.insert_one(key_data)
    
    @staticmethod
    def find_by_id(key_id):
        """Find key by ID"""
        try:
            key = Key.collection.find_one({"_id": ObjectId(key_id)})
            if key:
                Key._ensure_timezone(key)
            return key
        except:
            return None
    
    @staticmethod
    def find_by_key_id(key_id):
        """Find key by keyId field"""
        return Key.collection.find_one({"keyId": key_id})
    
    @staticmethod
    def find_by_user(user_id, include_revoked=False):
        """Find all keys for a user"""
        query = {"userId": ObjectId(user_id)}
        if not include_revoked:
            query["status"] = {"$nin": ["revoked", "deleted"]}
        
        keys = list(Key.collection.find(query).sort("createdAt", -1))
        for key in keys:
            Key._ensure_timezone(key)
        return keys
    
    @staticmethod
    def find_by_organization(organization_id, include_revoked=False):
        """Find all keys in an organization"""
        query = {"organizationId": ObjectId(organization_id)}
        if not include_revoked:
            query["status"] = {"$nin": ["revoked", "deleted"]}
        
        keys = list(Key.collection.find(query).sort("createdAt", -1))
        for key in keys:
            Key._ensure_timezone(key)
        return keys
    
    @staticmethod
    def find_by_user_and_org(user_id, organization_id, include_revoked=False):
        """Find keys for a user in an organization"""
        query = {
            "userId": ObjectId(user_id),
            "organizationId": ObjectId(organization_id)
        }
        if not include_revoked:
            query["status"] = {"$nin": ["revoked", "deleted"]}
        
        keys = list(Key.collection.find(query).sort("createdAt", -1))
        for key in keys:
            Key._ensure_timezone(key)
        return keys
    
    @staticmethod
    def update_key(key_id, updates):
        """Update key information"""
        updates["updatedAt"] = datetime.now(IST)
        
        # Ensure ObjectId conversion
        if updates.get('userId') and isinstance(updates['userId'], str):
            updates['userId'] = ObjectId(updates['userId'])
        if updates.get('organizationId') and isinstance(updates['organizationId'], str):
            updates['organizationId'] = ObjectId(updates['organizationId'])
        
        return Key.collection.update_one(
            {"_id": ObjectId(key_id)},
            {"$set": updates}
        )
    
    @staticmethod
    def update_by_key_id(key_id, updates):
        """Update key by keyId field"""
        updates["updatedAt"] = datetime.now(IST)
        return Key.collection.update_one(
            {"keyId": key_id},
            {"$set": updates}
        )
    
    @staticmethod
    def revoke_key(key_id, reason=None):
        """Revoke a key"""
        updates = {
            "status": "revoked",
            "revokedAt": datetime.now(IST),
            "updatedAt": datetime.now(IST)
        }
        if reason:
            updates["revocationReason"] = reason
        
        return Key.collection.update_one(
            {"_id": ObjectId(key_id)},
            {"$set": updates}
        )
    
    @staticmethod
    def revoke_by_key_id(key_id, reason=None):
        """Revoke a key by keyId field"""
        updates = {
            "status": "revoked",
            "revokedAt": datetime.now(IST),
            "updatedAt": datetime.now(IST)
        }
        if reason:
            updates["revocationReason"] = reason
        
        return Key.collection.update_one(
            {"keyId": key_id},
            {"$set": updates}
        )
    
    @staticmethod
    def delete_key(key_id):
        """Permanently delete a key (soft delete)"""
        return Key.collection.update_one(
            {"_id": ObjectId(key_id)},
            {"$set": {
                "status": "deleted",
                "deletedAt": datetime.now(IST),
                "updatedAt": datetime.now(IST)
            }}
        )
    
    @staticmethod
    def rotate_key(key_id, new_key_data):
        """Rotate a key (create new version)"""
        # Find old key
        old_key = Key.find_by_id(key_id)
        if not old_key:
            return None, "Key not found"
        
        # Create new key with incremented version
        new_key_data["version"] = old_key.get("version", 1) + 1
        new_key_data["previousVersionId"] = str(old_key["_id"])
        new_key_data["status"] = "active"
        new_key_data["createdAt"] = datetime.now(IST)
        new_key_data["updatedAt"] = datetime.now(IST)
        
        # Mark old key as rotated
        Key.collection.update_one(
            {"_id": ObjectId(key_id)},
            {"$set": {
                "status": "rotated",
                "rotatedAt": datetime.now(IST),
                "updatedAt": datetime.now(IST),
                "nextVersionId": None  # Will be updated after new key is created
            }}
        )
        
        # Insert new key
        result = Key.collection.insert_one(new_key_data)
        
        # Update old key with next version ID
        Key.collection.update_one(
            {"_id": ObjectId(key_id)},
            {"$set": {"nextVersionId": str(result.inserted_id)}}
        )
        
        return result, None
    
    @staticmethod
    def get_key_stats(organization_id=None, user_id=None):
        """Get key statistics"""
        match_query = {}
        if organization_id:
            match_query["organizationId"] = ObjectId(organization_id)
        if user_id:
            match_query["userId"] = ObjectId(user_id)
        
        pipeline = [
            {"$match": match_query},
            {"$group": {
                "_id": None,
                "total": {"$sum": 1},
                "active": {"$sum": {"$cond": [{"$eq": ["$status", "active"]}, 1, 0]}},
                "expired": {"$sum": {"$cond": [{"$eq": ["$status", "expired"]}, 1, 0]}},
                "revoked": {"$sum": {"$cond": [{"$eq": ["$status", "revoked"]}, 1, 0]}},
                "rotated": {"$sum": {"$cond": [{"$eq": ["$status", "rotated"]}, 1, 0]}},
                "pending": {"$sum": {"$cond": [{"$eq": ["$status", "pending"]}, 1, 0]}},
                "kem_keys": {"$sum": {"$cond": [{"$eq": ["$type", "kem"]}, 1, 0]}},
                "signature_keys": {"$sum": {"$cond": [{"$eq": ["$type", "signature"]}, 1, 0]}},
                "hybrid_keys": {"$sum": {"$cond": [{"$eq": ["$type", "hybrid"]}, 1, 0]}}
            }}
        ]
        
        result = list(Key.collection.aggregate(pipeline))
        if result:
            return result[0]
        return {
            "total": 0, "active": 0, "expired": 0, "revoked": 0,
            "rotated": 0, "pending": 0, "kem_keys": 0,
            "signature_keys": 0, "hybrid_keys": 0
        }
    
    @staticmethod
    def _ensure_timezone(key):
        """Ensure datetime fields have timezone info"""
        for field in ['createdAt', 'updatedAt', 'expiresAt', 'lastUsed', 'revokedAt', 'deletedAt', 'rotatedAt']:
            if field in key and key[field] and isinstance(key[field], datetime) and key[field].tzinfo is None:
                key[field] = IST.localize(key[field])
        return key
    
    @staticmethod
    def check_expired_keys():
        """Check for expired keys and update status"""
        now = datetime.now(IST)
        result = Key.collection.update_many(
            {
                "status": "active",
                "expiresAt": {"$lt": now}
            },
            {"$set": {"status": "expired", "updatedAt": now}}
        )
        return result.modified_count