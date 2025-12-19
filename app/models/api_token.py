from datetime import datetime, timedelta
from bson import ObjectId
from app.models import db
import secrets

class ApiToken:
    collection = db.api_tokens
    
    @staticmethod
    def create_token(data):
        """Create a new API token"""
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
            "expiresAt": data.get("expiresAt"),
            "lastUsed": data.get("lastUsed"),
            "lastUsedIp": data.get("lastUsedIp"),
            "apiCalls": data.get("apiCalls", 0),
            "createdAt": data.get("createdAt", datetime.utcnow()),
            "updatedAt": data.get("updatedAt", datetime.utcnow())
        }
        return ApiToken.collection.insert_one(token_data)
    
    @staticmethod
    def find_by_user(user_id, include_revoked=False):
        """Find all tokens for a user"""
        query = {"userId": ObjectId(user_id)}
        if not include_revoked:
            query["status"] = {"$ne": "revoked"}
        return list(ApiToken.collection.find(query).sort("createdAt", -1))
    
    @staticmethod
    def find_by_token_hash(token_hash):
        """Find token by its hash"""
        return ApiToken.collection.find_one({"tokenHash": token_hash})
    
    @staticmethod
    def find_by_id(token_id):
        """Find token by ID"""
        return ApiToken.collection.find_one({"_id": ObjectId(token_id)})
    
    @staticmethod
    def find_by_user_and_id(user_id, token_id):
        """Find token by user ID and token ID"""
        return ApiToken.collection.find_one({
            "_id": ObjectId(token_id),
            "userId": ObjectId(user_id)
        })
    
    @staticmethod
    def update_token(token_id, updates):
        """Update token information"""
        updates["updatedAt"] = datetime.utcnow()
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
                "lastUsed": datetime.utcnow(),
                "updatedAt": datetime.utcnow()
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
                "updatedAt": datetime.utcnow()
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
                "updatedAt": datetime.utcnow()
            }}
        )
    
    @staticmethod
    def delete_expired_tokens():
        """Delete expired tokens (can be run as cron job)"""
        return ApiToken.collection.delete_many({
            "expiresAt": {"$lt": datetime.utcnow()},
            "status": "active"
        })
    
    @staticmethod
    def is_token_valid(token_hash):
        """Check if token is valid and not expired/revoked"""
        token = ApiToken.find_by_token_hash(token_hash)
        if not token:
            return False
        
        if token.get("status") != "active":
            return False
        
        if token.get("expiresAt") and datetime.utcnow() > token["expiresAt"]:
            # Auto-mark as expired
            ApiToken.collection.update_one(
                {"_id": token["_id"]},
                {"$set": {"status": "expired"}}
            )
            return False
        
        return True