from datetime import datetime
from bson import ObjectId
from app.models import db
from pytz import timezone

IST = timezone('Asia/Kolkata')

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