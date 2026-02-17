from datetime import datetime, timedelta
from bson import ObjectId
from app.models import Key, AuditLog
from app.utils.security import get_current_ist_time

class KeyService:
    @staticmethod
    def format_key_for_response(key, include_private=False):
        """Format key for API response"""
        if not key:
            return None
        
        formatted = {
            "id": str(key["_id"]),
            "keyId": key.get("keyId"),
            "name": key.get("name"),
            "algorithm": key.get("algorithm"),
            "algorithm_full": key.get("algorithm_full"),
            "type": key.get("type"),
            "purpose": key.get("purpose"),
            "status": key.get("status"),
            "publicKey": key.get("publicKey"),
            "keySize": key.get("keySize"),
            "securityLevel": key.get("securityLevel"),
            "generationTime": key.get("generationTime"),
            "createdAt": key.get("createdAt").isoformat() if key.get("createdAt") else None,
            "updatedAt": key.get("updatedAt").isoformat() if key.get("updatedAt") else None,
            "expiresAt": key.get("expiresAt").isoformat() if key.get("expiresAt") else None,
            "lastUsed": key.get("lastUsed").isoformat() if key.get("lastUsed") else None,
            "version": key.get("version", 1),
            "usageCount": key.get("usageCount", 0),
            "description": key.get("metadata", {}).get("description", ""),
            "tags": key.get("tags", []),
            "department": key.get("metadata", {}).get("department", ""),
            "createdBy": key.get("metadata", {}).get("createdBy", "")
        }
        
        # Include private key only if requested
        if include_private and key.get("privateKey"):
            formatted["privateKey"] = key.get("privateKey")
        
        # Include revocation info if revoked
        if key.get("status") == "revoked":
            formatted["revokedAt"] = key.get("revokedAt").isoformat() if key.get("revokedAt") else None
            formatted["revocationReason"] = key.get("revocationReason", "")
        
        # Include rotation info if rotated
        if key.get("status") == "rotated":
            formatted["rotatedAt"] = key.get("rotatedAt").isoformat() if key.get("rotatedAt") else None
            formatted["nextVersionId"] = key.get("nextVersionId")
            formatted["previousVersionId"] = key.get("previousVersionId")
        
        return formatted
    
    @staticmethod
    def get_key_usage_history(key_id, limit=20):
        """Get usage history for a key from audit logs"""
        try:
            key = Key.find_by_id(key_id)
            if not key:
                return []
            
            logs = list(AuditLog.collection.find({
                "metadata.key_id": key.get("keyId"),
                "actionType": {"$in": ["KEY_ENCAPSULATE", "KEY_DECAPSULATE", "KEY_SIGN", "KEY_VERIFY"]}
            }).sort("timestamp", -1).limit(limit))
            
            history = []
            for log in logs:
                history.append({
                    "action": log.get("actionType"),
                    "timestamp": log.get("timestamp").isoformat() if log.get("timestamp") else None,
                    "ipAddress": log.get("ipAddress"),
                    "userAgent": log.get("userAgent"),
                    "success": True
                })
            
            return history
            
        except Exception as e:
            print(f"Error getting key usage history: {str(e)}")
            return []