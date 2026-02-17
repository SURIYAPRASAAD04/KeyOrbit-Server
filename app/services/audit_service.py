from datetime import datetime
from bson import ObjectId
from app.models import AuditLog, User

class AuditService:
    """Service for handling audit log operations"""
    
    @staticmethod
    def format_audit_logs(logs, include_all_fields=False):
        """Format audit logs for API response"""
        formatted_logs = []
        
        for log in logs:
            # Get user info if available
            user_info = None
            if log.get('userId'):
                user = User.find_by_id(log['userId'])
                if user:
                    user_info = {
                        "id": str(user["_id"]),
                        "name": f"{user.get('firstName', '')} {user.get('lastName', '')}".strip(),
                        "email": user.get('email', ''),
                        "initials": AuditService._get_initials(user)
                    }
            
            # Determine outcome based on action type
            outcome = AuditService._determine_outcome(log.get('actionType', ''))
            
            # Get severity
            severity = AuditService._determine_severity(log.get('actionType', ''))
            
            # Format log
            formatted_log = {
                "id": str(log["_id"]),
                "timestamp": log.get("timestamp").isoformat() if log.get("timestamp") else None,
                "event_type": log.get("actionType"),
                "event_type_display": AuditService._format_event_type(log.get("actionType", '')),
                "user": user_info["name"] if user_info else "System",
                "user_email": user_info["email"] if user_info else None,
                "user_id": str(log.get("userId")) if log.get("userId") else None,
                "user_initials": user_info["initials"] if user_info else "S",
                "action": AuditService._format_action(log.get("actionType", ''), log.get("metadata", {})),
                "resource_id": AuditService._extract_resource_id(log.get("metadata", {})),
                "ip_address": log.get("ipAddress"),
                "user_agent": log.get("userAgent"),
                "outcome": outcome,
                "severity": severity
            }
            
            if include_all_fields:
                # Add all metadata fields
                formatted_log.update({
                    "session_id": log.get("metadata", {}).get("session_id"),
                    "request_id": log.get("metadata", {}).get("request_id"),
                    "duration": log.get("metadata", {}).get("duration"),
                    "response_code": log.get("metadata", {}).get("response_code"),
                    "details": log.get("metadata", {}),
                    "organization_id": str(log.get("organizationId")) if log.get("organizationId") else None
                })
            
            formatted_logs.append(formatted_log)
        
        return formatted_logs
    
    @staticmethod
    def format_recent_events(logs):
        """Format logs for real-time event stream"""
        events = []
        
        for log in logs[:20]:  # Limit to 20 most recent
            # Get user info
            user_name = "System"
            if log.get('userId'):
                user = User.find_by_id(log['userId'])
                if user:
                    user_name = f"{user.get('firstName', '')} {user.get('lastName', '')}".strip()
            
            event = {
                "id": str(log["_id"]),
                "timestamp": log.get("timestamp").isoformat() if log.get("timestamp") else None,
                "event_type": log.get("actionType"),
                "event_type_display": AuditService._format_event_type(log.get("actionType", '')),
                "user": user_name,
                "action": AuditService._format_action(log.get("actionType", ''), log.get("metadata", {})),
                "outcome": AuditService._determine_outcome(log.get("actionType", '')),
                "severity": AuditService._determine_severity(log.get("actionType", ''))
            }
            
            events.append(event)
        
        return events
    
    @staticmethod
    def log_event(user_id, organization_id, action_type, metadata=None, ip_address=None, user_agent=None):
        """Create a new audit log entry"""
        try:
            log_data = {
                "userId": ObjectId(user_id) if user_id else None,
                "organizationId": ObjectId(organization_id) if organization_id else None,
                "actionType": action_type,
                "ipAddress": ip_address,
                "userAgent": user_agent,
                "metadata": metadata or {},
                "timestamp": datetime.utcnow()
            }
            
            result = AuditLog.collection.insert_one(log_data)
            return str(result.inserted_id)
            
        except Exception as e:
            print(f"Error logging audit event: {str(e)}")
            return None
    
    @staticmethod
    def _format_event_type(event_type):
        """Format event type for display"""
        # Remove common prefixes and format
        event_type = event_type.replace('KEY_', '').replace('USER_', '').replace('AUTH_', '')
        return event_type.replace('_', ' ').title()
    
    @staticmethod
    def _format_action(action_type, metadata):
        """Generate a human-readable action description"""
        action_map = {
            'KEY_GENERATED': 'Generated new key',
            'KEY_ROTATED': 'Rotated key',
            'KEY_REVOKED': 'Revoked key',
            'KEY_DELETED': 'Deleted key',
            'KEY_ENCAPSULATE': 'Performed key encapsulation',
            'KEY_DECAPSULATE': 'Performed key decapsulation',
            'KEY_SIGN': 'Signed message',
            'KEY_VERIFY': 'Verified signature',
            'USER_LOGIN': 'User login',
            'USER_LOGOUT': 'User logout',
            'USER_INVITED': 'Invited user',
            'USER_UPDATED': 'Updated user',
            'USER_DELETED': 'Deleted user',
            'PASSWORD_CHANGE': 'Changed password',
            'MFA_ENABLED': 'Enabled MFA',
            'MFA_DISABLED': 'Disabled MFA',
            'API_TOKEN_CREATED': 'Created API token',
            'API_TOKEN_REVOKED': 'Revoked API token',
            'POLICY_CREATED': 'Created policy',
            'POLICY_UPDATED': 'Updated policy',
            'POLICY_DELETED': 'Deleted policy',
            'ACCESS_DENIED': 'Access denied'
        }
        
        base_action = action_map.get(action_type, action_type.replace('_', ' ').lower())
        
        # Add resource name if available
        if metadata and 'key_name' in metadata:
            return f"{base_action}: {metadata['key_name']}"
        elif metadata and 'email' in metadata:
            return f"{base_action}: {metadata['email']}"
        elif metadata and 'name' in metadata:
            return f"{base_action}: {metadata['name']}"
        
        return base_action
    
    @staticmethod
    def _extract_resource_id(metadata):
        """Extract resource ID from metadata"""
        if not metadata:
            return None
        
        # Look for common ID fields
        for field in ['key_id', 'keyId', 'user_id', 'userId', 'token_id', 'policy_id']:
            if field in metadata:
                return metadata[field]
        
        return None
    
    @staticmethod
    def _determine_outcome(action_type):
        """Determine outcome based on action type"""
        failure_indicators = ['FAILED', 'DENIED', 'ERROR', 'REVOKED']
        
        for indicator in failure_indicators:
            if indicator in action_type.upper():
                return 'failure'
        
        warning_indicators = ['WARNING', 'EXPIRED', 'ROTATED']
        for indicator in warning_indicators:
            if indicator in action_type.upper():
                return 'warning'
        
        return 'success'
    
    @staticmethod
    def _determine_severity(action_type):
        """Determine severity based on action type"""
        critical_actions = ['KEY_REVOKED', 'KEY_DELETED', 'ACCESS_DENIED', 'FAILED']
        warning_actions = ['KEY_ROTATED', 'KEY_EXPIRED', 'PASSWORD_CHANGE', 'MFA_DISABLED']
        
        action_upper = action_type.upper()
        
        for action in critical_actions:
            if action in action_upper:
                return 'critical'
        
        for action in warning_actions:
            if action in action_upper:
                return 'warning'
        
        return 'info'
    
    @staticmethod
    def _get_initials(user):
        """Get user initials from first and last name"""
        first = user.get('firstName', '')
        last = user.get('lastName', '')
        
        if first and last:
            return (first[0] + last[0]).upper()
        elif first:
            return first[:2].upper()
        elif user.get('email'):
            return user['email'][:2].upper()
        
        return 'U'