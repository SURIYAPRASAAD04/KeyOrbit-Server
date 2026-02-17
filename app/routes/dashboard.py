from flask import Blueprint, request, jsonify
from app.middlewares.auth_middleware import token_required
from app.models import User, Key, ApiToken, AuditLog, Organization
from app.utils.security import get_current_ist_time
from datetime import datetime, timedelta
from bson import ObjectId

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/dashboard/stats', methods=['GET'])
@token_required
def get_dashboard_stats(current_user):
    """Get all dashboard statistics"""
    try:
        # Get full user document
        user = User.find_by_id(current_user['userId'])
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        organization_id = user.get('organizationId')
        
        # Calculate date ranges
        now = datetime.utcnow()
        today_start = datetime(now.year, now.month, now.day)
        week_ago = now - timedelta(days=7)
        month_ago = now - timedelta(days=30)
        
        # Initialize stats dictionary
        stats = {}
        
        # 1. KEY STATISTICS
        key_query = {"organizationId": ObjectId(organization_id)} if organization_id else {}
        
        # Total keys
        stats['total_keys'] = Key.collection.count_documents(key_query)
        
        # Keys by status
        pipeline = [
            {"$match": key_query},
            {"$group": {
                "_id": "$status",
                "count": {"$sum": 1}
            }}
        ]
        key_statuses = list(Key.collection.aggregate(pipeline))
        stats['keys_by_status'] = {item['_id']: item['count'] for item in key_statuses}
        
        # Keys by type
        type_pipeline = [
            {"$match": key_query},
            {"$group": {
                "_id": "$type",
                "count": {"$sum": 1}
            }}
        ]
        key_types = list(Key.collection.aggregate(type_pipeline))
        stats['keys_by_type'] = {item['_id']: item['count'] for item in key_types}
        
        # Active keys count
        stats['active_keys'] = stats['keys_by_status'].get('active', 0)
        
        # Expiring soon (within 30 days)
        expiring_soon = Key.collection.count_documents({
            **key_query,
            "status": "active",
            "expiresAt": {"$lt": now + timedelta(days=30), "$gt": now}
        })
        stats['expiring_soon'] = expiring_soon
        
        # 2. API TOKEN STATISTICS
        token_query = {"userId": ObjectId(current_user['userId'])}
        
        stats['total_tokens'] = ApiToken.collection.count_documents(token_query)
        
        # Active tokens
        stats['active_tokens'] = ApiToken.collection.count_documents({
            **token_query,
            "status": "active"
        })
        
        # Total API calls
        token_pipeline = [
            {"$match": token_query},
            {"$group": {
                "_id": None,
                "total_calls": {"$sum": "$apiCalls"}
            }}
        ]
        token_result = list(ApiToken.collection.aggregate(token_pipeline))
        stats['total_api_calls'] = token_result[0]['total_calls'] if token_result else 0
        
        # 3. OPERATIONS STATISTICS (from audit logs)
        ops_query = {"organizationId": ObjectId(organization_id)} if organization_id else {}
        
        # Operations today
        stats['operations_today'] = AuditLog.collection.count_documents({
            **ops_query,
            "timestamp": {"$gte": today_start}
        })
        
        # Operations this week
        stats['operations_week'] = AuditLog.collection.count_documents({
            **ops_query,
            "timestamp": {"$gte": week_ago}
        })
        
        # Operations this month
        stats['operations_month'] = AuditLog.collection.count_documents({
            **ops_query,
            "timestamp": {"$gte": month_ago}
        })
        
        # Operations by type
        ops_type_pipeline = [
            {"$match": {**ops_query, "timestamp": {"$gte": week_ago}}},
            {"$group": {
                "_id": "$actionType",
                "count": {"$sum": 1}
            }},
            {"$sort": {"count": -1}},
            {"$limit": 5}
        ]
        top_operations = list(AuditLog.collection.aggregate(ops_type_pipeline))
        stats['top_operations'] = [
            {"type": item['_id'], "count": item['count']} 
            for item in top_operations
        ]
        
        # Success rate
        success_count = AuditLog.collection.count_documents({
            **ops_query,
            "timestamp": {"$gte": week_ago},
            "actionType": {"$not": {"$regex": "FAILED|DENIED|ERROR"}}
        })
        total_ops = stats['operations_week']
        stats['success_rate'] = round((success_count / total_ops * 100), 1) if total_ops > 0 else 100
        
        # 4. RECENT ACTIVITY
        recent_activities = list(AuditLog.collection.find(ops_query)
                                 .sort("timestamp", -1)
                                 .limit(10))
        
        stats['recent_activity'] = []
        for activity in recent_activities:
            # Get user info
            user_info = None
            if activity.get('userId'):
                activity_user = User.find_by_id(activity['userId'])
                if activity_user:
                    user_info = {
                        "name": f"{activity_user.get('firstName', '')} {activity_user.get('lastName', '')}".strip(),
                        "email": activity_user.get('email', '')
                    }
            
            stats['recent_activity'].append({
                "id": str(activity['_id']),
                "timestamp": activity['timestamp'].isoformat(),
                "action": activity['actionType'],
                "user": user_info['name'] if user_info else "System",
                "user_email": user_info['email'] if user_info else None,
                "ip": activity.get('ipAddress'),
                "metadata": activity.get('metadata', {})
            })
        
        # 5. SECURITY ALERTS
        # Failed operations in last 24h
        failed_24h = AuditLog.collection.count_documents({
            **ops_query,
            "timestamp": {"$gte": now - timedelta(days=1)},
            "actionType": {"$regex": "FAILED|DENIED|ERROR"}
        })
        
        # Expired keys
        expired_keys = Key.collection.count_documents({
            **key_query,
            "status": "expired"
        })
        
        # Revoked keys
        revoked_keys = Key.collection.count_documents({
            **key_query,
            "status": "revoked"
        })
        
        stats['alerts'] = {
            "failed_operations_24h": failed_24h,
            "expired_keys": expired_keys,
            "revoked_keys": revoked_keys,
            "total_alerts": failed_24h + expired_keys + revoked_keys
        }
        
        # 6. SYSTEM STATUS
        stats['system_status'] = {
            "database": "healthy",
            "api": "healthy",
            "pqc_service": "healthy",
            "last_check": get_current_ist_time().isoformat()
        }
        
        # 7. USER INFO
        stats['user'] = {
            "name": f"{user.get('firstName', '')} {user.get('lastName', '')}".strip(),
            "email": user.get('email'),
            "role": user.get('role'),
            "organization": user.get('organization', {}).get('name', 'No Organization'),
            "joined": user.get('createdAt').isoformat() if user.get('createdAt') else None
        }
        
        return jsonify({
            "success": True,
            "stats": stats,
            "timestamp": get_current_ist_time().isoformat()
        }), 200
        
    except Exception as e:
        print(f"Error getting dashboard stats: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route('/dashboard/activity', methods=['GET'])
@token_required
def get_activity_timeline(current_user):
    """Get activity timeline for charts"""
    try:
        user = User.find_by_id(current_user['userId'])
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        organization_id = user.get('organizationId')
        days = int(request.args.get('days', 7))
        
        start_date = datetime.utcnow() - timedelta(days=days)
        
        # Get daily activity counts
        pipeline = [
            {
                "$match": {
                    "organizationId": ObjectId(organization_id),
                    "timestamp": {"$gte": start_date}
                }
            },
            {
                "$group": {
                    "_id": {
                        "year": {"$year": "$timestamp"},
                        "month": {"$month": "$timestamp"},
                        "day": {"$dayOfMonth": "$timestamp"}
                    },
                    "count": {"$sum": 1}
                }
            },
            {"$sort": {"_id.year": 1, "_id.month": 1, "_id.day": 1}}
        ]
        
        results = list(AuditLog.collection.aggregate(pipeline))
        
        # Format for chart
        activity_data = []
        for r in results:
            date_str = f"{r['_id']['year']}-{r['_id']['month']:02d}-{r['_id']['day']:02d}"
            activity_data.append({
                "date": date_str,
                "count": r["count"]
            })
        
        return jsonify({
            "success": True,
            "activity": activity_data,
            "period_days": days
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route('/dashboard/quick-actions', methods=['GET'])
@token_required
def get_quick_actions(current_user):
    """Get available quick actions based on user role"""
    try:
        user = User.find_by_id(current_user['userId'])
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        role = user.get('role', 'user')
        
        # Define actions based on role
        all_actions = [
            {
                "id": "generate_key",
                "title": "Generate New Key",
                "description": "Create a post-quantum cryptographic key",
                "icon": "Plus",
                "path": "/key-management?action=generate",
                "color": "primary",
                "roles": ["admin", "administrator", "manager", "developer"]
            },
            {
                "id": "invite_user",
                "title": "Invite Team Member",
                "description": "Add a new user to your organization",
                "icon": "UserPlus",
                "path": "/user-management?action=invite",
                "color": "secondary",
                "roles": ["admin", "administrator", "manager"]
            },
            {
                "id": "create_token",
                "title": "Create API Token",
                "description": "Generate a new API access token",
                "icon": "Key",
                "path": "/api-tokens?action=create",
                "color": "accent",
                "roles": ["admin", "administrator", "manager", "developer"]
            },
            {
                "id": "view_audit",
                "title": "View Audit Logs",
                "description": "Review security events and activities",
                "icon": "FileText",
                "path": "/audit-logs",
                "color": "info",
                "roles": ["admin", "administrator", "manager", "auditor"]
            },
            {
                "id": "rotate_keys",
                "title": "Rotate Expiring Keys",
                "description": "Review and rotate keys expiring soon",
                "icon": "RotateCw",
                "path": "/key-management?filter=expiring",
                "color": "warning",
                "roles": ["admin", "administrator", "manager"]
            },
            {
                "id": "compliance_report",
                "title": "Generate Compliance Report",
                "description": "Create SOX, HIPAA, or GDPR reports",
                "icon": "FileBarChart",
                "path": "/audit-logs?tab=compliance",
                "color": "success",
                "roles": ["admin", "administrator", "auditor"]
            }
        ]
        
        # Filter actions by user role
        available_actions = [
            action for action in all_actions 
            if role in action['roles']
        ]
        
        return jsonify({
            "success": True,
            "actions": available_actions
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@dashboard_bp.route('/dashboard/alerts', methods=['GET'])
@token_required
def get_security_alerts(current_user):
    """Get security alerts"""
    try:
        user = User.find_by_id(current_user['userId'])
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        organization_id = user.get('organizationId')
        now = datetime.utcnow()
        
        alerts = []
        
        # 1. Expiring keys (within 7 days)
        expiring_7d = list(Key.collection.find({
            "organizationId": ObjectId(organization_id),
            "status": "active",
            "expiresAt": {"$lt": now + timedelta(days=7), "$gt": now}
        }).sort("expiresAt", 1).limit(5))
        
        for key in expiring_7d:
            days_left = (key['expiresAt'] - now).days
            alerts.append({
                "id": f"expire_{key['_id']}",
                "type": "warning",
                "title": "Key Expiring Soon",
                "message": f"Key '{key.get('name', 'Unnamed')}' will expire in {days_left} days",
                "timestamp": now.isoformat(),
                "resource_id": str(key['_id']),
                "resource_type": "key",
                "action_path": f"/key-management/{key['_id']}"
            })
        
        # 2. Failed login attempts (last hour)
        failed_logins = AuditLog.collection.count_documents({
            "organizationId": ObjectId(organization_id),
            "actionType": "LOGIN_FAILED",
            "timestamp": {"$gte": now - timedelta(hours=1)}
        })
        
        if failed_logins > 5:
            alerts.append({
                "id": "failed_logins",
                "type": "critical" if failed_logins > 20 else "warning",
                "title": "Multiple Failed Login Attempts",
                "message": f"{failed_logins} failed login attempts in the last hour",
                "timestamp": now.isoformat(),
                "count": failed_logins,
                "action_path": "/audit-logs?filter=failed"
            })
        
        # 3. Revoked keys (last 24h)
        revoked_24h = Key.collection.count_documents({
            "organizationId": ObjectId(organization_id),
            "status": "revoked",
            "revokedAt": {"$gte": now - timedelta(days=1)}
        })
        
        if revoked_24h > 0:
            alerts.append({
                "id": "revoked_keys",
                "type": "critical",
                "title": "Keys Revoked",
                "message": f"{revoked_24h} key(s) were revoked in the last 24 hours",
                "timestamp": now.isoformat(),
                "count": revoked_24h,
                "action_path": "/key-management?status=revoked"
            })
        
        # 4. API token expiring
        tokens_expiring = ApiToken.collection.count_documents({
            "userId": ObjectId(current_user['userId']),
            "status": "active",
            "expiresAt": {"$lt": now + timedelta(days=7), "$gt": now}
        })
        
        if tokens_expiring > 0:
            alerts.append({
                "id": "tokens_expiring",
                "type": "info",
                "title": "API Tokens Expiring",
                "message": f"{tokens_expiring} API token(s) will expire within 7 days",
                "timestamp": now.isoformat(),
                "count": tokens_expiring,
                "action_path": "/api-tokens"
            })
        
        return jsonify({
            "success": True,
            "alerts": alerts,
            "total": len(alerts)
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500