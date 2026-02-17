from flask import Blueprint, request, jsonify
from app.middlewares.auth_middleware import token_required, role_required
from app.services.audit_service import AuditService
from app.models import User, AuditLog
from app.utils.security import get_current_ist_time
from datetime import datetime, timedelta
from bson import ObjectId

audit_bp = Blueprint('audit', __name__)

@audit_bp.route('/audit/logs', methods=['GET'])
@token_required
def get_audit_logs(current_user):
    """Get audit logs for the user's organization"""
    try:
        # Get the full user document to get organizationId
        user = User.find_by_id(current_user['userId'])
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Get organizationId from user document
        organization_id = user.get('organizationId')
        
        # If user has no organization, return empty list
        if not organization_id:
            print(f"User {current_user['userId']} has no organization")
            return jsonify({
                "logs": [],
                "total": 0,
                "filters": {
                    "event_types": [],
                    "users": []
                }
            }), 200
        
        print(f"Fetching logs for organization: {organization_id}")
        
        # Get query parameters
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        event_type = request.args.get('event_type')
        user_id = request.args.get('user_id')
        outcome = request.args.get('outcome')
        search = request.args.get('search')
        
        # Build query - ONLY filter by organizationId
        query = {"organizationId": ObjectId(organization_id)}
        
        # Date range filter
        if start_date or end_date:
            date_query = {}
            if start_date:
                try:
                    date_query["$gte"] = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
                except:
                    date_query["$gte"] = datetime.strptime(start_date, '%Y-%m-%d')
            if end_date:
                try:
                    date_query["$lte"] = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
                except:
                    end_dt = datetime.strptime(end_date, '%Y-%m-%d')
                    date_query["$lte"] = end_dt.replace(hour=23, minute=59, second=59)
            query["timestamp"] = date_query
        
        # Event type filter
        if event_type and event_type != 'all':
            query["actionType"] = event_type
        
        # User filter
        if user_id and user_id != 'all':
            if user_id == 'system':
                query["userId"] = None
            else:
                query["userId"] = ObjectId(user_id)
        
        # Search in metadata
        if search:
            query["$or"] = [
                {"metadata": {"$regex": search, "$options": "i"}},
                {"ipAddress": {"$regex": search, "$options": "i"}},
                {"userAgent": {"$regex": search, "$options": "i"}}
            ]
        
        print(f"Query: {query}")
        
        # Get total count
        total = AuditLog.collection.count_documents(query)
        print(f"Total logs found: {total}")
        
        # Get paginated logs
        skip = (page - 1) * per_page
        logs = list(AuditLog.collection.find(query)
                   .sort("timestamp", -1)
                   .skip(skip)
                   .limit(per_page))
        
        print(f"Retrieved {len(logs)} logs")
        
        # Format logs for response
        formatted_logs = AuditService.format_audit_logs(logs)
        
        # Get unique event types for filters
        event_types = AuditLog.collection.distinct("actionType", 
            {"organizationId": ObjectId(organization_id)})
        
        # Get users for filter
        users = list(User.collection.find(
            {"organizationId": ObjectId(organization_id)},
            {"_id": 1, "firstName": 1, "lastName": 1, "email": 1}
        ))
        
        formatted_users = [{
            "id": str(user["_id"]),
            "name": f"{user.get('firstName', '')} {user.get('lastName', '')}".strip() or user.get('email', ''),
            "email": user.get('email', '')
        } for user in users]
        
        # Add system user
        formatted_users.insert(0, {"id": "system", "name": "System", "email": "system"})
        
        return jsonify({
            "logs": formatted_logs,
            "total": total,
            "page": page,
            "per_page": per_page,
            "total_pages": (total + per_page - 1) // per_page,
            "filters": {
                "event_types": sorted(list(set(event_types))),
                "users": formatted_users
            },
            "organization_id": str(organization_id),
            "timestamp": get_current_ist_time().isoformat()
        }), 200
        
    except Exception as e:
        print(f"Error getting audit logs: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@audit_bp.route('/audit/stats', methods=['GET'])
@token_required
def get_audit_stats(current_user):
    """Get audit statistics for the organization"""
    try:
        user = User.find_by_id(current_user['userId'])
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        organization_id = user.get('organizationId')
        if not organization_id:
            return jsonify({"stats": {}}), 200
        
        days = int(request.args.get('days', 30))
        start_date = datetime.utcnow() - timedelta(days=days)
        
        # Get total counts
        total = AuditLog.collection.count_documents({
            "organizationId": ObjectId(organization_id),
            "timestamp": {"$gte": start_date}
        })
        
        # Get success/failure counts
        success = AuditLog.collection.count_documents({
            "organizationId": ObjectId(organization_id),
            "timestamp": {"$gte": start_date},
            "actionType": {"$not": {"$regex": "FAILED|DENIED|ERROR"}}
        })
        
        failure = AuditLog.collection.count_documents({
            "organizationId": ObjectId(organization_id),
            "timestamp": {"$gte": start_date},
            "actionType": {"$regex": "FAILED|DENIED|ERROR"}
        })
        
        # Get counts by event type
        pipeline = [
            {"$match": {
                "organizationId": ObjectId(organization_id),
                "timestamp": {"$gte": start_date}
            }},
            {"$group": {
                "_id": "$actionType",
                "count": {"$sum": 1}
            }},
            {"$sort": {"count": -1}},
            {"$limit": 10}
        ]
        
        event_types = list(AuditLog.collection.aggregate(pipeline))
        
        # Get daily activity
        daily_pipeline = [
            {"$match": {
                "organizationId": ObjectId(organization_id),
                "timestamp": {"$gte": start_date}
            }},
            {"$group": {
                "_id": {
                    "year": {"$year": "$timestamp"},
                    "month": {"$month": "$timestamp"},
                    "day": {"$dayOfMonth": "$timestamp"}
                },
                "count": {"$sum": 1}
            }},
            {"$sort": {"_id.year": 1, "_id.month": 1, "_id.day": 1}}
        ]
        
        daily_results = list(AuditLog.collection.aggregate(daily_pipeline))
        daily_activity = []
        for r in daily_results:
            date_str = f"{r['_id']['year']}-{r['_id']['month']:02d}-{r['_id']['day']:02d}"
            daily_activity.append({"date": date_str, "count": r["count"]})
        
        return jsonify({
            "total": total,
            "success": success,
            "failure": failure,
            "success_rate": round(success / max(total, 1) * 100, 1),
            "event_types": event_types,
            "daily_activity": daily_activity
        }), 200
        
    except Exception as e:
        print(f"Error getting audit stats: {str(e)}")
        return jsonify({"error": str(e)}), 500