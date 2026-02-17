from flask import Blueprint, request, jsonify
from app.middlewares.auth_middleware import token_required, role_required
from app.services.pqc_service import PQCService
from app.services.key_service import KeyService  # Fixed import
from app.models import Key, AuditLog
from app.utils.security import get_current_ist_time
from datetime import datetime, timedelta
from bson import ObjectId

keys_bp = Blueprint('keys', __name__)

# =====================================================
# KEY GENERATION ENDPOINTS
# =====================================================

@keys_bp.route('/keys/generate/ml-kem', methods=['POST'])
@token_required
def generate_ml_kem_key(current_user):
    """Generate ML-KEM (Kyber) keypair"""
    try:
        data = request.get_json() or {}
        
        # Validate algorithm
        algorithm = data.get('algorithm', 'ml-kem-768').lower()
        valid_algorithms = ['ml-kem-512', 'ml-kem-768', 'ml-kem-1024']
        if algorithm not in valid_algorithms:
            return jsonify({
                "error": f"Invalid algorithm. Supported: {', '.join(valid_algorithms)}"
            }), 400
        
        # Validate name
        if not data.get('name'):
            return jsonify({"error": "Key name is required"}), 400
        
        # Prepare metadata
        metadata = {
            "name": data['name'],
            "description": data.get('description', ''),
            "tags": data.get('tags', []),
            "expirationDays": data.get('expirationDays', 365),
            "purpose": data.get('purpose', 'key_encapsulation'),
            "department": data.get('department', ''),
            "createdBy": current_user['userId']
        }
        
        # Get organization ID
        organization_id = current_user.get('organization', {}).get('id')
        
        # Generate key
        key_data, error = PQCService.generate_ml_kem_keypair(
            algorithm=algorithm,
            user_id=current_user['userId'],
            organization_id=organization_id,
            metadata=metadata
        )
        
        if error:
            return jsonify({"error": error}), 500
        
        # Save to database
        result = Key.create_key(key_data)
        key_data['_id'] = str(result.inserted_id)
        
        # Log key generation
        AuditLog.log_auth_attempt(
            user_id=current_user['userId'],
            action_type="KEY_GENERATED",
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            metadata={
                "key_id": key_data['keyId'],
                "algorithm": algorithm,
                "type": "kem"
            }
        )
        
        # Remove private key from response for security
        response_data = key_data.copy()
        response_data.pop('privateKey', None)
        response_data.pop('keyHash', None)
        
        return jsonify({
            "message": "ML-KEM key generated successfully",
            "key": KeyService.format_key_for_response(response_data),
            "timestamp": get_current_ist_time().isoformat()
        }), 201
        
    except Exception as e:
        print(f"Error generating ML-KEM key: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@keys_bp.route('/keys/generate/ml-dsa', methods=['POST'])
@token_required
def generate_ml_dsa_key(current_user):
    """Generate ML-DSA (Dilithium) keypair"""
    try:
        data = request.get_json() or {}
        
        # Validate algorithm
        algorithm = data.get('algorithm', 'ml-dsa-65').lower()
        valid_algorithms = ['ml-dsa-44', 'ml-dsa-65', 'ml-dsa-87']
        if algorithm not in valid_algorithms:
            return jsonify({
                "error": f"Invalid algorithm. Supported: {', '.join(valid_algorithms)}"
            }), 400
        
        # Validate name
        if not data.get('name'):
            return jsonify({"error": "Key name is required"}), 400
        
        # Prepare metadata
        metadata = {
            "name": data['name'],
            "description": data.get('description', ''),
            "tags": data.get('tags', []),
            "expirationDays": data.get('expirationDays', 365),
            "purpose": data.get('purpose', 'digital_signature'),
            "department": data.get('department', ''),
            "createdBy": current_user['userId']
        }
        
        # Get organization ID
        organization_id = current_user.get('organization', {}).get('id')
        
        # Generate key
        key_data, error = PQCService.generate_ml_dsa_keypair(
            algorithm=algorithm,
            user_id=current_user['userId'],
            organization_id=organization_id,
            metadata=metadata
        )
        
        if error:
            return jsonify({"error": error}), 500
        
        # Save to database
        result = Key.create_key(key_data)
        key_data['_id'] = str(result.inserted_id)
        
        # Log key generation
        AuditLog.log_auth_attempt(
            user_id=current_user['userId'],
            action_type="KEY_GENERATED",
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            metadata={
                "key_id": key_data['keyId'],
                "algorithm": algorithm,
                "type": "signature"
            }
        )
        
        # Remove private key from response for security
        response_data = key_data.copy()
        response_data.pop('privateKey', None)
        response_data.pop('keyHash', None)
        
        return jsonify({
            "message": "ML-DSA key generated successfully",
            "key": KeyService.format_key_for_response(response_data),
            "timestamp": get_current_ist_time().isoformat()
        }), 201
        
    except Exception as e:
        print(f"Error generating ML-DSA key: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@keys_bp.route('/keys/generate/hybrid', methods=['POST'])
@token_required
def generate_hybrid_key(current_user):
    """Generate hybrid keypair (KEM + Signature)"""
    try:
        data = request.get_json() or {}
        
        # Validate algorithms
        kem_algorithm = data.get('kemAlgorithm', 'ml-kem-768').lower()
        sig_algorithm = data.get('sigAlgorithm', 'ml-dsa-65').lower()
        
        valid_kem = ['ml-kem-512', 'ml-kem-768', 'ml-kem-1024']
        valid_sig = ['ml-dsa-44', 'ml-dsa-65', 'ml-dsa-87']
        
        if kem_algorithm not in valid_kem:
            return jsonify({"error": f"Invalid KEM algorithm"}), 400
        if sig_algorithm not in valid_sig:
            return jsonify({"error": f"Invalid signature algorithm"}), 400
        
        # Validate name
        if not data.get('name'):
            return jsonify({"error": "Key name is required"}), 400
        
        # Prepare metadata
        metadata = {
            "name": data['name'],
            "description": data.get('description', ''),
            "tags": data.get('tags', []),
            "expirationDays": data.get('expirationDays', 365),
            "purpose": data.get('purpose', 'hybrid'),
            "department": data.get('department', ''),
            "createdBy": current_user['userId']
        }
        
        # Get organization ID
        organization_id = current_user.get('organization', {}).get('id')
        
        # Generate hybrid key
        result, error = PQCService.generate_hybrid_keypair(
            kem_algorithm=kem_algorithm,
            sig_algorithm=sig_algorithm,
            user_id=current_user['userId'],
            organization_id=organization_id,
            metadata=metadata
        )
        
        if error:
            return jsonify({"error": error}), 500
        
        # Save keys to database
        kem_result = Key.create_key(result['kemKey'])
        sig_result = Key.create_key(result['sigKey'])
        hybrid_result = Key.create_key(result['hybridKey'])
        
        result['kemKey']['_id'] = str(kem_result.inserted_id)
        result['sigKey']['_id'] = str(sig_result.inserted_id)
        result['hybridKey']['_id'] = str(hybrid_result.inserted_id)
        
        # Log hybrid key generation
        AuditLog.log_auth_attempt(
            user_id=current_user['userId'],
            action_type="HYBRID_KEY_GENERATED",
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            metadata={
                "hybrid_key_id": result['hybridKey']['keyId'],
                "kem_algorithm": kem_algorithm,
                "sig_algorithm": sig_algorithm
            }
        )
        
        # Remove private keys from response
        response_data = {
            "hybridKey": KeyService.format_key_for_response(result['hybridKey']),
            "kemKey": KeyService.format_key_for_response({k: v for k, v in result['kemKey'].items() if k != 'privateKey'}),
            "sigKey": KeyService.format_key_for_response({k: v for k, v in result['sigKey'].items() if k != 'privateKey'})
        }
        
        return jsonify({
            "message": "Hybrid key generated successfully",
            "keys": response_data,
            "timestamp": get_current_ist_time().isoformat()
        }), 201
        
    except Exception as e:
        print(f"Error generating hybrid key: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# =====================================================
# KEY MANAGEMENT ENDPOINTS
# =====================================================

@keys_bp.route('/keys', methods=['GET'])
@token_required
def get_keys(current_user):
    """Get all keys for the current user/organization"""
    try:
        # Get query parameters
        include_revoked = request.args.get('include_revoked', 'false').lower() == 'true'
        key_type = request.args.get('type')
        status = request.args.get('status')
        algorithm = request.args.get('algorithm')
        
        # Get organization ID
        organization_id = current_user.get('organization', {}).get('id')
        if not organization_id:
            return jsonify({"keys": [], "total": 0, "stats": {}}), 200
        
        # Build query
        query = {"organizationId": ObjectId(organization_id)}
        if not include_revoked:
            query["status"] = {"$nin": ["revoked", "deleted"]}
        if key_type:
            query["type"] = key_type
        if status:
            query["status"] = status
        if algorithm:
            query["algorithm"] = algorithm
        
        # Get keys
        keys = list(Key.collection.find(query).sort("createdAt", -1))
        
        # Format response
        formatted_keys = []
        for key in keys:
            formatted_key = KeyService.format_key_for_response(key)
            formatted_keys.append(formatted_key)
        
        # Get stats
        stats = Key.get_key_stats(organization_id=organization_id)
        
        return jsonify({
            "keys": formatted_keys,
            "total": len(formatted_keys),
            "stats": stats,
            "timestamp": get_current_ist_time().isoformat()
        }), 200
        
    except Exception as e:
        print(f"Error getting keys: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@keys_bp.route('/keys/<key_id>', methods=['GET'])
@token_required
def get_key_details(current_user, key_id):
    """Get details of a specific key"""
    try:
        # Find key
        key = Key.find_by_id(key_id)
        if not key:
            return jsonify({"error": "Key not found"}), 404
        
        # Check permission
        organization_id = current_user.get('organization', {}).get('id')
        if str(key.get('organizationId')) != organization_id:
            return jsonify({"error": "Access denied"}), 403
        
        # Format response
        formatted_key = KeyService.format_key_for_response(key, include_private=False)
        
        # Get key usage history
        usage_history = KeyService.get_key_usage_history(key_id, limit=10)
        
        # Get related keys (for hybrid)
        related_keys = []
        if key.get('type') == 'hybrid':
            if key.get('kemKeyId'):
                kem_key = Key.find_by_key_id(key['kemKeyId'])
                if kem_key:
                    related_keys.append(KeyService.format_key_for_response(kem_key))
            if key.get('sigKeyId'):
                sig_key = Key.find_by_key_id(key['sigKeyId'])
                if sig_key:
                    related_keys.append(KeyService.format_key_for_response(sig_key))
        
        return jsonify({
            "key": formatted_key,
            "usageHistory": usage_history,
            "relatedKeys": related_keys,
            "timestamp": get_current_ist_time().isoformat()
        }), 200
        
    except Exception as e:
        print(f"Error getting key details: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@keys_bp.route('/keys/<key_id>/revoke', methods=['POST'])
@token_required
def revoke_key(current_user, key_id):
    """Revoke a key"""
    try:
        # Check if request has JSON content type
        if request.is_json:
            data = request.get_json() or {}
        else:
            data = {}
            
        reason = data.get('reason', '')
        
        # Find key
        key = Key.find_by_id(key_id)
        if not key:
            return jsonify({"error": "Key not found"}), 404
        
        # Check permission
        organization_id = current_user.get('organization', {}).get('id')
        if str(key.get('organizationId')) != organization_id:
            return jsonify({"error": "Access denied"}), 403
        
        # Check if already revoked
        if key.get('status') == 'revoked':
            return jsonify({"error": "Key is already revoked"}), 400
        
        # Revoke key
        result = Key.revoke_key(key_id, reason)
        
        if result.modified_count == 0:
            return jsonify({"error": "Failed to revoke key"}), 500
        
        # Log revocation
        AuditLog.log_auth_attempt(
            user_id=current_user['userId'],
            action_type="KEY_REVOKED",
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            metadata={
                "key_id": key.get('keyId'),
                "key_name": key.get('name'),
                "reason": reason
            }
        )
        
        return jsonify({
            "message": "Key revoked successfully",
            "key_id": key.get('keyId'),
            "status": "revoked",
            "timestamp": get_current_ist_time().isoformat()
        }), 200
        
    except Exception as e:
        print(f"Error revoking key: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@keys_bp.route('/keys/<key_id>/delete', methods=['DELETE'])
@token_required
def delete_key(current_user, key_id):
    """Soft delete a key"""
    try:
        # Find key
        key = Key.find_by_id(key_id)
        if not key:
            return jsonify({"error": "Key not found"}), 404
        
        # Check permission - only admins can delete keys
        if current_user['role'] not in ['admin', 'administrator', 'manager']:
            return jsonify({"error": "Insufficient permissions"}), 403
        
        # Check organization
        organization_id = current_user.get('organization', {}).get('id')
        if str(key.get('organizationId')) != organization_id:
            return jsonify({"error": "Access denied"}), 403
        
        # Delete key
        result = Key.delete_key(key_id)
        
        if result.modified_count == 0:
            return jsonify({"error": "Failed to delete key"}), 500
        
        # Log deletion
        AuditLog.log_auth_attempt(
            user_id=current_user['userId'],
            action_type="KEY_DELETED",
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            metadata={
                "key_id": key.get('keyId'),
                "key_name": key.get('name')
            }
        )
        
        return jsonify({
            "message": "Key deleted successfully",
            "key_id": key.get('keyId'),
            "timestamp": get_current_ist_time().isoformat()
        }), 200
        
    except Exception as e:
        print(f"Error deleting key: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@keys_bp.route('/keys/<key_id>/rotate', methods=['POST'])
@token_required
def rotate_key(current_user, key_id):
    """Rotate a key (create new version)"""
    try:
        # Check if request has JSON content type
        if request.is_json:
            data = request.get_json() or {}
        else:
            data = {}
        
        # Find key
        old_key = Key.find_by_id(key_id)
        if not old_key:
            return jsonify({"error": "Key not found"}), 404
        
        # Check permission
        organization_id = current_user.get('organization', {}).get('id')
        if str(old_key.get('organizationId')) != organization_id:
            return jsonify({"error": "Access denied"}), 403
        
        # Check if key can be rotated
        if old_key.get('status') not in ['active', 'expired']:
            return jsonify({"error": f"Cannot rotate key with status: {old_key.get('status')}"}), 400
        
        # Generate new key based on type
        metadata = {
            "name": data.get('name', f"{old_key.get('name')} (Rotated)"),
            "description": data.get('description', old_key.get('description', '')),
            "tags": old_key.get('tags', []),
            "expirationDays": data.get('expirationDays', 365),
            "purpose": old_key.get('purpose'),
            "department": old_key.get('department', ''),
            "createdBy": current_user['userId']
        }
        
        new_key_data = None
        if old_key.get('type') == 'kem':
            new_key_data, error = PQCService.generate_ml_kem_keypair(
                algorithm=old_key.get('algorithm'),
                user_id=current_user['userId'],
                organization_id=organization_id,
                metadata=metadata
            )
        elif old_key.get('type') == 'signature':
            new_key_data, error = PQCService.generate_ml_dsa_keypair(
                algorithm=old_key.get('algorithm'),
                user_id=current_user['userId'],
                organization_id=organization_id,
                metadata=metadata
            )
        else:
            return jsonify({"error": "Key rotation not supported for this key type"}), 400
        
        if error:
            return jsonify({"error": error}), 500
        
        # Perform rotation
        result, error = Key.rotate_key(key_id, new_key_data)
        
        if error:
            return jsonify({"error": error}), 500
        
        # Log rotation
        AuditLog.log_auth_attempt(
            user_id=current_user['userId'],
            action_type="KEY_ROTATED",
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            metadata={
                "old_key_id": old_key.get('keyId'),
                "new_key_id": new_key_data['keyId'],
                "key_name": old_key.get('name')
            }
        )
        
        # Get new key
        new_key = Key.find_by_id(result.inserted_id)
        formatted_key = KeyService.format_key_for_response(new_key, include_private=False)
        
        return jsonify({
            "message": "Key rotated successfully",
            "old_key_id": old_key.get('keyId'),
            "new_key": formatted_key,
            "timestamp": get_current_ist_time().isoformat()
        }), 200
        
    except Exception as e:
        print(f"Error rotating key: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# =====================================================
# BULK OPERATIONS
# =====================================================

@keys_bp.route('/keys/bulk/revoke', methods=['POST'])
@token_required
def bulk_revoke_keys(current_user):
    """Bulk revoke multiple keys"""
    try:
        data = request.get_json()
        
        if 'keyIds' not in data or not data['keyIds']:
            return jsonify({"error": "Key IDs are required"}), 400
        
        reason = data.get('reason', 'Bulk revocation')
        
        organization_id = current_user.get('organization', {}).get('id')
        
        success_count = 0
        failed_keys = []
        
        for key_id in data['keyIds']:
            try:
                key = Key.find_by_id(key_id)
                if not key:
                    failed_keys.append({"id": key_id, "error": "Key not found"})
                    continue
                
                if str(key.get('organizationId')) != organization_id:
                    failed_keys.append({"id": key_id, "error": "Access denied"})
                    continue
                
                result = Key.revoke_key(key_id, reason)
                if result.modified_count > 0:
                    success_count += 1
                    
                    # Log individual revocation
                    AuditLog.log_auth_attempt(
                        user_id=current_user['userId'],
                        action_type="KEY_REVOKED",
                        ip_address=request.remote_addr,
                        user_agent=request.headers.get('User-Agent'),
                        metadata={
                            "key_id": key.get('keyId'),
                            "key_name": key.get('name'),
                            "bulk": True
                        }
                    )
                else:
                    failed_keys.append({"id": key_id, "error": "Revocation failed"})
                    
            except Exception as e:
                failed_keys.append({"id": key_id, "error": str(e)})
        
        # Log bulk action
        AuditLog.log_auth_attempt(
            user_id=current_user['userId'],
            action_type="BULK_KEY_REVOKE",
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            metadata={
                "total": len(data['keyIds']),
                "success": success_count,
                "failed": len(failed_keys)
            }
        )
        
        return jsonify({
            "message": f"Bulk revocation completed: {success_count} keys revoked",
            "success_count": success_count,
            "failed_count": len(failed_keys),
            "failed_keys": failed_keys,
            "timestamp": get_current_ist_time().isoformat()
        }), 200
        
    except Exception as e:
        print(f"Error in bulk revoke: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@keys_bp.route('/keys/bulk/delete', methods=['DELETE'])
@token_required
def bulk_delete_keys(current_user):
    """Bulk delete multiple keys (admin only)"""
    try:
        data = request.get_json()
        
        if 'keyIds' not in data or not data['keyIds']:
            return jsonify({"error": "Key IDs are required"}), 400
        
        organization_id = current_user.get('organization', {}).get('id')
        
        success_count = 0
        failed_keys = []
        
        for key_id in data['keyIds']:
            try:
                key = Key.find_by_id(key_id)
                if not key:
                    failed_keys.append({"id": key_id, "error": "Key not found"})
                    continue
                
                if str(key.get('organizationId')) != organization_id:
                    failed_keys.append({"id": key_id, "error": "Access denied"})
                    continue
                
                result = Key.delete_key(key_id)
                if result.modified_count > 0:
                    success_count += 1
                    
                    # Log individual deletion
                    AuditLog.log_auth_attempt(
                        user_id=current_user['userId'],
                        action_type="KEY_DELETED",
                        ip_address=request.remote_addr,
                        user_agent=request.headers.get('User-Agent'),
                        metadata={
                            "key_id": key.get('keyId'),
                            "key_name": key.get('name'),
                            "bulk": True
                        }
                    )
                else:
                    failed_keys.append({"id": key_id, "error": "Deletion failed"})
                    
            except Exception as e:
                failed_keys.append({"id": key_id, "error": str(e)})
        
        # Log bulk action
        AuditLog.log_auth_attempt(
            user_id=current_user['userId'],
            action_type="BULK_KEY_DELETE",
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            metadata={
                "total": len(data['keyIds']),
                "success": success_count,
                "failed": len(failed_keys)
            }
        )
        
        return jsonify({
            "message": f"Bulk deletion completed: {success_count} keys deleted",
            "success_count": success_count,
            "failed_count": len(failed_keys),
            "failed_keys": failed_keys,
            "timestamp": get_current_ist_time().isoformat()
        }), 200
        
    except Exception as e:
        print(f"Error in bulk delete: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# =====================================================
# KEY STATISTICS AND METRICS
# =====================================================

@keys_bp.route('/keys/stats', methods=['GET'])
@token_required
def get_key_stats(current_user):
    """Get key statistics"""
    try:
        organization_id = current_user.get('organization', {}).get('id')
        if not organization_id:
            return jsonify({"stats": {}}), 200
        
        stats = Key.get_key_stats(organization_id=organization_id)
        
        # Get expiring soon count (within 30 days)
        now = datetime.now()
        thirty_days = now + timedelta(days=30)
        
        expiring_soon = Key.collection.count_documents({
            "organizationId": ObjectId(organization_id),
            "status": "active",
            "expiresAt": {"$gt": now, "$lt": thirty_days}
        })
        
        stats["expiringSoon"] = expiring_soon
        
        # Get usage statistics
        usage_pipeline = [
            {"$match": {"organizationId": ObjectId(organization_id), "status": "active"}},
            {"$group": {
                "_id": None,
                "totalUsage": {"$sum": "$usageCount"},
                "avgUsage": {"$avg": "$usageCount"}
            }}
        ]
        
        usage_result = list(Key.collection.aggregate(usage_pipeline))
        if usage_result:
            stats["totalUsage"] = usage_result[0].get("totalUsage", 0)
            stats["avgUsage"] = round(usage_result[0].get("avgUsage", 0), 2)
        
        return jsonify({
            "stats": stats,
            "timestamp": get_current_ist_time().isoformat()
        }), 200
        
    except Exception as e:
        print(f"Error getting key stats: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# =====================================================
# ALGORITHM INFORMATION
# =====================================================

@keys_bp.route('/keys/algorithms', methods=['GET'])
def get_algorithms():
    """Get supported algorithms"""
    return jsonify({
        "kem": [
            {"id": "ml-kem-512", "name": "ML-KEM-512", "security": "128-bit", "type": "kem"},
            {"id": "ml-kem-768", "name": "ML-KEM-768", "security": "192-bit", "type": "kem"},
            {"id": "ml-kem-1024", "name": "ML-KEM-1024", "security": "256-bit", "type": "kem"}
        ],
        "signature": [
            {"id": "ml-dsa-44", "name": "ML-DSA-44", "security": "128-bit", "type": "signature"},
            {"id": "ml-dsa-65", "name": "ML-DSA-65", "security": "192-bit", "type": "signature"},
            {"id": "ml-dsa-87", "name": "ML-DSA-87", "security": "256-bit", "type": "signature"}
        ],
        "timestamp": get_current_ist_time().isoformat()
    }), 200