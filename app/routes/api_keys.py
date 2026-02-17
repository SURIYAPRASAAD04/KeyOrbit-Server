from flask import Blueprint, request, jsonify, url_for
from app.middlewares.api_auth_middleware import api_token_required
from app.models import Key, User
from app.services.key_service import KeyService
from app.services.pqc_service import PQCService
from app.utils.security import get_current_ist_time
from bson import ObjectId
from datetime import datetime, timedelta

api_keys_bp = Blueprint('api_keys', __name__)

# =====================================================
# API DOCUMENTATION VIEW
# =====================================================

@api_keys_bp.route('/api/v1', methods=['GET'])
def api_documentation():
    """API documentation and health check"""
    base_url = request.url_root.rstrip('/')
    
    return jsonify({
        "service": "KeyOrbit PQC API",
        "version": "1.0.0",
        "description": "Post-Quantum Cryptography API with ML-KEM and ML-DSA algorithms",
        "endpoints": {
            "system": {
                "health": {
                    "url": "/api/v1/health",
                    "method": "GET",
                    "description": "Health check endpoint",
                    "auth_required": False
                },
                "algorithms": {
                    "url": "/api/v1/keys/algorithms",
                    "method": "GET",
                    "description": "Get supported PQC algorithms",
                    "auth_required": True,
                    "permissions": ["none"]
                }
            },
            "key_generation": {
                "generate_ml_kem": {
                    "url": "/api/v1/keys/generate/ml-kem",
                    "method": "POST",
                    "description": "Generate ML-KEM (Kyber) keypair",
                    "auth_required": True,
                    "permissions": ["key:write"],
                    "request_body": {
                        "name": "string (required) - Key name",
                        "algorithm": "string (optional) - ml-kem-512/768/1024 (default: ml-kem-768)",
                        "description": "string (optional) - Key description",
                        "purpose": "string (optional) - Key purpose",
                        "expirationDays": "integer (optional) - Days until expiration (default: 365)",
                        "tags": "array (optional) - Key tags",
                        "department": "string (optional) - Department name"
                    }
                },
                "generate_ml_dsa": {
                    "url": "/api/v1/keys/generate/ml-dsa",
                    "method": "POST",
                    "description": "Generate ML-DSA (Dilithium) keypair",
                    "auth_required": True,
                    "permissions": ["key:write"],
                    "request_body": {
                        "name": "string (required) - Key name",
                        "algorithm": "string (optional) - ml-dsa-44/65/87 (default: ml-dsa-65)",
                        "description": "string (optional) - Key description",
                        "purpose": "string (optional) - Key purpose",
                        "expirationDays": "integer (optional) - Days until expiration (default: 365)",
                        "tags": "array (optional) - Key tags",
                        "department": "string (optional) - Department name"
                    }
                },
                "generate_hybrid": {
                    "url": "/api/v1/keys/generate/hybrid",
                    "method": "POST",
                    "description": "Generate hybrid keypair (KEM + Signature)",
                    "auth_required": True,
                    "permissions": ["key:write"],
                    "request_body": {
                        "name": "string (required) - Key name",
                        "kemAlgorithm": "string (optional) - ml-kem-512/768/1024 (default: ml-kem-768)",
                        "sigAlgorithm": "string (optional) - ml-dsa-44/65/87 (default: ml-dsa-65)",
                        "description": "string (optional) - Key description",
                        "purpose": "string (optional) - Key purpose",
                        "expirationDays": "integer (optional) - Days until expiration (default: 365)",
                        "tags": "array (optional) - Key tags",
                        "department": "string (optional) - Department name"
                    }
                }
            },
            "key_management": {
                "list_keys": {
                    "url": "/api/v1/keys",
                    "method": "GET",
                    "description": "List all keys for the authenticated user/organization",
                    "auth_required": True,
                    "permissions": ["key:read"],
                    "parameters": {
                        "include_revoked": "boolean (optional) - Include revoked keys",
                        "type": "string (optional) - Filter by key type (kem/signature/hybrid)",
                        "status": "string (optional) - Filter by status",
                        "limit": "integer (optional) - Results per page (default: 100)",
                        "offset": "integer (optional) - Pagination offset (default: 0)"
                    }
                },
                "get_key": {
                    "url": "/api/v1/keys/{key_id}",
                    "method": "GET",
                    "description": "Get details of a specific key",
                    "auth_required": True,
                    "permissions": ["key:read"]
                },
                "get_public_key": {
                    "url": "/api/v1/keys/{key_id}/public-key",
                    "method": "GET",
                    "description": "Get public key only (safe for API exposure)",
                    "auth_required": True,
                    "permissions": ["key:read"]
                },
                "revoke_key": {
                    "url": "/api/v1/keys/{key_id}/revoke",
                    "method": "POST",
                    "description": "Revoke a key",
                    "auth_required": True,
                    "permissions": ["key:revoke"],
                    "request_body": {
                        "reason": "string (optional) - Revocation reason"
                    }
                },
                "rotate_key": {
                    "url": "/api/v1/keys/{key_id}/rotate",
                    "method": "POST",
                    "description": "Rotate a key (create new version)",
                    "auth_required": True,
                    "permissions": ["key:rotate"],
                    "request_body": {
                        "name": "string (optional) - New key name",
                        "description": "string (optional) - New description",
                        "expirationDays": "integer (optional) - New expiration days"
                    }
                },
                "delete_key": {
                    "url": "/api/v1/keys/{key_id}/delete",
                    "method": "DELETE",
                    "description": "Soft delete a key",
                    "auth_required": True,
                    "permissions": ["key:delete"]
                },
                "key_stats": {
                    "url": "/api/v1/keys/stats",
                    "method": "GET",
                    "description": "Get key statistics",
                    "auth_required": True,
                    "permissions": ["key:read"]
                }
            },
            "bulk_operations": {
                "bulk_revoke": {
                    "url": "/api/v1/keys/bulk/revoke",
                    "method": "POST",
                    "description": "Bulk revoke multiple keys",
                    "auth_required": True,
                    "permissions": ["key:revoke", "admin"],
                    "request_body": {
                        "key_ids": "array (required) - List of key IDs to revoke",
                        "reason": "string (optional) - Revocation reason"
                    }
                },
                "bulk_delete": {
                    "url": "/api/v1/keys/bulk/delete",
                    "method": "DELETE",
                    "description": "Bulk delete multiple keys",
                    "auth_required": True,
                    "permissions": ["key:delete", "admin"],
                    "request_body": {
                        "key_ids": "array (required) - List of key IDs to delete"
                    }
                }
            },
            "cryptographic_operations": {
                "encapsulate": {
                    "url": "/api/v1/keys/encapsulate",
                    "method": "POST",
                    "description": "Encapsulate a shared secret using a KEM key",
                    "auth_required": True,
                    "permissions": ["key:encrypt"],
                    "request_body": {
                        "key_id": "string (required) - Key ID",
                        "public_key": "string (required) - Base64 encoded public key"
                    }
                },
                "decapsulate": {
                    "url": "/api/v1/keys/decapsulate",
                    "method": "POST",
                    "description": "Decapsulate a shared secret using a KEM key",
                    "auth_required": True,
                    "permissions": ["key:decrypt"],
                    "request_body": {
                        "key_id": "string (required) - Key ID",
                        "ciphertext": "string (required) - Base64 encoded ciphertext"
                    }
                },
                "sign": {
                    "url": "/api/v1/keys/sign",
                    "method": "POST",
                    "description": "Sign a message using a signature key",
                    "auth_required": True,
                    "permissions": ["key:sign"],
                    "request_body": {
                        "key_id": "string (required) - Key ID",
                        "message": "string (required) - Message to sign"
                    }
                },
                "verify": {
                    "url": "/api/v1/keys/verify",
                    "method": "POST",
                    "description": "Verify a signature using a signature key",
                    "auth_required": True,
                    "permissions": ["key:verify"],
                    "request_body": {
                        "key_id": "string (required) - Key ID",
                        "message": "string (required) - Original message",
                        "signature": "string (required) - Base64 encoded signature"
                    }
                }
            }
        },
        "authentication": {
            "type": "Bearer Token",
            "header": "Authorization: Bearer <your_api_token>",
            "token_source": "Generate API tokens from the KeyOrbit dashboard with required permissions"
        },
        "permissions_required": {
            "key:read": "View keys and their metadata",
            "key:write": "Create new keys",
            "key:revoke": "Revoke existing keys",
            "key:rotate": "Rotate keys",
            "key:delete": "Delete keys",
            "key:encrypt": "Perform encapsulation operations",
            "key:decrypt": "Perform decapsulation operations",
            "key:sign": "Sign messages",
            "key:verify": "Verify signatures",
            "admin": "Administrative operations (bulk actions)"
        },
        "algorithms_supported": {
            "kem": ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"],
            "signature": ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
        },
        "timestamp": get_current_ist_time().isoformat()
    }), 200


@api_keys_bp.route('/api/v1/health', methods=['GET'])
def api_health():
    """Health check endpoint for API"""
    return jsonify({
        "status": "healthy",
        "service": "KeyOrbit PQC API",
        "version": "1.0.0",
        "timestamp": get_current_ist_time().isoformat()
    }), 200


# =====================================================
# KEY GENERATION ENDPOINTS
# =====================================================

@api_keys_bp.route('/api/v1/keys/generate/ml-kem', methods=['POST'])
@api_token_required(required_permissions=['key:write'])
def api_generate_ml_kem():
    """Generate ML-KEM (Kyber) keypair via API"""
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
        
        token_info = request.token_info
        user_id = token_info.get('userId')
        
        # Get user to verify organization
        user = User.find_by_id(user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        organization_id = user.get('organization', {}).get('id')
        
        # Prepare metadata
        metadata = {
            "name": data['name'],
            "description": data.get('description', ''),
            "tags": data.get('tags', []),
            "expirationDays": data.get('expirationDays', 365),
            "purpose": data.get('purpose', 'key_encapsulation'),
            "department": data.get('department', ''),
            "createdBy": user_id,
            "source": "api"
        }
        
        # Generate key
        key_data, error = PQCService.generate_ml_kem_keypair(
            algorithm=algorithm,
            user_id=user_id,
            organization_id=organization_id,
            metadata=metadata
        )
        
        if error:
            return jsonify({"error": error}), 500
        
        # Save to database
        result = Key.create_key(key_data)
        key_data['_id'] = str(result.inserted_id)
        
        # Remove private key from response
        if 'privateKey' in key_data:
            del key_data['privateKey']
        if 'keyHash' in key_data:
            del key_data['keyHash']
        
        return jsonify({
            "message": "ML-KEM key generated successfully",
            "key": KeyService.format_key_for_response(key_data),
            "timestamp": get_current_ist_time().isoformat()
        }), 201
        
    except Exception as e:
        print(f"Error in API generate ML-KEM: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@api_keys_bp.route('/api/v1/keys/generate/ml-dsa', methods=['POST'])
@api_token_required(required_permissions=['key:write'])
def api_generate_ml_dsa():
    """Generate ML-DSA (Dilithium) keypair via API"""
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
        
        token_info = request.token_info
        user_id = token_info.get('userId')
        
        # Get user to verify organization
        user = User.find_by_id(user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        organization_id = user.get('organization', {}).get('id')
        
        # Prepare metadata
        metadata = {
            "name": data['name'],
            "description": data.get('description', ''),
            "tags": data.get('tags', []),
            "expirationDays": data.get('expirationDays', 365),
            "purpose": data.get('purpose', 'digital_signature'),
            "department": data.get('department', ''),
            "createdBy": user_id,
            "source": "api"
        }
        
        # Generate key
        key_data, error = PQCService.generate_ml_dsa_keypair(
            algorithm=algorithm,
            user_id=user_id,
            organization_id=organization_id,
            metadata=metadata
        )
        
        if error:
            return jsonify({"error": error}), 500
        
        # Save to database
        result = Key.create_key(key_data)
        key_data['_id'] = str(result.inserted_id)
        
        # Remove private key from response
        if 'privateKey' in key_data:
            del key_data['privateKey']
        if 'keyHash' in key_data:
            del key_data['keyHash']
        
        return jsonify({
            "message": "ML-DSA key generated successfully",
            "key": KeyService.format_key_for_response(key_data),
            "timestamp": get_current_ist_time().isoformat()
        }), 201
        
    except Exception as e:
        print(f"Error in API generate ML-DSA: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@api_keys_bp.route('/api/v1/keys/generate/hybrid', methods=['POST'])
@api_token_required(required_permissions=['key:write'])
def api_generate_hybrid():
    """Generate hybrid keypair (KEM + Signature) via API"""
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
        
        token_info = request.token_info
        user_id = token_info.get('userId')
        
        # Get user to verify organization
        user = User.find_by_id(user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        organization_id = user.get('organization', {}).get('id')
        
        # Prepare metadata
        metadata = {
            "name": data['name'],
            "description": data.get('description', ''),
            "tags": data.get('tags', []),
            "expirationDays": data.get('expirationDays', 365),
            "purpose": data.get('purpose', 'hybrid'),
            "department": data.get('department', ''),
            "createdBy": user_id,
            "source": "api"
        }
        
        # Generate hybrid key
        result, error = PQCService.generate_hybrid_keypair(
            kem_algorithm=kem_algorithm,
            sig_algorithm=sig_algorithm,
            user_id=user_id,
            organization_id=organization_id,
            metadata=metadata
        )
        
        if error:
            return jsonify({"error": error}), 500
        
        # Save keys to database
        kem_result = Key.create_key(result['kemKey'])
        sig_result = Key.create_key(result['sigKey'])
        hybrid_result = Key.create_key(result['hybridKey'])
        
        # Remove private keys from response
        kem_key = result['kemKey'].copy()
        sig_key = result['sigKey'].copy()
        hybrid_key = result['hybridKey'].copy()
        
        if 'privateKey' in kem_key:
            del kem_key['privateKey']
        if 'privateKey' in sig_key:
            del sig_key['privateKey']
        if 'keyHash' in kem_key:
            del kem_key['keyHash']
        if 'keyHash' in sig_key:
            del sig_key['keyHash']
        
        return jsonify({
            "message": "Hybrid key generated successfully",
            "keys": {
                "hybridKey": KeyService.format_key_for_response(hybrid_key),
                "kemKey": KeyService.format_key_for_response(kem_key),
                "sigKey": KeyService.format_key_for_response(sig_key)
            },
            "timestamp": get_current_ist_time().isoformat()
        }), 201
        
    except Exception as e:
        print(f"Error in API generate hybrid: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# =====================================================
# KEY LISTING AND DETAILS
# =====================================================

@api_keys_bp.route('/api/v1/keys', methods=['GET'])
@api_token_required(required_permissions=['key:read'])
def get_api_keys():
    """Get all keys for the authenticated user/organization using API token"""
    try:
        token_info = request.token_info
        user_id = token_info.get('userId')
        
        # Get user to verify organization
        user = User.find_by_id(user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        organization_id = user.get('organization', {}).get('id')
        if not organization_id:
            return jsonify({"keys": [], "total": 0}), 200
        
        # Get query parameters
        include_revoked = request.args.get('include_revoked', 'false').lower() == 'true'
        key_type = request.args.get('type')
        status = request.args.get('status')
        limit = int(request.args.get('limit', 100))
        offset = int(request.args.get('offset', 0))
        
        # Build query
        query = {"organizationId": ObjectId(organization_id)}
        if not include_revoked:
            query["status"] = {"$nin": ["revoked", "deleted"]}
        if key_type:
            query["type"] = key_type
        if status:
            query["status"] = status
        
        # Get total count
        total = Key.collection.count_documents(query)
        
        # Get keys with pagination
        keys = list(Key.collection.find(query)
                   .sort("createdAt", -1)
                   .skip(offset)
                   .limit(limit))
        
        # Format response (exclude private keys)
        formatted_keys = []
        for key in keys:
            key_copy = key.copy()
            if 'privateKey' in key_copy:
                del key_copy['privateKey']
            if 'keyHash' in key_copy:
                del key_copy['keyHash']
            formatted_keys.append(KeyService.format_key_for_response(key_copy))
        
        return jsonify({
            "keys": formatted_keys,
            "total": total,
            "limit": limit,
            "offset": offset,
            "timestamp": get_current_ist_time().isoformat()
        }), 200
        
    except Exception as e:
        print(f"Error in API get keys: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Internal server error"}), 500


@api_keys_bp.route('/api/v1/keys/<key_id>', methods=['GET'])
@api_token_required(required_permissions=['key:read'])
def get_api_key_details(key_id):
    """Get details of a specific key using API token"""
    try:
        token_info = request.token_info
        user_id = token_info.get('userId')
        
        # Get user to verify organization
        user = User.find_by_id(user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        organization_id = user.get('organization', {}).get('id')
        
        # Find key
        key = Key.find_by_id(key_id)
        if not key:
            return jsonify({"error": "Key not found"}), 404
        
        # Verify organization access
        if str(key.get('organizationId')) != organization_id:
            return jsonify({"error": "Access denied"}), 403
        
        # Don't expose private keys in API
        key_copy = key.copy()
        if 'privateKey' in key_copy:
            del key_copy['privateKey']
        if 'keyHash' in key_copy:
            del key_copy['keyHash']
        
        formatted_key = KeyService.format_key_for_response(key_copy)
        
        return jsonify({
            "key": formatted_key,
            "timestamp": get_current_ist_time().isoformat()
        }), 200
        
    except Exception as e:
        print(f"Error in API get key details: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Internal server error"}), 500


@api_keys_bp.route('/api/v1/keys/<key_id>/public-key', methods=['GET'])
@api_token_required(required_permissions=['key:read'])
def get_api_public_key(key_id):
    """Get public key only (safe for API exposure)"""
    try:
        token_info = request.token_info
        user_id = token_info.get('userId')
        
        # Get user to verify organization
        user = User.find_by_id(user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        organization_id = user.get('organization', {}).get('id')
        
        # Find key
        key = Key.find_by_id(key_id)
        if not key:
            return jsonify({"error": "Key not found"}), 404
        
        # Verify organization access
        if str(key.get('organizationId')) != organization_id:
            return jsonify({"error": "Access denied"}), 403
        
        return jsonify({
            "key_id": key.get('keyId'),
            "name": key.get('name'),
            "algorithm": key.get('algorithm'),
            "type": key.get('type'),
            "public_key": key.get('publicKey'),
            "created_at": key.get('createdAt').isoformat() if key.get('createdAt') else None,
            "expires_at": key.get('expiresAt').isoformat() if key.get('expiresAt') else None,
            "timestamp": get_current_ist_time().isoformat()
        }), 200
        
    except Exception as e:
        print(f"Error getting public key: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Internal server error"}), 500


@api_keys_bp.route('/api/v1/keys/stats', methods=['GET'])
@api_token_required(required_permissions=['key:read'])
def get_api_key_stats():
    """Get key statistics for the organization"""
    try:
        token_info = request.token_info
        user_id = token_info.get('userId')
        
        # Get user to verify organization
        user = User.find_by_id(user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        organization_id = user.get('organization', {}).get('id')
        
        # Get statistics
        from app.models import Key
        stats = Key.get_key_stats(organization_id=organization_id)
        
        # Get expiring soon count
        now = datetime.now()
        thirty_days = now + timedelta(days=30)
        
        expiring_soon = Key.collection.count_documents({
            "organizationId": ObjectId(organization_id),
            "status": "active",
            "expiresAt": {"$gt": now, "$lt": thirty_days}
        })
        
        stats["expiringSoon"] = expiring_soon
        
        return jsonify({
            "stats": stats,
            "timestamp": get_current_ist_time().isoformat()
        }), 200
        
    except Exception as e:
        print(f"Error getting API key stats: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500


# =====================================================
# KEY MANAGEMENT OPERATIONS
# =====================================================

@api_keys_bp.route('/api/v1/keys/<key_id>/revoke', methods=['POST'])
@api_token_required(required_permissions=['key:revoke'])
def api_revoke_key(key_id):
    """Revoke a key via API"""
    try:
        data = request.get_json() or {}
        reason = data.get('reason', '')
        
        token_info = request.token_info
        user_id = token_info.get('userId')
        
        # Get user to verify organization
        user = User.find_by_id(user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        organization_id = user.get('organization', {}).get('id')
        
        # Find key
        key = Key.find_by_id(key_id)
        if not key:
            return jsonify({"error": "Key not found"}), 404
        
        # Verify organization access
        if str(key.get('organizationId')) != organization_id:
            return jsonify({"error": "Access denied"}), 403
        
        # Check if already revoked
        if key.get('status') == 'revoked':
            return jsonify({"error": "Key is already revoked"}), 400
        
        # Revoke key
        result = Key.revoke_key(key_id, reason)
        
        if result.modified_count == 0:
            return jsonify({"error": "Failed to revoke key"}), 500
        
        return jsonify({
            "message": "Key revoked successfully",
            "key_id": key.get('keyId'),
            "status": "revoked",
            "timestamp": get_current_ist_time().isoformat()
        }), 200
        
    except Exception as e:
        print(f"Error in API revoke key: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@api_keys_bp.route('/api/v1/keys/<key_id>/rotate', methods=['POST'])
@api_token_required(required_permissions=['key:rotate'])
def api_rotate_key(key_id):
    """Rotate a key via API (create new version)"""
    try:
        data = request.get_json() or {}
        
        token_info = request.token_info
        user_id = token_info.get('userId')
        
        # Get user to verify organization
        user = User.find_by_id(user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        organization_id = user.get('organization', {}).get('id')
        
        # Find key
        old_key = Key.find_by_id(key_id)
        if not old_key:
            return jsonify({"error": "Key not found"}), 404
        
        # Verify organization access
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
            "createdBy": user_id,
            "source": "api"
        }
        
        new_key_data = None
        if old_key.get('type') == 'kem':
            new_key_data, error = PQCService.generate_ml_kem_keypair(
                algorithm=old_key.get('algorithm'),
                user_id=user_id,
                organization_id=organization_id,
                metadata=metadata
            )
        elif old_key.get('type') == 'signature':
            new_key_data, error = PQCService.generate_ml_dsa_keypair(
                algorithm=old_key.get('algorithm'),
                user_id=user_id,
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
        
        # Get new key
        new_key = Key.find_by_id(result.inserted_id)
        new_key_copy = new_key.copy()
        if 'privateKey' in new_key_copy:
            del new_key_copy['privateKey']
        if 'keyHash' in new_key_copy:
            del new_key_copy['keyHash']
        
        formatted_key = KeyService.format_key_for_response(new_key_copy)
        
        return jsonify({
            "message": "Key rotated successfully",
            "old_key_id": old_key.get('keyId'),
            "new_key": formatted_key,
            "timestamp": get_current_ist_time().isoformat()
        }), 200
        
    except Exception as e:
        print(f"Error in API rotate key: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@api_keys_bp.route('/api/v1/keys/<key_id>/delete', methods=['DELETE'])
@api_token_required(required_permissions=['key:delete'])
def api_delete_key(key_id):
    """Soft delete a key via API"""
    try:
        token_info = request.token_info
        user_id = token_info.get('userId')
        
        # Get user to verify organization
        user = User.find_by_id(user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        organization_id = user.get('organization', {}).get('id')
        
        # Find key
        key = Key.find_by_id(key_id)
        if not key:
            return jsonify({"error": "Key not found"}), 404
        
        # Verify organization access
        if str(key.get('organizationId')) != organization_id:
            return jsonify({"error": "Access denied"}), 403
        
        # Delete key
        result = Key.delete_key(key_id)
        
        if result.modified_count == 0:
            return jsonify({"error": "Failed to delete key"}), 500
        
        return jsonify({
            "message": "Key deleted successfully",
            "key_id": key.get('keyId'),
            "timestamp": get_current_ist_time().isoformat()
        }), 200
        
    except Exception as e:
        print(f"Error in API delete key: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# =====================================================
# BULK OPERATIONS
# =====================================================

@api_keys_bp.route('/api/v1/keys/bulk/revoke', methods=['POST'])
@api_token_required(required_permissions=['key:revoke', 'admin'])
def api_bulk_revoke_keys():
    """Bulk revoke multiple keys via API"""
    try:
        data = request.get_json()
        
        if 'key_ids' not in data or not data['key_ids']:
            return jsonify({"error": "key_ids are required"}), 400
        
        reason = data.get('reason', 'Bulk revocation via API')
        
        token_info = request.token_info
        user_id = token_info.get('userId')
        
        # Get user to verify organization
        user = User.find_by_id(user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        organization_id = user.get('organization', {}).get('id')
        
        success_count = 0
        failed_keys = []
        
        for key_id in data['key_ids']:
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
                else:
                    failed_keys.append({"id": key_id, "error": "Revocation failed"})
                    
            except Exception as e:
                failed_keys.append({"id": key_id, "error": str(e)})
        
        return jsonify({
            "message": f"Bulk revocation completed: {success_count} keys revoked",
            "success_count": success_count,
            "failed_count": len(failed_keys),
            "failed_keys": failed_keys,
            "timestamp": get_current_ist_time().isoformat()
        }), 200
        
    except Exception as e:
        print(f"Error in API bulk revoke: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@api_keys_bp.route('/api/v1/keys/bulk/delete', methods=['DELETE'])
@api_token_required(required_permissions=['key:delete', 'admin'])
def api_bulk_delete_keys():
    """Bulk delete multiple keys via API"""
    try:
        data = request.get_json()
        
        if 'key_ids' not in data or not data['key_ids']:
            return jsonify({"error": "key_ids are required"}), 400
        
        token_info = request.token_info
        user_id = token_info.get('userId')
        
        # Get user to verify organization
        user = User.find_by_id(user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        organization_id = user.get('organization', {}).get('id')
        
        success_count = 0
        failed_keys = []
        
        for key_id in data['key_ids']:
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
                else:
                    failed_keys.append({"id": key_id, "error": "Deletion failed"})
                    
            except Exception as e:
                failed_keys.append({"id": key_id, "error": str(e)})
        
        return jsonify({
            "message": f"Bulk deletion completed: {success_count} keys deleted",
            "success_count": success_count,
            "failed_count": len(failed_keys),
            "failed_keys": failed_keys,
            "timestamp": get_current_ist_time().isoformat()
        }), 200
        
    except Exception as e:
        print(f"Error in API bulk delete: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# =====================================================
# CRYPTOGRAPHIC OPERATIONS
# =====================================================

@api_keys_bp.route('/api/v1/keys/encapsulate', methods=['POST'])
@api_token_required(required_permissions=['key:encrypt'])
def api_encapsulate():
    """Encapsulate a shared secret using a KEM key"""
    try:
        data = request.get_json()
        
        if 'key_id' not in data:
            return jsonify({"error": "key_id is required"}), 400
        if 'public_key' not in data:
            return jsonify({"error": "public_key is required"}), 400
        
        token_info = request.token_info
        user_id = token_info.get('userId')
        
        # Get user to verify organization
        user = User.find_by_id(user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        organization_id = user.get('organization', {}).get('id')
        
        # Find key
        key = Key.find_by_id(data['key_id'])
        if not key:
            return jsonify({"error": "Key not found"}), 404
        
        # Verify organization access
        if str(key.get('organizationId')) != organization_id:
            return jsonify({"error": "Access denied"}), 403
        
        # Check key type
        if key.get('type') != 'kem':
            return jsonify({"error": "Key is not a KEM key"}), 400
        
        # Perform encapsulation
        result, error = PQCService.encapsulate(
            public_key_b64=data['public_key'],
            algorithm=key.get('algorithm')
        )
        
        if error:
            return jsonify({"error": error}), 500
        
        # Update key usage count
        Key.collection.update_one(
            {"_id": ObjectId(data['key_id'])},
            {"$inc": {"usageCount": 1}, "$set": {"lastUsed": get_current_ist_time()}}
        )
        
        return jsonify({
            "result": result,
            "key_id": key.get('keyId'),
            "timestamp": get_current_ist_time().isoformat()
        }), 200
        
    except Exception as e:
        print(f"Error in API encapsulate: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Internal server error"}), 500


@api_keys_bp.route('/api/v1/keys/decapsulate', methods=['POST'])
@api_token_required(required_permissions=['key:decrypt'])
def api_decapsulate():
    """Decapsulate a shared secret using a KEM key"""
    try:
        data = request.get_json()
        
        if 'key_id' not in data:
            return jsonify({"error": "key_id is required"}), 400
        if 'ciphertext' not in data:
            return jsonify({"error": "ciphertext is required"}), 400
        
        token_info = request.token_info
        user_id = token_info.get('userId')
        
        # Get user to verify organization
        user = User.find_by_id(user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        organization_id = user.get('organization', {}).get('id')
        
        # Find key
        key = Key.find_by_id(data['key_id'])
        if not key:
            return jsonify({"error": "Key not found"}), 404
        
        # Verify organization access
        if str(key.get('organizationId')) != organization_id:
            return jsonify({"error": "Access denied"}), 403
        
        # Check key type
        if key.get('type') != 'kem':
            return jsonify({"error": "Key is not a KEM key"}), 400
        
        # Perform decapsulation
        result, error = PQCService.decapsulate(
            ciphertext_b64=data['ciphertext'],
            private_key_b64=key.get('privateKey'),
            algorithm=key.get('algorithm')
        )
        
        if error:
            return jsonify({"error": error}), 500
        
        # Update key usage count
        Key.collection.update_one(
            {"_id": ObjectId(data['key_id'])},
            {"$inc": {"usageCount": 1}, "$set": {"lastUsed": get_current_ist_time()}}
        )
        
        return jsonify({
            "result": result,
            "key_id": key.get('keyId'),
            "timestamp": get_current_ist_time().isoformat()
        }), 200
        
    except Exception as e:
        print(f"Error in API decapsulate: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Internal server error"}), 500


@api_keys_bp.route('/api/v1/keys/sign', methods=['POST'])
@api_token_required(required_permissions=['key:sign'])
def api_sign():
    """Sign a message using a signature key"""
    try:
        data = request.get_json()
        
        if 'key_id' not in data:
            return jsonify({"error": "key_id is required"}), 400
        if 'message' not in data:
            return jsonify({"error": "message is required"}), 400
        
        token_info = request.token_info
        user_id = token_info.get('userId')
        
        # Get user to verify organization
        user = User.find_by_id(user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        organization_id = user.get('organization', {}).get('id')
        
        # Find key
        key = Key.find_by_id(data['key_id'])
        if not key:
            return jsonify({"error": "Key not found"}), 404
        
        # Verify organization access
        if str(key.get('organizationId')) != organization_id:
            return jsonify({"error": "Access denied"}), 403
        
        # Check key type
        if key.get('type') not in ['signature', 'hybrid']:
            return jsonify({"error": "Key is not a signature key"}), 400
        
        # Get private key
        if key.get('type') == 'hybrid':
            sig_key = Key.find_by_key_id(key.get('sigKeyId'))
            if not sig_key:
                return jsonify({"error": "Signature component not found"}), 404
            private_key = sig_key.get('privateKey')
            algorithm = sig_key.get('algorithm')
        else:
            private_key = key.get('privateKey')
            algorithm = key.get('algorithm')
        
        # Perform signing
        result, error = PQCService.sign(
            message=data['message'],
            private_key_b64=private_key,
            algorithm=algorithm
        )
        
        if error:
            return jsonify({"error": error}), 500
        
        # Update key usage count
        Key.collection.update_one(
            {"_id": ObjectId(data['key_id'])},
            {"$inc": {"usageCount": 1}, "$set": {"lastUsed": get_current_ist_time()}}
        )
        
        return jsonify({
            "result": result,
            "key_id": key.get('keyId'),
            "timestamp": get_current_ist_time().isoformat()
        }), 200
        
    except Exception as e:
        print(f"Error in API sign: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Internal server error"}), 500


@api_keys_bp.route('/api/v1/keys/verify', methods=['POST'])
@api_token_required(required_permissions=['key:verify'])
def api_verify():
    """Verify a signature using a signature key"""
    try:
        data = request.get_json()
        
        if 'key_id' not in data:
            return jsonify({"error": "key_id is required"}), 400
        if 'message' not in data:
            return jsonify({"error": "message is required"}), 400
        if 'signature' not in data:
            return jsonify({"error": "signature is required"}), 400
        
        token_info = request.token_info
        user_id = token_info.get('userId')
        
        # Get user to verify organization
        user = User.find_by_id(user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        organization_id = user.get('organization', {}).get('id')
        
        # Find key
        key = Key.find_by_id(data['key_id'])
        if not key:
            return jsonify({"error": "Key not found"}), 404
        
        # Verify organization access
        if str(key.get('organizationId')) != organization_id:
            return jsonify({"error": "Access denied"}), 403
        
        # Check key type
        if key.get('type') not in ['signature', 'hybrid']:
            return jsonify({"error": "Key is not a signature key"}), 400
        
        # Get public key
        if key.get('type') == 'hybrid':
            sig_key = Key.find_by_key_id(key.get('sigKeyId'))
            if not sig_key:
                return jsonify({"error": "Signature component not found"}), 404
            public_key = sig_key.get('publicKey')
            algorithm = sig_key.get('algorithm')
        else:
            public_key = key.get('publicKey')
            algorithm = key.get('algorithm')
        
        # Perform verification
        result, error = PQCService.verify(
            message=data['message'],
            signature_b64=data['signature'],
            public_key_b64=public_key,
            algorithm=algorithm
        )
        
        if error:
            return jsonify({"error": error}), 500
        
        # Update key usage count if verification succeeds
        if result.get('valid'):
            Key.collection.update_one(
                {"_id": ObjectId(data['key_id'])},
                {"$inc": {"usageCount": 1}, "$set": {"lastUsed": get_current_ist_time()}}
            )
        
        return jsonify({
            "result": result,
            "key_id": key.get('keyId'),
            "timestamp": get_current_ist_time().isoformat()
        }), 200
        
    except Exception as e:
        print(f"Error in API verify: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Internal server error"}), 500


# =====================================================
# ALGORITHM INFORMATION
# =====================================================

@api_keys_bp.route('/api/v1/keys/algorithms', methods=['GET'])
@api_token_required()
def get_api_algorithms():
    """Get supported algorithms with detailed information"""
    return jsonify({
        "kem": [
            {
                "id": "ml-kem-512",
                "name": "ML-KEM-512",
                "security": "128-bit",
                "nist_level": 1,
                "type": "kem",
                "description": "Key Encapsulation Mechanism - NIST Level 1"
            },
            {
                "id": "ml-kem-768",
                "name": "ML-KEM-768",
                "security": "192-bit",
                "nist_level": 3,
                "type": "kem",
                "description": "Key Encapsulation Mechanism - NIST Level 3"
            },
            {
                "id": "ml-kem-1024",
                "name": "ML-KEM-1024",
                "security": "256-bit",
                "nist_level": 5,
                "type": "kem",
                "description": "Key Encapsulation Mechanism - NIST Level 5"
            }
        ],
        "signature": [
            {
                "id": "ml-dsa-44",
                "name": "ML-DSA-44",
                "security": "128-bit",
                "nist_level": 2,
                "type": "signature",
                "description": "Digital Signature Algorithm - NIST Level 2"
            },
            {
                "id": "ml-dsa-65",
                "name": "ML-DSA-65",
                "security": "192-bit",
                "nist_level": 3,
                "type": "signature",
                "description": "Digital Signature Algorithm - NIST Level 3"
            },
            {
                "id": "ml-dsa-87",
                "name": "ML-DSA-87",
                "security": "256-bit",
                "nist_level": 5,
                "type": "signature",
                "description": "Digital Signature Algorithm - NIST Level 5"
            }
        ],
        "timestamp": get_current_ist_time().isoformat()
    }), 200