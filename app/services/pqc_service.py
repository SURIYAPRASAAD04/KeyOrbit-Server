import base64
import oqs
import secrets
from datetime import datetime, timedelta
from bson import ObjectId
from app.models import Key, AuditLog
from app.utils.security import generate_key_id, hash_key_material
from pytz import timezone

IST = timezone('Asia/Kolkata')

class PQCService:
    """Post-Quantum Cryptography Service"""
    
    SUPPORTED_KEMS = {
        'ml-kem-512': 'ML-KEM-512',
        'ml-kem-768': 'ML-KEM-768',
        'ml-kem-1024': 'ML-KEM-1024'
    }
    
    SUPPORTED_SIGNATURES = {
        'ml-dsa-44': 'ML-DSA-44',
        'ml-dsa-65': 'ML-DSA-65',
        'ml-dsa-87': 'ML-DSA-87',
        'sphincs-sha2-128f': 'SPHINCS+-SHA2-128f',
        'sphincs-sha2-128s': 'SPHINCS+-SHA2-128s'
    }
    
    KEY_PURPOSES = {
        'kem': 'Key Encapsulation Mechanism',
        'signature': 'Digital Signature',
        'hybrid': 'Hybrid (KEM + Signature)'
    }
    
    @staticmethod
    def generate_ml_kem_keypair(algorithm='ml-kem-768', user_id=None, organization_id=None, metadata=None):
        """Generate ML-KEM keypair"""
        try:
            # Map to liboqs algorithm name
            alg_map = {
                'ml-kem-512': 'ML-KEM-512',
                'ml-kem-768': 'ML-KEM-768',
                'ml-kem-1024': 'ML-KEM-1024'
            }
            
            alg_name = alg_map.get(algorithm.lower())
            if not alg_name:
                return None, f"Unsupported algorithm: {algorithm}"
            
            # Generate keypair
            start_time = datetime.now(IST)
            with oqs.KeyEncapsulation(alg_name) as kem:
                public_key = kem.generate_keypair()
                private_key = kem.export_secret_key()
            generation_time = (datetime.now(IST) - start_time).total_seconds()
            
            # Generate key ID
            key_id = generate_key_id()
            
            # Encode keys for storage
            encoded_public = base64.b64encode(public_key).decode('utf-8')
            encoded_private = base64.b64encode(private_key).decode('utf-8')
            
            # Hash sensitive key material for integrity verification
            key_hash = hash_key_material(public_key + private_key)
            
            # Prepare key data
            key_data = {
                "keyId": key_id,
                "name": metadata.get('name', f"ML-KEM Key {datetime.now(IST).strftime('%Y-%m-%d %H:%M')}"),
                "algorithm": algorithm,
                "algorithm_full": alg_name,
                "type": "kem",
                "purpose": "key_encapsulation",
                "publicKey": encoded_public,
                "privateKey": encoded_private,
                "keyHash": key_hash,
                "status": "active",
                "userId": ObjectId(user_id) if user_id else None,
                "organizationId": ObjectId(organization_id) if organization_id else None,
                "metadata": metadata or {},
                "keySize": PQCService._get_key_size(algorithm),
                "securityLevel": PQCService._get_security_level(algorithm),
                "generationTime": round(generation_time, 3),
                "createdAt": datetime.now(IST),
                "updatedAt": datetime.now(IST),
                "expiresAt": datetime.now(IST) + timedelta(days=metadata.get('expirationDays', 365)) if metadata else datetime.now(IST) + timedelta(days=365),
                "version": 1,
                "tags": metadata.get('tags', [])
            }
            
            return key_data, None
            
        except Exception as e:
            return None, str(e)
    
    @staticmethod
    def generate_ml_dsa_keypair(algorithm='ml-dsa-65', user_id=None, organization_id=None, metadata=None):
        """Generate ML-DSA (Dilithium) keypair"""
        try:
            # Map to liboqs algorithm name
            alg_map = {
                'ml-dsa-44': 'ML-DSA-44',
                'ml-dsa-65': 'ML-DSA-65',
                'ml-dsa-87': 'ML-DSA-87'
            }
            
            alg_name = alg_map.get(algorithm.lower())
            if not alg_name:
                return None, f"Unsupported algorithm: {algorithm}"
            
            # Generate keypair
            start_time = datetime.now(IST)
            with oqs.Signature(alg_name) as sig:
                public_key = sig.generate_keypair()
                private_key = sig.export_secret_key()
            generation_time = (datetime.now(IST) - start_time).total_seconds()
            
            # Generate key ID
            key_id = generate_key_id()
            
            # Encode keys for storage
            encoded_public = base64.b64encode(public_key).decode('utf-8')
            encoded_private = base64.b64encode(private_key).decode('utf-8')
            
            # Hash sensitive key material
            key_hash = hash_key_material(public_key + private_key)
            
            # Prepare key data
            key_data = {
                "keyId": key_id,
                "name": metadata.get('name', f"ML-DSA Key {datetime.now(IST).strftime('%Y-%m-%d %H:%M')}"),
                "algorithm": algorithm,
                "algorithm_full": alg_name,
                "type": "signature",
                "purpose": "digital_signature",
                "publicKey": encoded_public,
                "privateKey": encoded_private,
                "keyHash": key_hash,
                "status": "active",
                "userId": ObjectId(user_id) if user_id else None,
                "organizationId": ObjectId(organization_id) if organization_id else None,
                "metadata": metadata or {},
                "keySize": PQCService._get_key_size(algorithm),
                "securityLevel": PQCService._get_security_level(algorithm),
                "generationTime": round(generation_time, 3),
                "createdAt": datetime.now(IST),
                "updatedAt": datetime.now(IST),
                "expiresAt": datetime.now(IST) + timedelta(days=metadata.get('expirationDays', 365)) if metadata else datetime.now(IST) + timedelta(days=365),
                "version": 1,
                "tags": metadata.get('tags', [])
            }
            
            return key_data, None
            
        except Exception as e:
            return None, str(e)
    
    @staticmethod
    def generate_hybrid_keypair(kem_algorithm='ml-kem-768', sig_algorithm='ml-dsa-65', user_id=None, organization_id=None, metadata=None):
        """Generate hybrid keypair (KEM + Signature)"""
        try:
            # Generate KEM keypair
            kem_key, kem_error = PQCService.generate_ml_kem_keypair(
                algorithm=kem_algorithm,
                user_id=user_id,
                organization_id=organization_id,
                metadata={**metadata, 'name': f"{metadata.get('name', 'Hybrid')} - KEM"}
            )
            
            if kem_error:
                return None, f"KEM generation failed: {kem_error}"
            
            # Generate Signature keypair
            sig_key, sig_error = PQCService.generate_ml_dsa_keypair(
                algorithm=sig_algorithm,
                user_id=user_id,
                organization_id=organization_id,
                metadata={**metadata, 'name': f"{metadata.get('name', 'Hybrid')} - Signature"}
            )
            
            if sig_error:
                return None, f"Signature generation failed: {sig_error}"
            
            # Generate hybrid key ID
            hybrid_key_id = generate_key_id()
            
            # Create hybrid key record
            hybrid_key = {
                "keyId": hybrid_key_id,
                "name": metadata.get('name', f"Hybrid Key {datetime.now(IST).strftime('%Y-%m-%d %H:%M')}"),
                "algorithm": f"hybrid-{kem_algorithm}-{sig_algorithm}",
                "type": "hybrid",
                "purpose": "hybrid",
                "kemKeyId": kem_key['keyId'],
                "sigKeyId": sig_key['keyId'],
                "status": "active",
                "userId": ObjectId(user_id) if user_id else None,
                "organizationId": ObjectId(organization_id) if organization_id else None,
                "metadata": metadata or {},
                "securityLevel": "hybrid",
                "createdAt": datetime.now(IST),
                "updatedAt": datetime.now(IST),
                "expiresAt": kem_key['expiresAt'] if kem_key['expiresAt'] < sig_key['expiresAt'] else sig_key['expiresAt'],
                "version": 1,
                "tags": metadata.get('tags', [])
            }
            
            return {
                "hybridKey": hybrid_key,
                "kemKey": kem_key,
                "sigKey": sig_key
            }, None
            
        except Exception as e:
            return None, str(e)
    
    @staticmethod
    def encapsulate(public_key_b64, algorithm='ml-kem-768'):
        """Encapsulate a shared secret using ML-KEM"""
        try:
            # Map algorithm
            alg_map = {
                'ml-kem-512': 'ML-KEM-512',
                'ml-kem-768': 'ML-KEM-768',
                'ml-kem-1024': 'ML-KEM-1024'
            }
            
            alg_name = alg_map.get(algorithm.lower())
            if not alg_name:
                return None, f"Unsupported algorithm: {algorithm}"
            
            # Decode public key
            public_key = base64.b64decode(public_key_b64)
            
            # Perform encapsulation
            start_time = datetime.now(IST)
            with oqs.KeyEncapsulation(alg_name) as kem:
                ciphertext, shared_secret = kem.encap_secret(public_key)
            elapsed = (datetime.now(IST) - start_time).total_seconds()
            
            return {
                "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
                "shared_secret": base64.b64encode(shared_secret).decode('utf-8'),
                "algorithm": algorithm,
                "time_seconds": round(elapsed, 3)
            }, None
            
        except Exception as e:
            return None, str(e)
    
    @staticmethod
    def decapsulate(ciphertext_b64, private_key_b64, algorithm='ml-kem-768'):
        """Decapsulate a shared secret using ML-KEM"""
        try:
            # Map algorithm
            alg_map = {
                'ml-kem-512': 'ML-KEM-512',
                'ml-kem-768': 'ML-KEM-768',
                'ml-kem-1024': 'ML-KEM-1024'
            }
            
            alg_name = alg_map.get(algorithm.lower())
            if not alg_name:
                return None, f"Unsupported algorithm: {algorithm}"
            
            # Decode inputs
            ciphertext = base64.b64decode(ciphertext_b64)
            private_key = base64.b64decode(private_key_b64)
            
            # Perform decapsulation
            start_time = datetime.now(IST)
            with oqs.KeyEncapsulation(alg_name, secret_key=private_key) as kem:
                shared_secret = kem.decap_secret(ciphertext)
            elapsed = (datetime.now(IST) - start_time).total_seconds()
            
            return {
                "shared_secret": base64.b64encode(shared_secret).decode('utf-8'),
                "algorithm": algorithm,
                "time_seconds": round(elapsed, 3)
            }, None
            
        except Exception as e:
            return None, str(e)
    
    @staticmethod
    def sign(message, private_key_b64, algorithm='ml-dsa-65'):
        """Sign a message using ML-DSA"""
        try:
            # Map algorithm
            alg_map = {
                'ml-dsa-44': 'ML-DSA-44',
                'ml-dsa-65': 'ML-DSA-65',
                'ml-dsa-87': 'ML-DSA-87'
            }
            
            alg_name = alg_map.get(algorithm.lower())
            if not alg_name:
                return None, f"Unsupported algorithm: {algorithm}"
            
            # Decode private key
            private_key = base64.b64decode(private_key_b64)
            
            # Sign message
            message_bytes = message.encode('utf-8') if isinstance(message, str) else message
            
            start_time = datetime.now(IST)
            with oqs.Signature(alg_name, secret_key=private_key) as sig:
                signature = sig.sign(message_bytes)
            elapsed = (datetime.now(IST) - start_time).total_seconds()
            
            return {
                "signature": base64.b64encode(signature).decode('utf-8'),
                "algorithm": algorithm,
                "time_seconds": round(elapsed, 3)
            }, None
            
        except Exception as e:
            return None, str(e)
    
    @staticmethod
    def verify(message, signature_b64, public_key_b64, algorithm='ml-dsa-65'):
        """Verify a signature using ML-DSA"""
        try:
            # Map algorithm
            alg_map = {
                'ml-dsa-44': 'ML-DSA-44',
                'ml-dsa-65': 'ML-DSA-65',
                'ml-dsa-87': 'ML-DSA-87'
            }
            
            alg_name = alg_map.get(algorithm.lower())
            if not alg_name:
                return None, f"Unsupported algorithm: {algorithm}"
            
            # Decode inputs
            signature = base64.b64decode(signature_b64)
            public_key = base64.b64decode(public_key_b64)
            
            # Verify signature
            message_bytes = message.encode('utf-8') if isinstance(message, str) else message
            
            start_time = datetime.now(IST)
            with oqs.Signature(alg_name) as verifier:
                valid = verifier.verify(message_bytes, signature, public_key)
            elapsed = (datetime.now(IST) - start_time).total_seconds()
            
            return {
                "valid": bool(valid),
                "algorithm": algorithm,
                "time_seconds": round(elapsed, 3)
            }, None
            
        except Exception as e:
            return None, str(e)
    
    @staticmethod
    def _get_key_size(algorithm):
        """Get key size in bits"""
        sizes = {
            'ml-kem-512': 512,
            'ml-kem-768': 768,
            'ml-kem-1024': 1024,
            'ml-dsa-44': 44,
            'ml-dsa-65': 65,
            'ml-dsa-87': 87
        }
        return sizes.get(algorithm.lower(), 0)
    
    @staticmethod
    def _get_security_level(algorithm):
        """Get security level"""
        if 'kem' in algorithm.lower():
            return {
                'ml-kem-512': 128,
                'ml-kem-768': 192,
                'ml-kem-1024': 256
            }.get(algorithm.lower(), 128)
        elif 'dsa' in algorithm.lower():
            return {
                'ml-dsa-44': 128,
                'ml-dsa-65': 192,
                'ml-dsa-87': 256
            }.get(algorithm.lower(), 128)
        return 128