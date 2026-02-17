from flask import Flask, jsonify, request
from flask_cors import CORS
from app.config import Config
from app.routes.auth import auth_bp
from app.routes.registration import registration_bp
from app.routes.profile import profile_bp
from app.routes.password import password_bp
from app.routes.tokens import tokens_bp
from app.routes.me import me_bp
from app.routes.api_protected import api_protected_bp
from app.routes.users import users_bp
from app.routes.keys import keys_bp
from app.routes.api_keys import api_keys_bp
from app.routes.audit import audit_bp
from app.routes.dashboard import dashboard_bp
import os
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def create_app():
    """Application factory function"""
    app = Flask(__name__)
    
    # =====================================================
    # CONFIGURATION
    # =====================================================
    
    # Use environment variable for secret key (never hardcode!)
    app.secret_key = os.getenv("SECRET_KEY", "Sur@6904")
    app.config.from_object(Config)
    
    # Set production/development mode
    app.config['ENV'] = os.getenv("FLASK_ENV", "development")
    app.config['DEBUG'] = os.getenv("FLASK_ENV", "development") == "development"
    
    # =====================================================
    # CORS CONFIGURATION
    # =====================================================
    
    cors_origins = [
        Config.FRONTEND_URL,
        "http://localhost:3000",
        "http://localhost:4028",
        "http://127.0.0.1:8000",
    ]
    
    # In production, only allow specific origins
    if app.config['ENV'] == "production":
        cors_origins = [Config.FRONTEND_URL]
        logger.info(f"Production mode: CORS origins restricted to {cors_origins}")
    
    CORS(
        app,
        origins=cors_origins,
        supports_credentials=True,
        allow_headers=["Content-Type", "Authorization", "X-Forwarded-For"],
        methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        max_age=3600
    )
    
    # =====================================================
    # BLUEPRINT REGISTRATION
    # =====================================================
    
    blueprints = [
        (auth_bp, '/auth'),
        (registration_bp, '/'),
        (profile_bp, '/'),
        (password_bp, '/'),
        (tokens_bp, '/'),
        (me_bp, '/'),
        (api_protected_bp, '/'),
        (users_bp, ''),
        (keys_bp, ''),
        (api_keys_bp, ''),
        (audit_bp, ''),
        (dashboard_bp, ''),
    ]
    
    for blueprint, url_prefix in blueprints:
        app.register_blueprint(blueprint, url_prefix=url_prefix)
        logger.info(f"Registered blueprint: {blueprint.name}")
    
    # =====================================================
    # ROUTES
    # =====================================================
    
    @app.route('/health', methods=['GET'])
    def health_check():
        """Health check endpoint for load balancers"""
        return jsonify({
            "status": "healthy",
            "service": "keyorbit-auth",
            "version": "2.0.0",
            "environment": app.config['ENV']
        }), 200
    
    @app.route('/', methods=['GET'])
    def root():
        """Root endpoint with service information"""
        return jsonify({
            "service": "Keyorbit KMS",
            "description": "Post-Quantum Cryptography Key Management System",
            "version": "2.0.0",
            "status": "operational",
            "endpoints": {
                "health": "/health",
                "auth": "/auth",
                "api": "/api",
                "keys": "/keys",
                "audit": "/audit"
            }
        }), 200
    
    # =====================================================
    # ERROR HANDLERS
    # =====================================================
    
    @app.errorhandler(400)
    def bad_request(error):
        """Handle bad request errors"""
        logger.warning(f"Bad request: {error}")
        return jsonify({
            "error": "Bad Request",
            "message": str(error),
            "status": 400
        }), 400
    
    @app.errorhandler(401)
    def unauthorized(error):
        """Handle unauthorized errors"""
        logger.warning(f"Unauthorized access attempt")
        return jsonify({
            "error": "Unauthorized",
            "message": "Authentication required",
            "status": 401
        }), 401
    
    @app.errorhandler(403)
    def forbidden(error):
        """Handle forbidden errors"""
        logger.warning(f"Forbidden access attempt")
        return jsonify({
            "error": "Forbidden",
            "message": "Insufficient permissions",
            "status": 403
        }), 403
    
    @app.errorhandler(404)
    def not_found(error):
        """Handle 404 errors"""
        return jsonify({
            "error": "Not Found",
            "message": f"Endpoint not found: {request.path}",
            "status": 404
        }), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        """Handle internal server errors"""
        logger.error(f"Internal server error: {error}", exc_info=True)
        return jsonify({
            "error": "Internal Server Error",
            "message": "An unexpected error occurred",
            "status": 500
        }), 500
    
    @app.errorhandler(503)
    def service_unavailable(error):
        """Handle service unavailable errors"""
        logger.error(f"Service unavailable: {error}")
        return jsonify({
            "error": "Service Unavailable",
            "message": "Service temporarily unavailable",
            "status": 503
        }), 503
    
    # =====================================================
    # REQUEST/RESPONSE LOGGING (Development only)
    # =====================================================
    
    @app.before_request
    def log_request():
        """Log incoming requests"""
        if app.config['DEBUG']:
            logger.debug(f"{request.method} {request.path} - {request.remote_addr}")
    
    @app.after_request
    def log_response(response):
        """Log response status"""
        if app.config['DEBUG']:
            logger.debug(f"Response: {response.status_code} - {request.path}")
        return response
    
    # =====================================================
    # INITIALIZATION
    # =====================================================
    
    logger.info("=" * 50)
    logger.info("Keyorbit KMS Application Initialized")
    logger.info(f"Environment: {app.config['ENV']}")
    logger.info(f"Debug Mode: {app.config['DEBUG']}")
    logger.info(f"Frontend URL: {Config.FRONTEND_URL}")
    logger.info("=" * 50)
    
    return app


if __name__ == '__main__':
    # =====================================================
    # LOCAL DEVELOPMENT ONLY
    # =====================================================
    
    app = create_app()
    
    # Use environment variable for port
    port = int(os.getenv("PORT", 8000))
    debug_mode = os.getenv("FLASK_ENV", "development") == "development"
    
    logger.info(f"Starting Flask application on port {port}")
    logger.info(f"Debug mode: {debug_mode}")
    logger.warning("⚠️  This server is for development only!")
    logger.warning("⚠️  Use Gunicorn in production: gunicorn 'main:create_app()'")
    
    app.run(
        debug=debug_mode,
        host='0.0.0.0',
        port=port,
        use_reloader=debug_mode
    )