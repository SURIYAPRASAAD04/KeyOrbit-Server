from flask import Flask, jsonify
from flask_cors import CORS
from app.config import Config
from app.routes.auth import auth_bp
from app.routes.registration import registration_bp
from app.routes.profile import profile_bp
from app.routes.password import password_bp
from app.routes.tokens import tokens_bp
from app.routes.me import me_bp
from app.routes.api_protected import api_protected_bp

def create_app():
    app = Flask(__name__)
    app.secret_key = "Sur@6904"
    app.config.from_object(Config)
    
    # Enable CORS with proper configuration
    CORS(app, 
         origins=[Config.FRONTEND_URL, "http://localhost:4028", "http://127.0.0.1:8000"],
         supports_credentials=True,
         allow_headers=["Content-Type", "Authorization", "X-Forwarded-For"],
         methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    )
    
    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(registration_bp, url_prefix='/')
    app.register_blueprint(profile_bp, url_prefix='/')
    app.register_blueprint(password_bp, url_prefix='/')
    app.register_blueprint(tokens_bp, url_prefix='/')
    app.register_blueprint(me_bp, url_prefix='/')
    app.register_blueprint(api_protected_bp, url_prefix='/')
    
    # Add health check endpoint
    @app.route('/health', methods=['GET'])
    def health_check():
        return jsonify({"status": "healthy", "service": "keyorbit-auth"}), 200
    
    # Add error handler for 404
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({"error": "Endpoint not found"}), 404
    
    # Add error handler for 500
    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({"error": "Internal server error"}), 500
    
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='0.0.0.0', port=8000)