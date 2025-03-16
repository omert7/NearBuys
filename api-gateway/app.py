import os
import json
import requests
import logging
from flask import Flask, request, jsonify, Response, redirect
from flask_cors import CORS
from dotenv import load_dotenv
import jwt
from functools import wraps

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('api_gateway')

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Service registry - in production, you might use a service discovery tool like Consul
SERVICE_REGISTRY = {
    # Use correct Docker service names (not localhost)
    'product-service': 'http://product-service:5004',
    'user-service': 'http://user-service:5003',
    'seller-service': 'http://seller-service:5005'
}

# Secret key for JWT validation
JWT_SECRET = os.getenv('JWT_SECRET_KEY', 'your-secret-key')

# Routes that don't require authentication
PUBLIC_ROUTES = [
    # Health endpoints
    '/health',
    '/product-service/health',
    '/user-service/health',
    '/seller-service/health',
    
    # Authentication endpoints
    '/user-service/api/users/register',
    '/user-service/api/users/login',
    '/user-service/oauth/login/google',
    '/user-service/oauth/login/facebook',
    '/user-service/oauth/callback/google',
    '/user-service/oauth/callback/facebook',
    
    # Public product endpoints
    '/product-service/categories',
    '/product-service/products',
    '/product-service/api/products',
    
    # Public seller endpoints
    '/seller-service/sellers'
]

# Authentication decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Get token from header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        
        try:
            # Decode the token
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            request.user = payload
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401
            
        return f(*args, **kwargs)
    
    return decorated

# Rate limiting configuration (simple implementation)
class RateLimiter:
    def __init__(self, limit=100, window=60):  # 100 requests per minute by default
        self.limit = limit
        self.window = window  # seconds
        self.clients = {}
        
    def is_allowed(self, client_id):
        import time
        current_time = time.time()
        
        if client_id not in self.clients:
            self.clients[client_id] = []
        
        # Remove old requests
        self.clients[client_id] = [timestamp for timestamp in self.clients[client_id] 
                                  if timestamp > current_time - self.window]
        
        # Check if client is within rate limit
        if len(self.clients[client_id]) < self.limit:
            self.clients[client_id].append(current_time)
            return True
        return False

# Create rate limiter instance
rate_limiter = RateLimiter()

# Health check endpoint
@app.route('/health', methods=['GET'])
def health_check():
    # Check health of all services
    services_status = {}
    for service_name, service_url in SERVICE_REGISTRY.items():
        try:
            logger.info(f"Checking health of {service_name} at {service_url}")
            response = requests.get(f"{service_url}/health", timeout=2)
            services_status[service_name] = "UP" if response.status_code == 200 else "DOWN"
        except requests.RequestException:
            services_status[service_name] = "DOWN"
    
    all_healthy = all(status == "UP" for status in services_status.values())
    return jsonify({
        "status": "UP" if all_healthy else "PARTIAL",
        "services": services_status
    }), 200 if all_healthy else 207

# OAuth redirect handler
@app.route('/oauth/login/<provider>', methods=['GET'])
def oauth_login(provider):
    """Redirect to user-service OAuth login"""
    return redirect(f"{SERVICE_REGISTRY['user-service']}/oauth/login/{provider}")

@app.route('/oauth/callback/<provider>', methods=['GET'])
def oauth_callback(provider):
    """Handle OAuth callback by forwarding to user-service"""
    return redirect(f"{SERVICE_REGISTRY['user-service']}/oauth/callback/{provider}")

# Main gateway logic - forwarding requests to appropriate services
@app.route('/<service>/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@app.route('/<service>/', methods=['GET', 'POST', 'PUT', 'DELETE'], defaults={'path': ''})
def gateway(service, path):
    full_path = f"/{service}/{path}" if path else f"/{service}/"
    logger.info(f"full_path: {full_path}")
            
    # Check if request is to a known service
    if service not in SERVICE_REGISTRY:
        return jsonify({"error": "Service not found"}), 404
    
    # Apply rate limiting based on IP address (or user ID if authenticated)
    client_id = request.headers.get('X-Forwarded-For', request.remote_addr)
    if hasattr(request, 'user'):
        client_id = request.user.get('sub', client_id)
    
    if not rate_limiter.is_allowed(client_id):
        return jsonify({"error": "Rate limit exceeded"}), 429
    
    # Authenticate request if needed
    if full_path not in PUBLIC_ROUTES and request.method != 'OPTIONS':
        # For OPTIONS requests, we skip authentication to handle CORS preflight
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({'message': 'Authentication required'}), 401
        
        try:
            # Decode the token
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            # Store user info for the microservice
            request.user = payload
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401
    
    # Construct target URL
    target_url = f"{SERVICE_REGISTRY[service]}/{path}"
    
    # Forward the request to the appropriate service
    try:
        # Prepare headers
        headers = {key: value for key, value in request.headers if key != 'Host'}
        
        # Add user info to request if authenticated
        if hasattr(request, 'user'):
            headers['X-User-ID'] = str(request.user.get('sub'))
            headers['X-User-Role'] = request.user.get('role', 'user')
        
        # Get request data
        data = request.get_data()
        logger.info(f"iv'e reached here")
        # Forward the request
        service_response = requests.request(
            method=request.method,
            url=target_url,
            headers=headers,
            params=request.args,
            data=data,
            cookies=request.cookies,
            timeout=30  # timeout in seconds
        )
        
        # Log the request for monitoring
        logger.info(f"Request: {request.method} {full_path} -> {service} | " +
                   f"Status: {service_response.status_code}")
        
        # Return the service response to the client
        response = Response(
            service_response.content,
            service_response.status_code,
            dict(service_response.headers)
        )
        return response
        
    except requests.RequestException as e:
        logger.error(f"Service request failed: {str(e)}")
        return jsonify({
            "error": "Service unavailable",
            "message": str(e)
        }), 503

# Custom error handlers
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not Found", "message": str(e)}), 404

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Server error: {str(e)}")
    return jsonify({"error": "Internal Server Error", "message": "An unexpected error occurred"}), 500

# Admin endpoint to view service registry
@app.route('/admin/services', methods=['GET'])
@token_required
def list_services():
    # Check if user has admin rights
    if request.user.get('role') != 'admin':
        return jsonify({"error": "Unauthorized"}), 403
        
    return jsonify(SERVICE_REGISTRY)

# Metrics endpoint (simplified)
@app.route('/metrics', methods=['GET'])
@token_required
def metrics():
    # In a real implementation, you might use Prometheus or another monitoring tool
    if request.user.get('role') != 'admin':
        return jsonify({"error": "Unauthorized"}), 403
        
    # Return some basic metrics
    return jsonify({
        "active_clients": len(rate_limiter.clients),
        "services": list(SERVICE_REGISTRY.keys())
    })

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug_mode = os.getenv('DEBUG', 'False').lower() == 'true'
    
    logger.info(f"Starting API Gateway on port {port}")
    logger.info(f"Registered services: {json.dumps(SERVICE_REGISTRY, indent=2)}")
    app.run(host='0.0.0.0', port=port, debug=debug_mode)