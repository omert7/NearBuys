import os
import uuid
import logging
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth
import re
from shared.utils.message_queue import MessageQueue
from shared.utils.prometheus_metrics import init_metrics, track_requests, track_user_activity
import atexit

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('user_service')

app = Flask(__name__)
CORS(app)

# Initialize Prometheus metrics
metrics_port = int(os.getenv('METRICS_PORT', 8001))
init_metrics('user-service', '1.0.0', metrics_port)
track_requests(app)

# Initialize message queue with retries
message_queue = None

def init_message_queue():
    global message_queue
    try:
        message_queue = MessageQueue(max_retries=5, retry_delay=5)
        logger.info("Successfully initialized message queue")
    except Exception as e:
        logger.error(f"Failed to initialize message queue: {str(e)}")
        raise

def close_message_queue():
    global message_queue
    if message_queue:
        try:
            message_queue.close()
            logger.info("Successfully closed message queue connection")
        except Exception as e:
            logger.error(f"Error closing message queue connection: {str(e)}")

# Initialize message queue on startup
init_message_queue()

# Register cleanup function
atexit.register(close_message_queue)

# JWT configuration
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-secret-key')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES', 3600))  # 1 hour default

# OAuth Configuration
oauth = OAuth(app)

# Setup OAuth providers
oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid email profile'},
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs'
)

oauth.register(
    name='facebook',
    client_id=os.getenv('FACEBOOK_CLIENT_ID'),
    client_secret=os.getenv('FACEBOOK_CLIENT_SECRET'),
    access_token_url='https://graph.facebook.com/oauth/access_token',
    access_token_params=None,
    authorize_url='https://www.facebook.com/v11.0/dialog/oauth',
    authorize_params=None,
    api_base_url='https://graph.facebook.com/v11.0/',
    client_kwargs={'scope': 'email public_profile'},
)

# Utility functions
def generate_token(user_id, role):
    """Generate a JWT token for the given user"""
    payload = {
        'exp': datetime.utcnow() + timedelta(seconds=app.config['JWT_ACCESS_TOKEN_EXPIRES']),
        'iat': datetime.utcnow(),
        'sub': str(user_id),
        'role': role
    }
    return jwt.encode(
        payload,
        app.config['JWT_SECRET_KEY'],
        algorithm='HS256'
    )

def token_required(f):
    """Decorator to require a valid JWT token"""
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
            payload = jwt.decode(
                token, 
                app.config['JWT_SECRET_KEY'],
                algorithms=['HS256']
            )
            current_user_id = payload['sub']
            current_user_role = payload['role']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401
            
        # Attach user info to request
        request.user_id = current_user_id
        request.user_role = current_user_role
        
        return f(*args, **kwargs)
    
    return decorated

def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not hasattr(request, 'user_role') or request.user_role != 'admin':
            return jsonify({'message': 'Admin access required'}), 403
        return f(*args, **kwargs)
    
    return decorated

def validate_email(email):
    """Validate email format"""
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(pattern, email) is not None

def validate_password(password):
    """Validate password strength"""
    # At least 8 characters, contains uppercase, lowercase, number, and special character
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
        
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
        
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one number"
        
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character"
        
    return True, "Password meets requirements"

# Routes
@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    try:
        # Check message queue connection
        if not message_queue or not message_queue.connection or message_queue.connection.is_closed:
            init_message_queue()
        return jsonify({'status': 'healthy', 'service': 'user-service'})
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500

@app.route('/api/users/register', methods=['POST'])
def register():
    try:
        logger.info(f"iv'e reached here")
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['username', 'email', 'password']
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400
            
        # Validate email format
        if not validate_email(data['email']):
            return jsonify({'error': 'Invalid email format'}), 400
            
        # Validate password strength
        is_valid, message = validate_password(data['password'])
        if not is_valid:
            return jsonify({'error': message}), 400
            
        # Hash password
        password_hash = generate_password_hash(data['password'])
        
        # Ensure message queue is connected
        if not message_queue or not message_queue.connection or message_queue.connection.is_closed:
            init_message_queue()

        # Track user registration
        track_user_activity('registration', 'new_user')

        # Send message to message processor
        response = message_queue.publish_and_wait('user.created', {
            'username': data['username'],
            'email': data['email'],
            'password_hash': password_hash
        })

        if response.get('status') != 'success':
            return jsonify({'error': f'Failed to create user {response.get("error")}'}), 500
            
        return jsonify(response), 201
        
    except Exception as e:
        logger.error(f"Error in register: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        
        # Validate required fields
        if not all(field in data for field in ['email', 'password']):
            return jsonify({'error': 'Missing required fields'}), 400
            
        # Ensure message queue is connected
        if not message_queue or not message_queue.connection or message_queue.connection.is_closed:
            init_message_queue()
        
        # Track login attempt
        track_user_activity('login_attempt', 'user')
            
        # Send message to message processor
        response = message_queue.publish_and_wait('user.login', {
            'email': data['email'],
            'password': data['password']
        })
        
        if not response:
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Track successful login
        if response.get('status') == 'success':
            track_user_activity('login_success', response.get('role', 'user'))
            
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Error in login: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/oauth/login/<provider>', methods=['GET'])
def oauth_login(provider):
    """Initiate OAuth login"""
    if provider not in ['google', 'facebook']:
        return jsonify({'message': 'Invalid provider'}), 400
        
    redirect_uri = oauth.create_client(provider).authorize_redirect()
    return redirect_uri

@app.route('/oauth/callback/<provider>', methods=['GET'])
def oauth_callback(provider):
    """Handle OAuth callback"""
    if provider not in ['google', 'facebook']:
        return jsonify({'message': 'Invalid provider'}), 400
        
    client = oauth.create_client(provider)
    token = client.authorize_access_token()
    user_info = client.get('userinfo').json()
    
    # Generate user ID
    user_id = str(uuid.uuid4())
    
    # Create user data
    user_data = {
        'id': user_id,
        'email': user_info.get('email'),
        'first_name': user_info.get('given_name', user_info.get('first_name')),
        'last_name': user_info.get('family_name', user_info.get('last_name')),
        'role': 'buyer',
        'oauth_provider': provider,
        'oauth_id': user_info.get('sub', user_info.get('id')),
        'is_active': True,
        'is_email_verified': True,
        'avatar_url': user_info.get('picture')
    }
    
    # Send message to RabbitMQ
    message_queue.publish('user.created', user_data)
    
    # Generate token
    token = generate_token(user_id, user_data['role'])
    
    return jsonify({
        'message': 'User registered successfully',
        'user_id': user_id,
        'token': token
    }), 201

@app.route('/api/users/<user_id>', methods=['GET'])
@token_required
def get_user(user_id):
    try:
        # Track user profile view
        track_user_activity('profile_view', request.user_role)
        
        # Send message to message processor
        response = message_queue.publish_and_wait('user.get_profile', {
            'user_id': user_id
        })
        
        if not response:
            return jsonify({'error': 'User not found'}), 404
            
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Error in get_user: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/<user_id>', methods=['PUT'])
@token_required
def update_user(user_id):
    try:
        data = request.get_json()
        
        # Validate user can only update their own profile
        if request.user_id != user_id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Track profile update
        track_user_activity('profile_update', request.user_role)
            
        # Send message to message processor
        response = message_queue.publish_and_wait('user.updated', {
            'id': user_id,
            **data
        })
        
        if not response:
            return jsonify({'error': 'Failed to update user'}), 500
            
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Error in update_user: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/<user_id>/password', methods=['PUT'])
@token_required
def change_password(user_id):
    try:
        data = request.get_json()
        
        # Validate user can only change their own password
        if request.user_id != user_id:
            return jsonify({'error': 'Unauthorized'}), 403
            
        # Validate required fields
        if not all(field in data for field in ['current_password', 'new_password']):
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Track password change
        track_user_activity('password_change', request.user_role)
            
        # Send message to message processor
        response = message_queue.publish_and_wait('user.password_change', {
            'user_id': user_id,
            'current_password': data['current_password'],
            'new_password': data['new_password']
        })
        
        if not response:
            return jsonify({'error': 'Failed to change password'}), 500
            
        return jsonify({'message': 'Password changed successfully'}), 200
        
    except Exception as e:
        logger.error(f"Error in change_password: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/<user_id>/addresses', methods=['POST'])
@token_required
def add_address(user_id):
    try:
        data = request.get_json()
        
        # Validate user can only add address to their own profile
        if request.user_id != user_id:
            return jsonify({'error': 'Unauthorized'}), 403
            
        # Generate address ID
        address_id = str(uuid.uuid4())
        
        # Track address addition
        track_user_activity('address_added', request.user_role)
        
        # Send message to message processor
        response = message_queue.publish_and_wait('user.address_added', {
            'id': address_id,
            'user_id': user_id,
            **data
        })
        
        if not response:
            return jsonify({'error': 'Failed to add address'}), 500
            
        return jsonify(response), 201
        
    except Exception as e:
        logger.error(f"Error in add_address: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/<user_id>/addresses/<address_id>', methods=['PUT'])
@token_required
def update_address(user_id, address_id):
    try:
        data = request.get_json()
        
        # Validate user can only update their own addresses
        if request.user_id != user_id:
            return jsonify({'error': 'Unauthorized'}), 403
            
        # Send message to message processor
        response = message_queue.publish_and_wait('user.address_updated', {
            'id': address_id,
            'user_id': user_id,
            **data
        })
        
        if not response:
            return jsonify({'error': 'Failed to update address'}), 500
            
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Error in update_address: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/<user_id>/addresses/<address_id>', methods=['DELETE'])
@token_required
def delete_address(user_id, address_id):
    try:
        # Validate user can only delete their own addresses
        if request.user_id != user_id:
            return jsonify({'error': 'Unauthorized'}), 403
            
        # Send message to message processor
        response = message_queue.publish_and_wait('user.address_deleted', {
            'id': address_id,
            'user_id': user_id
        })
        
        if not response:
            return jsonify({'error': 'Failed to delete address'}), 500
            
        return jsonify({'message': 'Address deleted successfully'}), 200
        
    except Exception as e:
        logger.error(f"Error in delete_address: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/<user_id>/preferences', methods=['PUT'])
@token_required
def update_preferences(user_id):
    try:
        data = request.get_json()
        
        # Validate user can only update their own preferences
        if request.user_id != user_id:
            return jsonify({'error': 'Unauthorized'}), 403
            
        # Send message to message processor
        response = message_queue.publish_and_wait('user.preferences_updated', {
            'user_id': user_id,
            'preferences': data
        })
        
        if not response:
            return jsonify({'error': 'Failed to update preferences'}), 500
            
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Error in update_preferences: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/<user_id>/privacy', methods=['PUT'])
@token_required
def update_privacy_settings(user_id):
    try:
        data = request.get_json()
        
        # Validate user can only update their own privacy settings
        if request.user_id != user_id:
            return jsonify({'error': 'Unauthorized'}), 403
            
        # Send message to message processor
        response = message_queue.publish_and_wait('user.privacy_settings_updated', {
            'user_id': user_id,
            'privacy_settings': data
        })
        
        if not response:
            return jsonify({'error': 'Failed to update privacy settings'}), 500
            
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Error in update_privacy_settings: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/<user_id>/deactivate', methods=['POST'])
@token_required
def deactivate_user(user_id):
    try:
        # Validate user can only deactivate their own account
        if request.user_id != user_id:
            return jsonify({'error': 'Unauthorized'}), 403
            
        # Send message to message processor
        response = message_queue.publish_and_wait('user.deactivated', {
            'user_id': user_id
        })
        
        if not response:
            return jsonify({'error': 'Failed to deactivate user'}), 500
            
        return jsonify({'message': 'User deactivated successfully'}), 200
        
    except Exception as e:
        logger.error(f"Error in deactivate_user: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/<user_id>/reactivate', methods=['POST'])
@token_required
def reactivate_user(user_id):
    try:
        # Validate user can only reactivate their own account
        if request.user_id != user_id:
            return jsonify({'error': 'Unauthorized'}), 403
            
        # Send message to message processor
        response = message_queue.publish_and_wait('user.reactivated', {
            'user_id': user_id
        })
        if not response:
            return jsonify({'error': 'Failed to reactivate user'}), 500
            
        return jsonify({'message': 'User reactivated successfully'}), 200
        
    except Exception as e:
        logger.error(f"Error in reactivate_user: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/users/<user_id>/ratings', methods=['GET'])
@token_required
def get_user_ratings(user_id):
    """Get user ratings"""
    # Send message to RabbitMQ
    message_queue.publish('user.get_ratings', {
        'user_id': user_id,
        'requested_by': request.user_id
    })
    
    return jsonify({
        'message': 'Ratings request received',
        'status': 'processing'
    }), 202

@app.route('/users/<user_id>/ratings', methods=['POST'])
@token_required
def rate_user(user_id):
    """Rate a user"""
    data = request.get_json()
    
    if not data or not data.get('rating'):
        return jsonify({'message': 'Rating is required'}), 400
        
    if not 1 <= data['rating'] <= 5:
        return jsonify({'message': 'Rating must be between 1 and 5'}), 400
        
    # Send message to RabbitMQ
    message_queue.publish('user.rated', {
        'from_user_id': request.user_id,
        'to_user_id': user_id,
        'rating': data['rating'],
        'review': data.get('review')
    })
    
    return jsonify({
        'message': 'Rating request received',
        'status': 'processing'
    }), 202

@app.route('/addresses', methods=['GET'])
@token_required
def get_addresses():
    """Get user addresses"""
    # Send message to RabbitMQ
    message_queue.publish('user.get_addresses', {
        'user_id': request.user_id
    })
    
    return jsonify({
        'message': 'Addresses request received',
        'status': 'processing'
    }), 202

@app.route('/verify-address/<address_id>', methods=['POST'])
@token_required
def initiate_address_verification(address_id):
    """Initiate address verification"""
    # Send message to RabbitMQ
    message_queue.publish('user.address_verification_initiated', {
        'user_id': request.user_id,
        'address_id': address_id
    })
    
    return jsonify({
        'message': 'Address verification request received',
        'status': 'processing'
    }), 202

@app.route('/preferences', methods=['GET'])
@token_required
def get_preferences():
    """Get user preferences"""
    # Send message to RabbitMQ
    message_queue.publish('user.get_preferences', {
        'user_id': request.user_id
    })
    
    return jsonify({
        'message': 'Preferences request received',
        'status': 'processing'
    }), 202

@app.route('/privacy-settings', methods=['GET'])
@token_required
def get_privacy_settings():
    """Get user privacy settings"""
    # Send message to RabbitMQ
    message_queue.publish('user.get_privacy_settings', {
        'user_id': request.user_id
    })
    
    return jsonify({
        'message': 'Privacy settings request received',
        'status': 'processing'
    }), 202

@app.route('/admin/users', methods=['GET'])
@token_required
@admin_required
def list_users():
    """List all users (admin only)"""
    # Send message to RabbitMQ
    message_queue.publish('user.list', {
        'requested_by': request.user_id
    })
    
    return jsonify({
        'message': 'Users list request received',
        'status': 'processing'
    }), 202

@app.route('/admin/users/<user_id>', methods=['GET'])
@token_required
@admin_required
def admin_get_user(user_id):
    """Get user details (admin only)"""
    # Send message to RabbitMQ
    message_queue.publish('user.admin_get', {
        'user_id': user_id,
        'requested_by': request.user_id
    })
    
    return jsonify({
        'message': 'User details request received',
        'status': 'processing'
    }), 202

@app.route('/admin/users/<user_id>', methods=['PUT'])
@token_required
@admin_required
def admin_update_user(user_id):
    """Update user details (admin only)"""
    data = request.get_json()
    
    if not data:
        return jsonify({'message': 'No data provided'}), 400
        
    # Add user ID to data
    data['user_id'] = user_id
    data['updated_by'] = request.user_id
    
    # Send message to RabbitMQ
    message_queue.publish('user.admin_updated', data)
    
    return jsonify({
        'message': 'User update request received',
        'status': 'processing'
    }), 202

@app.route('/admin/verify-address/<address_id>', methods=['POST'])
@token_required
@admin_required
def admin_verify_address(address_id):
    """Verify user address (admin only)"""
    # Send message to RabbitMQ
    message_queue.publish('user.address_verified', {
        'address_id': address_id,
        'verified_by': request.user_id
    })
    
    return jsonify({
        'message': 'Address verification request received',
        'status': 'processing'
    }), 202

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5003))
    app.run(host='0.0.0.0', port=port)