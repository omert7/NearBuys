import os
import uuid
import logging
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy import text
from sqlalchemy.sql import func
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from dotenv import load_dotenv
from sqlalchemy.exc import SQLAlchemyError
from authlib.integrations.flask_client import OAuth
import re
from shared.utils.message_queue import MessageQueue

# Initialize message queue
message_queue = MessageQueue()

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

# Database configuration
schema = os.getenv('DATABASE_SCHEMA', 'users')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-secret-key')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES', 3600))  # 1 hour default

db = SQLAlchemy(app)

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

# Models
class User(db.Model):
    __tablename__ = 'users'
    __table_args__ = {'schema': schema}
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=True)  # Nullable for OAuth users
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    role = db.Column(db.String(20), nullable=False, default='buyer')  # buyer, seller, admin
    oauth_provider = db.Column(db.String(20), nullable=True)  # google, facebook, etc.
    oauth_id = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=func.now())
    updated_at = db.Column(db.DateTime, nullable=False, default=func.now(), onupdate=func.now())
    last_login = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    is_email_verified = db.Column(db.Boolean, nullable=False, default=False)
    avatar_url = db.Column(db.String(255), nullable=True)
    
    def __repr__(self):
        return f'<User {self.email}>'

class Profile(db.Model):
    __tablename__ = 'profiles'
    __table_args__ = {'schema': schema}
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('users.id'), nullable=False)
    bio = db.Column(db.Text, nullable=True)
    preferences = db.Column(JSONB, nullable=True)
    privacy_settings = db.Column(JSONB, nullable=False, default={
        'share_location': False,
        'visible_to_public': True,
        'receive_notifications': True
    })
    created_at = db.Column(db.DateTime, nullable=False, default=func.now())
    updated_at = db.Column(db.DateTime, nullable=False, default=func.now(), onupdate=func.now())
    
    user = db.relationship('User', backref=db.backref('profile', uselist=False))
    
    def __repr__(self):
        return f'<Profile for user {self.user_id}>'

class Address(db.Model):
    __tablename__ = 'addresses'
    __table_args__ = {'schema': schema}
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('users.id'), nullable=False)
    street = db.Column(db.String(255), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    state = db.Column(db.String(100), nullable=False)
    zip_code = db.Column(db.String(20), nullable=False)
    country = db.Column(db.String(100), nullable=False, default='United States')
    is_primary = db.Column(db.Boolean, nullable=False, default=True)
    lat = db.Column(db.Float, nullable=True)
    lng = db.Column(db.Float, nullable=True)
    is_verified = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=func.now())
    updated_at = db.Column(db.DateTime, nullable=False, default=func.now(), onupdate=func.now())
    
    user = db.relationship('User', backref=db.backref('addresses', lazy=True))
    
    def __repr__(self):
        return f'<Address {self.street}, {self.city}>'

class Rating(db.Model):
    __tablename__ = 'ratings'
    __table_args__ = {'schema': schema}
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    from_user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('users.id'), nullable=False)
    to_user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('users.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)  # 1-5 stars
    review = db.Column(db.Text, nullable=True)
    transaction_id = db.Column(UUID(as_uuid=True), nullable=True)  # Optional reference to a transaction
    created_at = db.Column(db.DateTime, nullable=False, default=func.now())
    updated_at = db.Column(db.DateTime, nullable=False, default=func.now(), onupdate=func.now())
    
    from_user = db.relationship('User', foreign_keys=[from_user_id], backref=db.backref('ratings_given', lazy=True))
    to_user = db.relationship('User', foreign_keys=[to_user_id], backref=db.backref('ratings_received', lazy=True))
    
    def __repr__(self):
        return f'<Rating {self.rating} from {self.from_user_id} to {self.to_user_id}>'

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
        # Test database connection
        db.session.execute(text('SELECT 1'))
        return jsonify({'status': 'UP'}), 200
    except SQLAlchemyError as e:
        logger.error(f"Database health check failed: {e}")
        return jsonify({'status': 'DOWN', 'message': 'Database connection error'}), 500

@app.route('/register', methods=['POST'])
def register():
    """Register a new user"""
    data = request.get_json()
    
    # Validate required fields
    required_fields = ['email', 'password', 'first_name', 'last_name']
    for field in required_fields:
        if field not in data:
            return jsonify({'message': f'Missing required field: {field}'}), 400
    
    # Validate email format
    if not validate_email(data['email']):
        return jsonify({'message': 'Invalid email format'}), 400
    
    # Check if user already exists
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'User with this email already exists'}), 409
    
    # Validate password strength
    password_valid, password_message = validate_password(data['password'])
    if not password_valid:
        return jsonify({'message': password_message}), 400
    
    try:
        # Create new user
        new_user = User(
            email=data['email'],
            password_hash=generate_password_hash(data['password']),
            first_name=data['first_name'],
            last_name=data['last_name'],
            phone=data.get('phone'),
            role=data.get('role', 'buyer')
        )
        
        # Save to database
        db.session.add(new_user)
        db.session.flush()  # Flush to get the ID
        
        # Create default profile
        new_profile = Profile(
            user_id=new_user.id,
            preferences=data.get('preferences', {}),
            privacy_settings=data.get('privacy_settings', {
                'share_location': False,
                'visible_to_public': True,
                'receive_notifications': True
            })
        )
        db.session.add(new_profile)
        
        # Create address if provided
        if 'address' in data:
            addr = data['address']
            new_address = Address(
                user_id=new_user.id,
                street=addr.get('street', ''),
                city=addr.get('city', ''),
                state=addr.get('state', ''),
                zip_code=addr.get('zip_code', ''),
                country=addr.get('country', 'United States'),
                is_primary=True
            )
            db.session.add(new_address)
        
        db.session.commit()
        
        # Generate token
        token = generate_token(new_user.id, new_user.role)
        
        return jsonify({
            'message': 'User registered successfully',
            'user_id': str(new_user.id),
            'token': token
        }), 201
        
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Registration error: {e}")
        return jsonify({'message': 'An error occurred during registration'}), 500

@app.route('/login', methods=['POST'])
def login():
    """Authenticate user and return token"""
    data = request.get_json()
    
    # Validate required fields
    if 'email' not in data or 'password' not in data:
        return jsonify({'message': 'Email and password are required'}), 400
    
    try:
        # Find user by email
        user = User.query.filter_by(email=data['email']).first()
        
        # Check if user exists and password is correct
        if not user or not check_password_hash(user.password_hash, data['password']):
            return jsonify({'message': 'Invalid email or password'}), 401
        
        # Check if user is active
        if not user.is_active:
            return jsonify({'message': 'Account is deactivated'}), 403
        
        # Update last login time
        user.last_login = func.now()
        db.session.commit()
        
        # Generate token
        token = generate_token(user.id, user.role)
        
        return jsonify({
            'message': 'Login successful',
            'user_id': str(user.id),
            'token': token,
            'role': user.role
        }), 200
        
    except SQLAlchemyError as e:
        logger.error(f"Login error: {e}")
        return jsonify({'message': 'An error occurred during login'}), 500

@app.route('/oauth/login/<provider>', methods=['GET'])
def oauth_login(provider):
    """Initiate OAuth login flow"""
    if provider not in oauth.registrations:
        return jsonify({'message': f'Unsupported OAuth provider: {provider}'}), 400
    
    redirect_uri = url_for('oauth_callback', provider=provider, _external=True)
    return oauth.create_client(provider).authorize_redirect(redirect_uri)

@app.route('/oauth/callback/<provider>', methods=['GET'])
def oauth_callback(provider):
    """Handle OAuth callback"""
    if provider not in oauth.registrations:
        return jsonify({'message': f'Unsupported OAuth provider: {provider}'}), 400
    
    try:
        token = oauth.create_client(provider).authorize_access_token()
        
        if provider == 'google':
            user_info = oauth.google.get('userinfo').json()
            email = user_info.get('email')
            first_name = user_info.get('given_name', '')
            last_name = user_info.get('family_name', '')
            oauth_id = user_info.get('id')
            avatar_url = user_info.get('picture')
        
        elif provider == 'facebook':
            user_info = oauth.facebook.get('me?fields=id,email,first_name,last_name,picture').json()
            email = user_info.get('email')
            first_name = user_info.get('first_name', '')
            last_name = user_info.get('last_name', '')
            oauth_id = user_info.get('id')
            avatar_url = user_info.get('picture', {}).get('data', {}).get('url')
        
        # Check if email is provided
        if not email:
            return jsonify({'message': 'Email not provided by OAuth provider'}), 400
        
        # Find or create user
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Update OAuth info if needed
            if not user.oauth_id:
                user.oauth_provider = provider
                user.oauth_id = oauth_id
                user.avatar_url = avatar_url
        else:
            # Create new user
            user = User(
                email=email,
                first_name=first_name,
                last_name=last_name,
                oauth_provider=provider,
                oauth_id=oauth_id,
                is_email_verified=True,  # Trust email verification from OAuth
                avatar_url=avatar_url
            )
            db.session.add(user)
            db.session.flush()
            
            # Create default profile
            profile = Profile(user_id=user.id)
            db.session.add(profile)
        
        # Update last login time
        user.last_login = func.now()
        db.session.commit()
        
        # Generate token
        token = generate_token(user.id, user.role)
        
        # This could redirect to a frontend page with the token
        # For API usage, we'll just return the token
        return jsonify({
            'message': 'OAuth login successful',
            'user_id': str(user.id),
            'token': token,
            'role': user.role
        }), 200
        
    except Exception as e:
        logger.error(f"OAuth callback error: {e}")
        return jsonify({'message': 'An error occurred during OAuth login'}), 500

@app.route('/me', methods=['GET'])
@token_required
def get_user_profile():
    """Get current user profile"""
    try:
        user = User.query.get(request.user_id)
        
        if not user:
            return jsonify({'message': 'User not found'}), 404
        
        # Get profile
        profile = Profile.query.filter_by(user_id=user.id).first()
        
        # Get primary address
        address = Address.query.filter_by(user_id=user.id, is_primary=True).first()
        
        # Calculate average rating
        rating_query = db.session.query(
            func.avg(Rating.rating).label('avg_rating'),
            func.count(Rating.id).label('total_ratings')
        ).filter(Rating.to_user_id == user.id).first()
        
        avg_rating = float(rating_query.avg_rating) if rating_query.avg_rating else 0
        total_ratings = rating_query.total_ratings
        
        return jsonify({
            'id': str(user.id),
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'phone': user.phone,
            'role': user.role,
            'created_at': user.created_at.isoformat(),
            'last_login': user.last_login.isoformat() if user.last_login else None,
            'is_active': user.is_active,
            'is_email_verified': user.is_email_verified,
            'avatar_url': user.avatar_url,
            'profile': {
                'bio': profile.bio if profile else None,
                'preferences': profile.preferences if profile else {},
                'privacy_settings': profile.privacy_settings if profile else {}
            },
            'primary_address': {
                'street': address.street,
                'city': address.city,
                'state': address.state,
                'zip_code': address.zip_code,
                'country': address.country,
                'is_verified': address.is_verified
            } if address else None,
            'reputation': {
                'avg_rating': avg_rating,
                'total_ratings': total_ratings
            }
        }), 200
        
    except SQLAlchemyError as e:
        logger.error(f"Get profile error: {e}")
        return jsonify({'message': 'An error occurred while retrieving user profile'}), 500

@app.route('/me', methods=['PUT'])
@token_required
def update_user_profile():
    """Update current user profile"""
    data = request.get_json()
    
    try:
        user = User.query.get(request.user_id)
        
        if not user:
            return jsonify({'message': 'User not found'}), 404
        
        # Update user fields
        updateable_fields = ['first_name', 'last_name', 'phone', 'avatar_url']
        for field in updateable_fields:
            if field in data:
                setattr(user, field, data[field])
        
        # Update profile
        if 'profile' in data:
            profile = Profile.query.filter_by(user_id=user.id).first()
            
            if not profile:
                profile = Profile(user_id=user.id)
                db.session.add(profile)
            
            profile_data = data['profile']
            if 'bio' in profile_data:
                profile.bio = profile_data['bio']
            
            if 'preferences' in profile_data:
                profile.preferences = profile_data['preferences']
            
            if 'privacy_settings' in profile_data:
                # Update existing keys without overwriting all settings
                for key, value in profile_data['privacy_settings'].items():
                    profile.privacy_settings[key] = value
        
        # Update address
        if 'address' in data:
            address = Address.query.filter_by(user_id=user.id, is_primary=True).first()
            
            addr_data = data['address']
            if address:
                # Update existing address
                for field in ['street', 'city', 'state', 'zip_code', 'country']:
                    if field in addr_data:
                        setattr(address, field, addr_data[field])
                
                # Reset verification if address changed
                address.is_verified = False
            else:
                # Create new address
                new_address = Address(
                    user_id=user.id,
                    street=addr_data.get('street', ''),
                    city=addr_data.get('city', ''),
                    state=addr_data.get('state', ''),
                    zip_code=addr_data.get('zip_code', ''),
                    country=addr_data.get('country', 'United States'),
                    is_primary=True
                )
                db.session.add(new_address)
        
        db.session.commit()
        
        return jsonify({'message': 'Profile updated successfully'}), 200
        
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Update profile error: {e}")
        return jsonify({'message': 'An error occurred while updating user profile'}), 500

@app.route('/me/password', methods=['PUT'])
@token_required
def change_password():
    """Change user password"""
    data = request.get_json()
    
    # Validate required fields
    if 'current_password' not in data or 'new_password' not in data:
        return jsonify({'message': 'Current password and new password are required'}), 400
    
    try:
        user = User.query.get(request.user_id)
        
        if not user:
            return jsonify({'message': 'User not found'}), 404
        
        # OAuth users without password
        if not user.password_hash:
            return jsonify({'message': 'Password change not available for OAuth users'}), 400
        
        # Verify current password
        if not check_password_hash(user.password_hash, data['current_password']):
            return jsonify({'message': 'Current password is incorrect'}), 401
        
        # Validate new password strength
        password_valid, password_message = validate_password(data['new_password'])
        if not password_valid:
            return jsonify({'message': password_message}), 400
        
        # Update password
        user.password_hash = generate_password_hash(data['new_password'])
        db.session.commit()
        
        return jsonify({'message': 'Password changed successfully'}), 200
        
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Password change error: {e}")
        return jsonify({'message': 'An error occurred while changing password'}), 500

@app.route('/users/<user_id>', methods=['GET'])
@token_required
def get_user(user_id):
    """Get public user profile by ID"""
    try:
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'message': 'User not found'}), 404
        
        # Get profile for privacy settings
        profile = Profile.query.filter_by(user_id=user.id).first()
        
        # Check privacy settings
        is_public = True
        if profile and profile.privacy_settings:
            is_public = profile.privacy_settings.get('visible_to_public', True)
        
        # If not public and not current user
        if not is_public and str(user.id) != request.user_id:
            return jsonify({'message': 'This profile is private'}), 403
        
        # Calculate average rating
        rating_query = db.session.query(
            func.avg(Rating.rating).label('avg_rating'),
            func.count(Rating.id).label('total_ratings')
        ).filter(Rating.to_user_id == user.id).first()
        
        avg_rating = float(rating_query.avg_rating) if rating_query.avg_rating else 0
        total_ratings = rating_query.total_ratings
        
        # Determine if address should be shared
        share_location = False
        if profile and profile.privacy_settings:
            share_location = profile.privacy_settings.get('share_location', False)
        
        # Get location if sharing is enabled
        location = None
        if share_location or str(user.id) == request.user_id:
            address = Address.query.filter_by(user_id=user.id, is_primary=True).first()
            if address:
                location = {
                    'city': address.city,
                    'state': address.state
                }
                # Full address only for self
                if str(user.id) == request.user_id:
                    location.update({
                        'street': address.street,
                        'zip_code': address.zip_code,
                        'country': address.country,
                        'is_verified': address.is_verified
                    })
        
        return jsonify({
            'id': str(user.id),
            'first_name': user.first_name,
            'last_name': user.last_name,
            'role': user.role,
            'created_at': user.created_at.isoformat(),
            'avatar_url': user.avatar_url,
            'bio': profile.bio if profile else None,
            'location': location,
            'reputation': {
                'avg_rating': avg_rating,
                'total_ratings': total_ratings
            }
        }), 200
        
    except SQLAlchemyError as e:
        logger.error(f"Get user error: {e}")
        return jsonify({'message': 'An error occurred while retrieving user profile'}), 500

@app.route('/users/<user_id>/ratings', methods=['GET'])
@token_required
def get_user_ratings(user_id):
    """Get ratings for a user"""
    try:
        # Check if user exists
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'message': 'User not found'}), 404
        
        # Get ratings
        ratings = Rating.query.filter_by(to_user_id=user_id).order_by(Rating.created_at.desc()).all()
        
        # Calculate summary
        rating_counts = {i: 0 for i in range(1, 6)}  # Initialize counts for 1-5 stars
        for rating in ratings:
            rating_counts[rating.rating] = rating_counts.get(rating.rating, 0) + 1
        
        total_ratings = len(ratings)
        avg_rating = sum(r.rating for r in ratings) / total_ratings if total_ratings > 0 else 0
        
        # Format ratings for response
        ratings_data = []
        for rating in ratings:
            from_user = User.query.get(rating.from_user_id)
            ratings_data.append({
                'id': str(rating.id),
                'rating': rating.rating,
                'review': rating.review,
                'created_at': rating.created_at.isoformat(),
                'from_user': {
                    'id': str(from_user.id),
                    'name': f"{from_user.first_name} {from_user.last_name}",
                    'avatar_url': from_user.avatar_url
                }
            })
        
        return jsonify({
            'user_id': user_id,
            'summary': {
                'avg_rating': avg_rating,
                'total_ratings': total_ratings,
                'rating_counts': rating_counts
            },
            'ratings': ratings_data
        }), 200
        
    except SQLAlchemyError as e:
        logger.error(f"Get ratings error: {e}")
        return jsonify({'message': 'An error occurred while retrieving user ratings'}), 500

@app.route('/users/<user_id>/ratings', methods=['POST'])
@token_required
def rate_user(user_id):
    """Add a rating for a user"""
    data = request.get_json()
    
    # Validate required fields
    if 'rating' not in data:
        return jsonify({'message': 'Rating value is required'}), 400
    
    # Validate rating value
    rating_value = data['rating']
    if not isinstance(rating_value, int) or rating_value < 1 or rating_value > 5:
        return jsonify({'message': 'Rating must be an integer between 1 and 5'}), 400
    
    try:
        # Check if user exists
        to_user = User.query.get(user_id)
        
        if not to_user:
            return jsonify({'message': 'User not found'}), 404
        
        # Cannot rate yourself
        if str(to_user.id) == request.user_id:
            return jsonify({'message': 'You cannot rate yourself'}), 400
        
        # Check if already rated
        existing_rating = Rating.query.filter_by(
            from_user_id=request.user_id,
            to_user_id=user_id,
            transaction_id=data.get('transaction_id')
        ).first()
        
        if existing_rating:
            # Update existing rating
            existing_rating.rating = rating_value
            existing_rating.review = data.get('review')
            existing_rating.updated_at = func.now()
        else:
            # Create new rating
            new_rating = Rating(
                from_user_id=request.user_id,
                to_user_id=user_id,
                rating=rating_value,
                review=data.get('review'),
                transaction_id=data.get('transaction_id')
            )
            db.session.add(new_rating)
        
        db.session.commit()
        
        return jsonify({'message': 'Rating submitted successfully'}), 201
        
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Create rating error: {e}")
        return jsonify({'message': 'An error occurred while submitting rating'}), 500

@app.route('/addresses', methods=['GET'])
@token_required
def get_addresses():
    """Get all addresses for current user"""
    try:
        addresses = Address.query.filter_by(user_id=request.user_id).all()
        
        result = []
        for address in addresses:
            result.append({
                'id': str(address.id),
                'street': address.street,
                'city': address.city,
                'state': address.state,
                'zip_code': address.zip_code,
                'country': address.country,
                'is_primary': address.is_primary,
                'is_verified': address.is_verified,
                'lat': address.lat,
                'lng': address.lng,
                'created_at': address.created_at.isoformat()
            })
        
        return jsonify(result), 200
        
    except SQLAlchemyError as e:
        logger.error(f"Get addresses error: {e}")
        return jsonify({'message': 'An error occurred while retrieving addresses'}), 500

@app.route('/addresses', methods=['POST'])
@token_required
def add_address():
    """Add a new address for current user"""
    data = request.get_json()
    
    # Validate required fields
    required_fields = ['street', 'city', 'state', 'zip_code']
    for field in required_fields:
        if field not in data:
            return jsonify({'message': f'Missing required field: {field}'}), 400
    
    try:
        # Check if setting as primary
        is_primary = data.get('is_primary', False)
        
        # If setting as primary, update existing primary address
        if is_primary:
            Address.query.filter_by(user_id=request.user_id, is_primary=True).update({'is_primary': False})
        
        # Create new address
        new_address = Address(
            user_id=request.user_id,
            street=data['street'],
            city=data['city'],
            state=data['state'],
            zip_code=data['zip_code'],
            country=data.get('country', 'United States'),
            is_primary=is_primary
        )
        
        # Add geocoding here if needed
        # new_address.lat = ...
        # new_address.lng = ...
        
        db.session.add(new_address)
        db.session.commit()
        
        return jsonify({
            'message': 'Address added successfully',
            'address_id': str(new_address.id)
        }), 201
        
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Add address error: {e}")
        return jsonify({'message': 'An error occurred while adding address'}), 500

@app.route('/addresses/<address_id>', methods=['PUT'])
@token_required
def update_address(address_id):
    """Update an address"""
    data = request.get_json()
    
    try:
        # Find address
        address = Address.query.get(address_id)
        
        if not address:
            return jsonify({'message': 'Address not found'}), 404
        
        # Verify ownership
        if str(address.user_id) != request.user_id:
            return jsonify({'message': 'Unauthorized to modify this address'}), 403
        
        # Update fields
        updateable_fields = ['street', 'city', 'state', 'zip_code', 'country']
        for field in updateable_fields:
            if field in data:
                setattr(address, field, data[field])
        
        # Handle is_primary flag
        if 'is_primary' in data and data['is_primary'] and not address.is_primary:
            Address.query.filter_by(user_id=request.user_id, is_primary=True).update({'is_primary': False})
            address.is_primary = True
        
        # Reset verification if address changed
        address.is_verified = False
        
        # Add geocoding update here if needed
        # address.lat = ...
        # address.lng = ...
        
        db.session.commit()
        
        return jsonify({'message': 'Address updated successfully'}), 200
        
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Update address error: {e}")
        return jsonify({'message': 'An error occurred while updating address'}), 500

@app.route('/addresses/<address_id>', methods=['DELETE'])
@token_required
def delete_address(address_id):
    """Delete an address"""
    try:
        # Find address
        address = Address.query.get(address_id)
        
        if not address:
            return jsonify({'message': 'Address not found'}), 404
        
        # Verify ownership
        if str(address.user_id) != request.user_id:
            return jsonify({'message': 'Unauthorized to delete this address'}), 403
        
        # Cannot delete primary address if it's the only one
        if address.is_primary and Address.query.filter_by(user_id=request.user_id).count() == 1:
            return jsonify({'message': 'Cannot delete the only address'}), 400
        
        # If deleting primary, set another as primary
        if address.is_primary:
            next_address = Address.query.filter_by(user_id=request.user_id).filter(Address.id != address_id).first()
            if next_address:
                next_address.is_primary = True
        
        # Delete the address
        db.session.delete(address)
        db.session.commit()
        
        return jsonify({'message': 'Address deleted successfully'}), 200
        
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Delete address error: {e}")
        return jsonify({'message': 'An error occurred while deleting address'}), 500

@app.route('/verify-address/<address_id>', methods=['POST'])
@token_required
def initiate_address_verification(address_id):
    """Initiate address verification process"""
    try:
        # Find address
        address = Address.query.get(address_id)
        
        if not address:
            return jsonify({'message': 'Address not found'}), 404
        
        # Verify ownership
        if str(address.user_id) != request.user_id:
            return jsonify({'message': 'Unauthorized to verify this address'}), 403
        
        # In a real implementation, this would initiate a verification process
        # For now, we'll simulate it with a success message
        
        return jsonify({
            'message': 'Address verification initiated',
            'verification_id': str(uuid.uuid4())
        }), 200
        
    except SQLAlchemyError as e:
        logger.error(f"Address verification error: {e}")
        return jsonify({'message': 'An error occurred during address verification'}), 500

@app.route('/preferences', methods=['GET'])
@token_required
def get_preferences():
    """Get user preferences"""
    try:
        profile = Profile.query.filter_by(user_id=request.user_id).first()
        
        if not profile:
            return jsonify({'message': 'Profile not found'}), 404
        
        return jsonify(profile.preferences or {}), 200
        
    except SQLAlchemyError as e:
        logger.error(f"Get preferences error: {e}")
        return jsonify({'message': 'An error occurred while retrieving preferences'}), 500

@app.route('/preferences', methods=['PUT'])
@token_required
def update_preferences():
    """Update user preferences"""
    data = request.get_json()
    
    try:
        profile = Profile.query.filter_by(user_id=request.user_id).first()
        
        if not profile:
            profile = Profile(user_id=request.user_id)
            db.session.add(profile)
        
        # Initialize preferences if None
        if profile.preferences is None:
            profile.preferences = {}
        
        # Update preferences
        for key, value in data.items():
            profile.preferences[key] = value
        
        db.session.commit()
        
        return jsonify({'message': 'Preferences updated successfully'}), 200
        
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Update preferences error: {e}")
        return jsonify({'message': 'An error occurred while updating preferences'}), 500

@app.route('/privacy-settings', methods=['GET'])
@token_required
def get_privacy_settings():
    """Get user privacy settings"""
    try:
        profile = Profile.query.filter_by(user_id=request.user_id).first()
        
        if not profile:
            return jsonify({'message': 'Profile not found'}), 404
        
        return jsonify(profile.privacy_settings or {}), 200
        
    except SQLAlchemyError as e:
        logger.error(f"Get privacy settings error: {e}")
        return jsonify({'message': 'An error occurred while retrieving privacy settings'}), 500

@app.route('/privacy-settings', methods=['PUT'])
@token_required
def update_privacy_settings():
    """Update user privacy settings"""
    data = request.get_json()
    
    try:
        profile = Profile.query.filter_by(user_id=request.user_id).first()
        
        if not profile:
            profile = Profile(user_id=request.user_id)
            db.session.add(profile)
        
        # Initialize privacy settings if None
        if profile.privacy_settings is None:
            profile.privacy_settings = {
                'share_location': False,
                'visible_to_public': True,
                'receive_notifications': True
            }
        
        # Update settings
        for key, value in data.items():
            profile.privacy_settings[key] = value
        
        db.session.commit()
        
        return jsonify({'message': 'Privacy settings updated successfully'}), 200
        
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Update privacy settings error: {e}")
        return jsonify({'message': 'An error occurred while updating privacy settings'}), 500

@app.route('/deactivate', methods=['POST'])
@token_required
def deactivate_account():
    """Deactivate user account"""
    data = request.get_json()
    
    # Require password confirmation
    if 'password' not in data:
        return jsonify({'message': 'Password confirmation required'}), 400
    
    try:
        user = User.query.get(request.user_id)
        
        if not user:
            return jsonify({'message': 'User not found'}), 404
        
        # OAuth users without password
        if not user.password_hash:
            # For OAuth users, we might want a different verification method
            # For now, we'll allow deactivation without password check
            pass
        else:
            # Verify password
            if not check_password_hash(user.password_hash, data['password']):
                return jsonify({'message': 'Incorrect password'}), 401
        
        # Deactivate account
        user.is_active = False
        db.session.commit()
        
        return jsonify({'message': 'Account deactivated successfully'}), 200
        
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Deactivate account error: {e}")
        return jsonify({'message': 'An error occurred while deactivating account'}), 500

@app.route('/reactivate', methods=['POST'])
def reactivate_account():
    """Reactivate user account"""
    data = request.get_json()
    
    # Validate required fields
    if 'email' not in data or 'password' not in data:
        return jsonify({'message': 'Email and password are required'}), 400
    
    try:
        # Find user by email
        user = User.query.filter_by(email=data['email']).first()
        
        # Check if user exists and password is correct
        if not user or not check_password_hash(user.password_hash, data['password']):
            return jsonify({'message': 'Invalid email or password'}), 401
        
        # Check if account is already active
        if user.is_active:
            return jsonify({'message': 'Account is already active'}), 400
        
        # Reactivate account
        user.is_active = True
        user.last_login = func.now()
        db.session.commit()
        
        # Generate token
        token = generate_token(user.id, user.role)
        
        return jsonify({
            'message': 'Account reactivated successfully',
            'user_id': str(user.id),
            'token': token
        }), 200
        
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Reactivate account error: {e}")
        return jsonify({'message': 'An error occurred while reactivating account'}), 500

# Admin routes
@app.route('/admin/users', methods=['GET'])
@token_required
@admin_required
def list_users():
    """List all users (admin only)"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        
        # Get filtering parameters
        email = request.args.get('email')
        role = request.args.get('role')
        active = request.args.get('active')
        
        # Build query
        query = User.query
        
        if email:
            query = query.filter(User.email.ilike(f'%{email}%'))
        
        if role:
            query = query.filter_by(role=role)
        
        if active is not None:
            active_bool = active.lower() == 'true'
            query = query.filter_by(is_active=active_bool)
        
        # Paginate results
        users_page = query.order_by(User.created_at.desc()).paginate(page=page, per_page=per_page)
        
        # Format response
        result = {
            'total': users_page.total,
            'pages': users_page.pages,
            'page': page,
            'per_page': per_page,
            'users': []
        }
        
        for user in users_page.items:
            result['users'].append({
                'id': str(user.id),
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'role': user.role,
                'is_active': user.is_active,
                'created_at': user.created_at.isoformat(),
                'last_login': user.last_login.isoformat() if user.last_login else None
            })
        
        return jsonify(result), 200
        
    except SQLAlchemyError as e:
        logger.error(f"List users error: {e}")
        return jsonify({'message': 'An error occurred while listing users'}), 500

@app.route('/admin/users/<user_id>', methods=['GET'])
@token_required
@admin_required
def admin_get_user(user_id):
    """Get detailed user info (admin only)"""
    try:
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'message': 'User not found'}), 404
        
        # Get profile
        profile = Profile.query.filter_by(user_id=user.id).first()
        
        # Get addresses
        addresses = Address.query.filter_by(user_id=user.id).all()
        addresses_data = []
        for addr in addresses:
            addresses_data.append({
                'id': str(addr.id),
                'street': addr.street,
                'city': addr.city,
                'state': addr.state,
                'zip_code': addr.zip_code,
                'country': addr.country,
                'is_primary': addr.is_primary,
                'is_verified': addr.is_verified
            })
        
        # Calculate ratings
        rating_query = db.session.query(
            func.avg(Rating.rating).label('avg_rating'),
            func.count(Rating.id).label('total_ratings')
        ).filter(Rating.to_user_id == user.id).first()
        
        avg_rating = float(rating_query.avg_rating) if rating_query.avg_rating else 0
        total_ratings = rating_query.total_ratings
        
        return jsonify({
            'id': str(user.id),
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'phone': user.phone,
            'role': user.role,
            'oauth_provider': user.oauth_provider,
            'created_at': user.created_at.isoformat(),
            'updated_at': user.updated_at.isoformat(),
            'last_login': user.last_login.isoformat() if user.last_login else None,
            'is_active': user.is_active,
            'is_email_verified': user.is_email_verified,
            'avatar_url': user.avatar_url,
            'profile': {
                'bio': profile.bio if profile else None,
                'preferences': profile.preferences if profile else {},
                'privacy_settings': profile.privacy_settings if profile else {}
            } if profile else None,
            'addresses': addresses_data,
            'reputation': {
                'avg_rating': avg_rating,
                'total_ratings': total_ratings
            }
        }), 200
        
    except SQLAlchemyError as e:
        logger.error(f"Admin get user error: {e}")
        return jsonify({'message': 'An error occurred while retrieving user details'}), 500

@app.route('/admin/users/<user_id>', methods=['PUT'])
@token_required
@admin_required
def admin_update_user(user_id):
    """Update user (admin only)"""
    data = request.get_json()
    
    try:
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'message': 'User not found'}), 404
        
        # Update user fields
        for field in ['first_name', 'last_name', 'phone', 'role', 'is_active', 'is_email_verified']:
            if field in data:
                setattr(user, field, data[field])
        
        db.session.commit()
        
        return jsonify({'message': 'User updated successfully'}), 200
        
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Admin update user error: {e}")
        return jsonify({'message': 'An error occurred while updating user'}), 500

@app.route('/admin/verify-address/<address_id>', methods=['POST'])
@token_required
@admin_required
def admin_verify_address(address_id):
    """Manually verify address (admin only)"""
    try:
        address = Address.query.get(address_id)
        
        if not address:
            return jsonify({'message': 'Address not found'}), 404
        
        # Mark as verified
        address.is_verified = True
        db.session.commit()
        
        return jsonify({'message': 'Address marked as verified'}), 200
        
    except SQLAlchemyError as e:
        db.session.rollback()
        logger.error(f"Admin verify address error: {e}")
        return jsonify({'message': 'An error occurred while verifying address'}), 500

if __name__ == '__main__':
    with app.app_context():
        # Create tables if they don't exist
        db.session.execute(text(f'CREATE SCHEMA IF NOT EXISTS {schema}'))
        db.session.commit()
        db.create_all()
    
    port = int(os.getenv('PORT', 5003))
    debug_mode = os.getenv('DEBUG', 'False').lower() == 'true'
    
    app.run(host='0.0.0.0', port=port, debug=debug_mode)