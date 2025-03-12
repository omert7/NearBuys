import os
import json
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
import jwt
from datetime import datetime, timedelta
from functools import wraps
from dotenv import load_dotenv
from sqlalchemy import text

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)

# Configure database
schema = os.getenv('DATABASE_SCHEMA', 'sellers')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['PRODUCT_SERVICE_URL'] = os.getenv('PRODUCT_SERVICE_URL')
app.config['USER_SERVICE_URL'] = os.getenv('USER_SERVICE_URL')

db = SQLAlchemy(app)

# Define database models
class Seller(db.Model):
    __tablename__ = 'sellers'
    __table_args__ = {'schema': schema}
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False, unique=True)
    business_name = db.Column(db.String(255), nullable=False)
    business_description = db.Column(db.Text)
    verification_status = db.Column(db.String(50), default='pending')
    creation_date = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    contact_email = db.Column(db.String(255))
    contact_phone = db.Column(db.String(50))
    website = db.Column(db.String(255))
    tax_id = db.Column(db.String(100))
    is_active = db.Column(db.Boolean, default=True)
    
    bids = db.relationship('Bid', backref='seller', lazy=True)
    ratings = db.relationship('SellerRating', backref='seller', lazy=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'business_name': self.business_name,
            'business_description': self.business_description,
            'verification_status': self.verification_status,
            'creation_date': self.creation_date.isoformat() if self.creation_date else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'contact_email': self.contact_email,
            'contact_phone': self.contact_phone,
            'website': self.website,
            'tax_id': self.tax_id,
            'is_active': self.is_active,
            'average_rating': self.get_average_rating()
        }
    
    def get_average_rating(self):
        if not self.ratings:
            return None
        return sum(rating.rating for rating in self.ratings) / len(self.ratings)

class Bid(db.Model):
    __tablename__ = 'bids'
    __table_args__ = {'schema': schema}
    id = db.Column(db.Integer, primary_key=True)
    seller_id = db.Column(db.Integer, db.ForeignKey(f'{schema}.sellers.id'), nullable=False)
    group_buy_id = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text)
    terms = db.Column(db.Text)
    status = db.Column(db.String(50), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    expiration_date = db.Column(db.DateTime)
    is_winning_bid = db.Column(db.Boolean, default=False)
    
    def to_dict(self):
        return {
            'id': self.id,
            'seller_id': self.seller_id,
            'group_buy_id': self.group_buy_id,
            'price': self.price,
            'description': self.description,
            'terms': self.terms,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'expiration_date': self.expiration_date.isoformat() if self.expiration_date else None,
            'is_winning_bid': self.is_winning_bid,
            'seller_info': {
                'business_name': self.seller.business_name,
                'verification_status': self.seller.verification_status,
                'average_rating': self.seller.get_average_rating()
            }
        }

class SellerRating(db.Model):
    __tablename__ = 'seller_ratings'
    __table_args__ = {'schema': schema}
    id = db.Column(db.Integer, primary_key=True)
    seller_id = db.Column(db.Integer, db.ForeignKey(f'{schema}.sellers.id'), nullable=False)
    user_id = db.Column(db.Integer, nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (db.UniqueConstraint('seller_id', 'user_id'),)
    
    def to_dict(self):
        return {
            'id': self.id,
            'seller_id': self.seller_id,
            'user_id': self.user_id,
            'rating': self.rating,
            'comment': self.comment,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

# Authentication decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        if not token:
                return jsonify({'message': 'Token is missing!'}), 401            
        try:
            jwt_secret = app.config['JWT_SECRET_KEY']
            payload = jwt.decode(token, jwt_secret, algorithms=['HS256'])
            current_user_id = payload['sub']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 401
            
        return f(current_user_id, *args, **kwargs)
    return decorated

# Helper function to forward request to product service
def get_group_buy(group_buy_id, token=None):
   headers = {}
   if token:
       headers['Authorization'] = f'Bearer {token}'
   
   product_service_url = app.config['PRODUCT_SERVICE_URL']
   response = requests.get(f'{product_service_url}/group-buys/{group_buy_id}', headers=headers)
   
   if response.status_code != 200:
       return None
       
   return response.json()

# Health check endpoint
@app.route('/health', methods=['GET'])
def health_check():
   return jsonify({'status': 'healthy', 'service': 'seller-service'})

# Seller endpoints
@app.route('/sellers', methods=['GET'])
def get_sellers():
   sellers = Seller.query.filter_by(is_active=True).all()
   return jsonify([seller.to_dict() for seller in sellers])

@app.route('/sellers/<int:seller_id>', methods=['GET'])
def get_seller(seller_id):
   seller = Seller.query.get_or_404(seller_id)
   return jsonify(seller.to_dict())

@app.route('/sellers/me', methods=['GET'])
@token_required
def get_my_seller_profile(current_user_id):
   seller = Seller.query.filter_by(user_id=current_user_id).first()
   
   if not seller:
       return jsonify({'message': 'Seller profile not found!'}), 404
       
   return jsonify(seller.to_dict())

@app.route('/sellers', methods=['POST'])
@token_required
def create_seller(current_user_id):
   # Check if seller already exists for this user
   existing = Seller.query.filter_by(user_id=current_user_id).first()
   if existing:
       return jsonify({'message': 'You already have a seller profile!'}), 400
   
   data = request.get_json()
   
   if not data or not data.get('business_name'):
       return jsonify({'message': 'Business name is required!'}), 400
       
   seller = Seller(
       user_id=current_user_id,
       business_name=data.get('business_name'),
       business_description=data.get('business_description'),
       contact_email=data.get('contact_email'),
       contact_phone=data.get('contact_phone'),
       website=data.get('website'),
       tax_id=data.get('tax_id')
   )
   
   db.session.add(seller)
   db.session.commit()
   
   return jsonify(seller.to_dict()), 201

@app.route('/sellers/me', methods=['PUT'])
@token_required
def update_seller(current_user_id):
   seller = Seller.query.filter_by(user_id=current_user_id).first()
   
   if not seller:
       return jsonify({'message': 'Seller profile not found!'}), 404
   
   data = request.get_json()
   
   if data.get('business_name'):
       seller.business_name = data.get('business_name')
   if 'business_description' in data:
       seller.business_description = data.get('business_description')
   if 'contact_email' in data:
       seller.contact_email = data.get('contact_email')
   if 'contact_phone' in data:
       seller.contact_phone = data.get('contact_phone')
   if 'website' in data:
       seller.website = data.get('website')
   if 'tax_id' in data:
       seller.tax_id = data.get('tax_id')
   
   seller.updated_at = datetime.utcnow()
   
   db.session.commit()
   
   return jsonify(seller.to_dict())

# Bid endpoints
@app.route('/bids', methods=['GET'])
@token_required
def get_my_bids(current_user_id):
   # Get seller profile
   seller = Seller.query.filter_by(user_id=current_user_id).first()
   
   if not seller:
       return jsonify({'message': 'Seller profile not found!'}), 404
   
   bids = Bid.query.filter_by(seller_id=seller.id).all()
   return jsonify([bid.to_dict() for bid in bids])

@app.route('/bids/<int:bid_id>', methods=['GET'])
def get_bid(bid_id):
   bid = Bid.query.get_or_404(bid_id)
   return jsonify(bid.to_dict())

@app.route('/group-buys/<int:group_buy_id>/bids', methods=['GET'])
def get_group_buy_bids(group_buy_id):
   bids = Bid.query.filter_by(group_buy_id=group_buy_id).all()
   return jsonify([bid.to_dict() for bid in bids])

@app.route('/bid', methods=['POST'])
@token_required
def create_bid(current_user_id):
   # Get seller profile
   seller = Seller.query.filter_by(user_id=current_user_id).first()
   
   if not seller:
       return jsonify({'message': 'You need to create a seller profile first!'}), 400
   
   # Check verification status
   if seller.verification_status != 'verified':
       return jsonify({'message': 'Your seller account needs to be verified before you can bid!'}), 403
   
   data = request.get_json()
   
   if not data or not data.get('group_buy_id') or not data.get('price'):
       return jsonify({'message': 'Group buy ID and price are required!'}), 400
   
   group_buy_id = data.get('group_buy_id')
   
   # Get group buy information from product service
   group_buy = get_group_buy(group_buy_id)
   
   if not group_buy:
       return jsonify({'message': 'Group buy not found!'}), 404
   
   # Check if group buy accepts seller bids
   if not group_buy.get('accepts_seller_bids'):
       return jsonify({'message': 'This group buy does not accept seller bids!'}), 400
   
   # Check if bidding is open
   if group_buy.get('bidding_status') != 'open':
       return jsonify({'message': 'Bidding is closed for this group buy!'}), 400
   
   # Check if seller already has a bid for this group buy
   existing_bid = Bid.query.filter_by(seller_id=seller.id, group_buy_id=group_buy_id).first()
   
   if existing_bid:
       return jsonify({'message': 'You already have a bid for this group buy! Update your existing bid instead.'}), 400
   
   # Parse expiration date if provided
   expiration_date = None
   if data.get('expiration_date'):
       try:
           expiration_date = datetime.fromisoformat(data.get('expiration_date'))
       except ValueError:
           return jsonify({'message': 'Invalid expiration date format! Use ISO format (YYYY-MM-DDTHH:MM:SS)'}), 400
   
   bid = Bid(
       seller_id=seller.id,
       group_buy_id=group_buy_id,
       price=data.get('price'),
       description=data.get('description'),
       terms=data.get('terms'),
       expiration_date=expiration_date
   )
   
   db.session.add(bid)
   db.session.commit()
   
   return jsonify(bid.to_dict()), 201

@app.route('/bids/<int:bid_id>', methods=['PUT'])
@token_required
def update_bid(current_user_id, bid_id):
   # Get seller profile
   seller = Seller.query.filter_by(user_id=current_user_id).first()
   
   if not seller:
       return jsonify({'message': 'Seller profile not found!'}), 404
   
   bid = Bid.query.get_or_404(bid_id)
   
   # Check if bid belongs to seller
   if bid.seller_id != seller.id:
       return jsonify({'message': 'You can only update your own bids!'}), 403
   
   # Get group buy information
   group_buy = get_group_buy(bid.group_buy_id)
   
   if not group_buy:
       return jsonify({'message': 'Group buy not found!'}), 404
   
   # Check if bidding is still open
   if group_buy.get('bidding_status') != 'open':
       return jsonify({'message': 'Bidding is closed for this group buy!'}), 400
   
   data = request.get_json()
   
   if 'price' in data:
       bid.price = data.get('price')
   if 'description' in data:
       bid.description = data.get('description')
   if 'terms' in data:
       bid.terms = data.get('terms')
   if 'expiration_date' in data:
       try:
           bid.expiration_date = datetime.fromisoformat(data.get('expiration_date')) if data.get('expiration_date') else None
       except ValueError:
           return jsonify({'message': 'Invalid expiration date format! Use ISO format (YYYY-MM-DDTHH:MM:SS)'}), 400
   
   bid.updated_at = datetime.utcnow()
   
   db.session.commit()
   
   return jsonify(bid.to_dict())

# Seller ratings endpoints
@app.route('/sellers/<int:seller_id>/ratings', methods=['GET'])
def get_seller_ratings(seller_id):
   seller = Seller.query.get_or_404(seller_id)
   ratings = SellerRating.query.filter_by(seller_id=seller_id).all()
   return jsonify([rating.to_dict() for rating in ratings])

@app.route('/sellers/<int:seller_id>/rate', methods=['POST'])
@token_required
def rate_seller(current_user_id, seller_id):
   seller = Seller.query.get_or_404(seller_id)
   
   # Check if user is rating their own seller profile
   if seller.user_id == current_user_id:
       return jsonify({'message': 'You cannot rate your own seller profile!'}), 400
   
   data = request.get_json()
   
   if not data or not data.get('rating'):
       return jsonify({'message': 'Rating is required!'}), 400
   
   rating_value = data.get('rating')
   
   # Validate rating
   if not isinstance(rating_value, int) or rating_value < 1 or rating_value > 5:
       return jsonify({'message': 'Rating must be an integer between 1 and 5!'}), 400
   
   # Check if user already rated this seller
   existing = SellerRating.query.filter_by(
       seller_id=seller_id,
       user_id=current_user_id
   ).first()
   
   if existing:
       # Update existing rating
       existing.rating = rating_value
       existing.comment = data.get('comment')
   else:
       # Create new rating
       rating = SellerRating(
           seller_id=seller_id,
           user_id=current_user_id,
           rating=rating_value,
           comment=data.get('comment')
       )
       db.session.add(rating)
   
   db.session.commit()
   
   return jsonify({'message': 'Rating submitted successfully!'})

@app.route('/sellers/dashboard', methods=['GET'])
@token_required
def seller_dashboard(current_user_id):
   # Get seller profile
   seller = Seller.query.filter_by(user_id=current_user_id).first()
   
   if not seller:
       return jsonify({'message': 'Seller profile not found!'}), 404
   
   # Get seller's bids
   bids = Bid.query.filter_by(seller_id=seller.id).all()
   
   # Calculate metrics
   total_bids = len(bids)
   winning_bids = sum(1 for bid in bids if bid.is_winning_bid)
   win_rate = (winning_bids / total_bids * 100) if total_bids > 0 else 0
   
   pending_bids = sum(1 for bid in bids if bid.status == 'pending')
   active_bids = sum(1 for bid in bids if bid.status == 'active')
   
   # Get average rating
   avg_rating = seller.get_average_rating()
   
   # Get recent ratings
   recent_ratings = SellerRating.query.filter_by(seller_id=seller.id).order_by(SellerRating.created_at.desc()).limit(5).all()
   
   return jsonify({
       'seller': seller.to_dict(),
       'metrics': {
           'total_bids': total_bids,
           'winning_bids': winning_bids,
           'win_rate': win_rate,
           'pending_bids': pending_bids,
           'active_bids': active_bids,
           'average_rating': avg_rating
       },
       'recent_bids': [bid.to_dict() for bid in Bid.query.filter_by(seller_id=seller.id).order_by(Bid.created_at.desc()).limit(5).all()],
       'recent_ratings': [rating.to_dict() for rating in recent_ratings]
   })

# Webhook endpoint for bid status updates
@app.route('/webhooks/bid-status', methods=['POST'])
def bid_status_webhook():
   data = request.get_json()
   
   if not data or not data.get('bid_id') or not data.get('status'):
       return jsonify({'message': 'Bid ID and status are required!'}), 400
   
   bid_id = data.get('bid_id')
   status = data.get('status')
   is_winning = data.get('is_winning_bid', False)
   
   bid = Bid.query.get(bid_id)
   
   if not bid:
       return jsonify({'message': 'Bid not found!'}), 404
   
   bid.status = status
   bid.is_winning_bid = is_winning
   bid.updated_at = datetime.utcnow()
   
   db.session.commit()
   
   return jsonify({'message': 'Bid status updated successfully!'})

# Create tables if they don't exist
with app.app_context():
    db.session.execute(text(f'CREATE SCHEMA IF NOT EXISTS {schema}'))
    db.session.commit()
    db.create_all()

if __name__ == '__main__':
   port = int(os.getenv('PORT', 5004))
   app.run(host='0.0.0.0', port=port, debug=os.getenv('DEBUG', 'False').lower() == 'true')