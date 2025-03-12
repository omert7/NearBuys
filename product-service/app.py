import os
import json
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
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
schema = os.getenv('DATABASE_SCHEMA', 'products')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')

db = SQLAlchemy(app)

# Define database models
class Category(db.Model):
    __tablename__ = 'categories'
    __table_args__ = {'schema': schema}
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class Product(db.Model):
    __tablename__ = 'products'
    __table_args__ = {'schema': schema}
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    category_id = db.Column(db.Integer, db.ForeignKey(f'{schema}.categories.id'))
    base_price = db.Column(db.Float)
    image_url = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = db.Column(db.Integer, nullable=False)
    
    category = db.relationship('Category', backref=db.backref('products', lazy=True))
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'category_id': self.category_id,
            'category_name': self.category.name if self.category else None,
            'base_price': self.base_price,
            'image_url': self.image_url,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'created_by': self.created_by
        }

class GroupBuy(db.Model):
    __tablename__ = 'group_buys'
    __table_args__ = {'schema': schema}
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey(f'{schema}.products.id'))
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    min_participants = db.Column(db.Integer, default=1)
    max_participants = db.Column(db.Integer)
    current_participants = db.Column(db.Integer, default=0)
    price_per_unit = db.Column(db.Float)
    status = db.Column(db.String(50), default='active')
    start_date = db.Column(db.DateTime, default=datetime.utcnow)
    end_date = db.Column(db.DateTime)
    created_by = db.Column(db.Integer, nullable=False)
    location_lat = db.Column(db.Float)
    location_lng = db.Column(db.Float)
    location_radius = db.Column(db.Integer, default=5000)
    accepts_seller_bids = db.Column(db.Boolean, default=True)
    bidding_status = db.Column(db.String(50), default='open')
    winning_bid_id = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    product = db.relationship('Product', backref=db.backref('group_buys', lazy=True))
    
    def to_dict(self):
        return {
            'id': self.id,
            'product_id': self.product_id,
            'product_name': self.product.name if self.product else None,
            'name': self.name,
            'description': self.description,
            'min_participants': self.min_participants,
            'max_participants': self.max_participants,
            'current_participants': self.current_participants,
            'price_per_unit': self.price_per_unit,
            'status': self.status,
            'start_date': self.start_date.isoformat() if self.start_date else None,
            'end_date': self.end_date.isoformat() if self.end_date else None,
            'created_by': self.created_by,
            'location': {
                'lat': self.location_lat,
                'lng': self.location_lng,
                'radius': self.location_radius
            } if self.location_lat and self.location_lng else None,
            'accepts_seller_bids': self.accepts_seller_bids,
            'bidding_status': self.bidding_status,
            'winning_bid_id': self.winning_bid_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class GroupBuyParticipant(db.Model):
    __tablename__ = 'group_buy_participants'
    __table_args__ = {'schema': schema}
    id = db.Column(db.Integer, primary_key=True)
    group_buy_id = db.Column(db.Integer, db.ForeignKey(f'{schema}.group_buys.id'))
    user_id = db.Column(db.Integer, nullable=False)
    join_date = db.Column(db.DateTime, default=datetime.utcnow)
    quantity = db.Column(db.Integer, default=1)
    status = db.Column(db.String(50), default='active')
    
    group_buy = db.relationship('GroupBuy', backref=db.backref('participants', lazy=True))
    
    def to_dict(self):
        return {
            'id': self.id,
            'group_buy_id': self.group_buy_id,
            'user_id': self.user_id,
            'join_date': self.join_date.isoformat() if self.join_date else None,
            'quantity': self.quantity,
            'status': self.status
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

# Health check endpoint
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'service': 'product-service'})

# Category endpoints
@app.route('/categories', methods=['GET'])
def get_categories():
    categories = Category.query.all()
    return jsonify([category.to_dict() for category in categories])

@app.route('/categories', methods=['POST'])
@token_required
def create_category(current_user_id):
    data = request.get_json()
    
    if not data or not data.get('name'):
        return jsonify({'message': 'Name is required!'}), 400
        
    category = Category(
        name=data.get('name'),
        description=data.get('description')
    )
    
    db.session.add(category)
    db.session.commit()
    
    return jsonify(category.to_dict()), 201

# Product endpoints
@app.route('/products', methods=['GET'])
def get_products():
    products = Product.query.all()
    return jsonify([product.to_dict() for product in products])

@app.route('/products/<int:product_id>', methods=['GET'])
def get_product(product_id):
    product = Product.query.get_or_404(product_id)
    return jsonify(product.to_dict())

@app.route('/products', methods=['POST'])
@token_required
def create_product(current_user_id):
    data = request.get_json()
    
    if not data or not data.get('name'):
        return jsonify({'message': 'Name is required!'}), 400
        
    product = Product(
        name=data.get('name'),
        description=data.get('description'),
        category_id=data.get('category_id'),
        base_price=data.get('base_price'),
        image_url=data.get('image_url'),
        created_by=current_user_id
    )
    
    db.session.add(product)
    db.session.commit()
    
    return jsonify(product.to_dict()), 201

@app.route('/products/search', methods=['GET'])
def search_products():
    query = request.args.get('q', '')
    category_id = request.args.get('category_id')
    
    products_query = Product.query
    
    if query:
        products_query = products_query.filter(Product.name.ilike(f'%{query}%') | 
                                             Product.description.ilike(f'%{query}%'))
    
    if category_id:
        products_query = products_query.filter(Product.category_id == category_id)
    
    products = products_query.all()
    return jsonify([product.to_dict() for product in products])

# Group Buy endpoints
@app.route('/group-buys', methods=['GET'])
def get_group_buys():
    status = request.args.get('status')
    lat = request.args.get('lat', type=float)
    lng = request.args.get('lng', type=float)
    radius = request.args.get('radius', 5000, type=int)
    
    query = GroupBuy.query
    
    if status:
        query = query.filter(GroupBuy.status == status)
    
    # Default to active group buys if no status specified
    else:
        query = query.filter(GroupBuy.status == 'active')
    
    # If location provided, filter by distance
    # Note: This is a simplified version. In production, you'd use geospatial queries
    if lat and lng:
        # This is placeholder logic. In a real application, you'd use proper
        # spatial queries or a PostGIS extension for accurate distance calculations
        group_buys = query.all()
        
        # Filter in-memory for demonstration purposes
        # In a real app, you'd implement this at the database level
        result = []
        for group_buy in group_buys:
            if group_buy.location_lat and group_buy.location_lng:
                # Simple check if within bounding box (not accurate for large distances)
                if (abs(group_buy.location_lat - lat) < 0.1 and 
                    abs(group_buy.location_lng - lng) < 0.1):
                    result.append(group_buy)
        
        return jsonify([group_buy.to_dict() for group_buy in result])
    
    group_buys = query.all()
    return jsonify([group_buy.to_dict() for group_buy in group_buys])

@app.route('/group-buys/<int:group_buy_id>', methods=['GET'])
def get_group_buy(group_buy_id):
    group_buy = GroupBuy.query.get_or_404(group_buy_id)
    return jsonify(group_buy.to_dict())

@app.route('/group-buys', methods=['POST'])
@token_required
def create_group_buy(current_user_id):
    data = request.get_json()
    
    if not data or not data.get('name') or not data.get('product_id'):
        return jsonify({'message': 'Name and product_id are required!'}), 400
    
    # Convert string dates to datetime objects
    start_date = datetime.fromisoformat(data.get('start_date')) if data.get('start_date') else datetime.utcnow()
    end_date = datetime.fromisoformat(data.get('end_date')) if data.get('end_date') else None
    
    group_buy = GroupBuy(
        product_id=data.get('product_id'),
        name=data.get('name'),
        description=data.get('description'),
        min_participants=data.get('min_participants', 1),
        max_participants=data.get('max_participants'),
        price_per_unit=data.get('price_per_unit'),
        start_date=start_date,
        end_date=end_date,
        created_by=current_user_id,
        location_lat=data.get('location', {}).get('lat'),
        location_lng=data.get('location', {}).get('lng'),
        location_radius=data.get('location', {}).get('radius', 5000),
        accepts_seller_bids=data.get('accepts_seller_bids', True)
    )
    
    db.session.add(group_buy)
    db.session.commit()
    
    # Automatically add creator as first participant
    participant = GroupBuyParticipant(
        group_buy_id=group_buy.id,
        user_id=current_user_id,
        quantity=data.get('quantity', 1)
    )
    
    db.session.add(participant)
    
    # Update current participants count
    group_buy.current_participants = 1
    
    db.session.commit()
    
    return jsonify(group_buy.to_dict()), 201

@app.route('/group-buys/<int:group_buy_id>/join', methods=['POST'])
@token_required
def join_group_buy(current_user_id, group_buy_id):
    group_buy = GroupBuy.query.get_or_404(group_buy_id)
    
    # Check if group buy is active
    if group_buy.status != 'active':
        return jsonify({'message': 'This group buy is no longer active!'}), 400
    
    # Check if max participants reached
    if group_buy.max_participants and group_buy.current_participants >= group_buy.max_participants:
        return jsonify({'message': 'This group buy has reached maximum participants!'}), 400
    
    # Check if user already joined
    existing = GroupBuyParticipant.query.filter_by(
        group_buy_id=group_buy_id,
        user_id=current_user_id
    ).first()
    
    if existing:
        return jsonify({'message': 'You have already joined this group buy!'}), 400
    
    data = request.get_json() or {}
    quantity = data.get('quantity', 1)
    
    participant = GroupBuyParticipant(
        group_buy_id=group_buy_id,
        user_id=current_user_id,
        quantity=quantity
    )
    
    db.session.add(participant)
    
    # Update current participants count
    group_buy.current_participants += 1
    
    db.session.commit()
    
    return jsonify(participant.to_dict()), 201

@app.route('/group-buys/<int:group_buy_id>/participants', methods=['GET'])
def get_group_buy_participants(group_buy_id):
    participants = GroupBuyParticipant.query.filter_by(group_buy_id=group_buy_id).all()
    return jsonify([participant.to_dict() for participant in participants])

@app.route('/group-buys/<int:group_buy_id>/bids', methods=['GET'])
def get_group_buy_bids(group_buy_id):
    # This will be implemented when we integrate with the Seller Service
    # For now, return empty list
    return jsonify([])

@app.route('/group-buys/<int:group_buy_id>/select-bid', methods=['POST'])
@token_required
def select_winning_bid(current_user_id, group_buy_id):
    # This will be implemented when we integrate with the Seller Service
    # For now, return placeholder response
    group_buy = GroupBuy.query.get_or_404(group_buy_id)
    
    # Ensure user is the creator of the group buy
    if group_buy.created_by != current_user_id:
        return jsonify({'message': 'Only the creator can select a winning bid!'}), 403
    
    data = request.get_json()
    
    if not data or not data.get('bid_id'):
        return jsonify({'message': 'Bid ID is required!'}), 400
    
    # In a real implementation, we would verify the bid exists and belongs to this group buy
    # For now, just update the group buy
    group_buy.bidding_status = 'closed'
    group_buy.winning_bid_id = data.get('bid_id')
    
    db.session.commit()
    
    return jsonify({'message': 'Winning bid selected!', 'group_buy': group_buy.to_dict()})

# Create tables if they don't exist
with app.app_context():
    db.session.execute(text(f'CREATE SCHEMA IF NOT EXISTS {schema}'))
    db.session.commit()
    db.create_all()
    
    # Add some default categories if none exist
    if Category.query.count() == 0:
        default_categories = [
            Category(name='Electronics', description='Electronic devices and gadgets'),
            Category(name='Home & Garden', description='Products for home and garden'),
            Category(name='Groceries', description='Food and household supplies'),
            Category(name='Clothing', description='Apparel and accessories'),
            Category(name='Sports & Outdoors', description='Sporting goods and outdoor equipment')
        ]
        db.session.add_all(default_categories)
        db.session.commit()

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5002))
    app.run(host='0.0.0.0', port=port, debug=os.getenv('DEBUG', 'False').lower() == 'true')