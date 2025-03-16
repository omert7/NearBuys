import os
import json
import requests
import uuid
import logging
from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
from datetime import datetime, timedelta
from functools import wraps
from dotenv import load_dotenv
from shared.utils.message_queue import MessageQueue
from shared.utils.prometheus_metrics import init_metrics, track_requests, track_user_activity

# Initialize message queue
message_queue = MessageQueue()

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('seller_service')

app = Flask(__name__)
CORS(app)

# Initialize Prometheus metrics
metrics_port = int(os.getenv('METRICS_PORT', 8003))
init_metrics('seller-service', '1.0.0', metrics_port)
track_requests(app)

# JWT configuration
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['PRODUCT_SERVICE_URL'] = os.getenv('PRODUCT_SERVICE_URL')
app.config['USER_SERVICE_URL'] = os.getenv('USER_SERVICE_URL')

# Authentication decorator
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
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'service': 'seller-service'})

# Seller endpoints
@app.route('/sellers', methods=['GET'])
def get_sellers():
    """Get all sellers"""
    # Get query parameters
    search = request.args.get('search')
    category = request.args.get('category')
    min_rating = request.args.get('min_rating')
    
    # Send message to RabbitMQ
    message_queue.publish('seller.list', {
        'search': search,
        'category': category,
        'min_rating': min_rating
    })
    
    return jsonify({
        'message': 'Sellers request received',
        'status': 'processing'
    }), 202

@app.route('/api/sellers', methods=['POST'])
@token_required
def create_seller():
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['business_name', 'business_address']
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400
            
        # Generate seller ID
        seller_id = str(uuid.uuid4())
        
        # Track seller creation
        track_user_activity('seller_created', request.user_role)
        
        # Send message to message processor
        response = message_queue.publish_and_wait('seller.created', {
            'id': seller_id,
            'user_id': request.user_id,
            **data
        })
        
        if not response:
            return jsonify({'error': 'Failed to create seller'}), 500
            
        return jsonify(response), 201
        
    except Exception as e:
        logger.error(f"Error in create_seller: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/sellers/<seller_id>', methods=['GET'])
def get_seller(seller_id):
    try:
        # Send message to message processor
        response = message_queue.publish_and_wait('seller.get', {
            'seller_id': seller_id
        })
        
        if not response:
            return jsonify({'error': 'Seller not found'}), 404
            
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Error in get_seller: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/sellers/<seller_id>', methods=['PUT'])
@token_required
def update_seller(seller_id):
    try:
        data = request.get_json()
        
        # Validate seller can only update their own profile
        if request.user_id != data.get('user_id'):
            return jsonify({'error': 'Unauthorized'}), 403
            
        # Send message to message processor
        response = message_queue.publish_and_wait('seller.updated', {
            'id': seller_id,
            **data
        })
        
        if not response:
            return jsonify({'error': 'Failed to update seller'}), 500
            
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Error in update_seller: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/sellers/<seller_id>', methods=['DELETE'])
@token_required
def delete_seller(seller_id):
    """Delete a seller"""
    # Send message to RabbitMQ
    message_queue.publish('seller.deleted', {
        'seller_id': seller_id,
        'deleted_by': request.user_id
    })
    
    return jsonify({
        'message': 'Seller delete request received',
        'status': 'processing'
    }), 202

@app.route('/sellers/<seller_id>/ratings', methods=['GET'])
def get_seller_ratings(seller_id):
    """Get all ratings for a seller"""
    # Send message to RabbitMQ
    message_queue.publish('seller.get_ratings', {
        'seller_id': seller_id
    })
    
    return jsonify({
        'message': 'Ratings request received',
        'status': 'processing'
    }), 202

@app.route('/api/sellers/<seller_id>/rate', methods=['POST'])
@token_required
def rate_seller(seller_id):
    try:
        data = request.get_json()
        
        # Validate required fields
        if 'rating' not in data:
            return jsonify({'error': 'Rating is required'}), 400
            
        # Validate rating range
        if not 1 <= data['rating'] <= 5:
            return jsonify({'error': 'Rating must be between 1 and 5'}), 400
            
        # Send message to message processor
        response = message_queue.publish_and_wait('seller.rated', {
            'seller_id': seller_id,
            'user_id': request.user_id,
            'rating': data['rating'],
            'comment': data.get('comment')
        })
        
        if not response:
            return jsonify({'error': 'Failed to rate seller'}), 500
            
        return jsonify(response), 201
        
    except Exception as e:
        logger.error(f"Error in rate_seller: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/sellers/<seller_id>/bids', methods=['GET'])
def get_seller_bids(seller_id):
    """Get all bids for a seller"""
    # Send message to RabbitMQ
    message_queue.publish('seller.get_bids', {
        'seller_id': seller_id
    })
    
    return jsonify({
        'message': 'Bids request received',
        'status': 'processing'
    }), 202

@app.route('/api/bids', methods=['POST'])
@token_required
def create_bid():
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['group_buy_id', 'amount']
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400
            
        # Generate bid ID
        bid_id = str(uuid.uuid4())
        
        # Send message to message processor
        response = message_queue.publish_and_wait('bid.created', {
            'id': bid_id,
            'user_id': request.user_id,
            **data
        })
        
        if not response:
            return jsonify({'error': 'Failed to create bid'}), 500
            
        return jsonify(response), 201
        
    except Exception as e:
        logger.error(f"Error in create_bid: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/bids/<bid_id>', methods=['GET'])
def get_bid(bid_id):
    """Get bid by ID"""
    # Send message to RabbitMQ
    message_queue.publish('seller.get_bid', {
        'bid_id': bid_id
    })
    
    return jsonify({
        'message': 'Bid request received',
        'status': 'processing'
    }), 202

@app.route('/api/bids/<bid_id>', methods=['PUT'])
@token_required
def update_bid(bid_id):
    try:
        data = request.get_json()
        
        # Validate user can only update their own bids
        if request.user_id != data.get('user_id'):
            return jsonify({'error': 'Unauthorized'}), 403
            
        # Send message to message processor
        response = message_queue.publish_and_wait('bid.updated', {
            'id': bid_id,
            **data
        })
        
        if not response:
            return jsonify({'error': 'Failed to update bid'}), 500
            
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Error in update_bid: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/bids/<bid_id>', methods=['DELETE'])
@token_required
def delete_bid(bid_id):
    try:
        # Send message to message processor
        response = message_queue.publish_and_wait('bid.deleted', {
            'bid_id': bid_id,
            'user_id': request.user_id
        })
        
        if not response:
            return jsonify({'error': 'Failed to delete bid'}), 500
            
        return jsonify({'message': 'Bid deleted successfully'}), 200
        
    except Exception as e:
        logger.error(f"Error in delete_bid: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/admin/sellers', methods=['GET'])
@token_required
@admin_required
def list_sellers():
    """List all sellers (admin only)"""
    # Send message to RabbitMQ
    message_queue.publish('seller.admin_list', {
        'requested_by': request.user_id
    })
    
    return jsonify({
        'message': 'Sellers list request received',
        'status': 'processing'
    }), 202

@app.route('/admin/sellers/<seller_id>', methods=['GET'])
@token_required
@admin_required
def admin_get_seller(seller_id):
    """Get seller details (admin only)"""
    # Send message to RabbitMQ
    message_queue.publish('seller.admin_get', {
        'seller_id': seller_id,
        'requested_by': request.user_id
    })
    
    return jsonify({
        'message': 'Seller details request received',
        'status': 'processing'
    }), 202

@app.route('/admin/sellers/<seller_id>', methods=['PUT'])
@token_required
@admin_required
def admin_update_seller(seller_id):
    """Update seller details (admin only)"""
    data = request.get_json()
    
    if not data:
        return jsonify({'message': 'No data provided'}), 400
        
    # Add seller ID to data
    data['seller_id'] = seller_id
    data['updated_by'] = request.user_id
    
    # Send message to RabbitMQ
    message_queue.publish('seller.admin_updated', data)
    
    return jsonify({
        'message': 'Seller update request received',
        'status': 'processing'
    }), 202

@app.route('/api/sellers/<seller_id>/verify', methods=['POST'])
@token_required
@admin_required
def verify_seller(seller_id):
    try:
        # Send message to message processor
        response = message_queue.publish_and_wait('seller.verified', {
            'seller_id': seller_id,
            'verified_by': request.user_id
        })
        
        if not response:
            return jsonify({'error': 'Failed to verify seller'}), 500
            
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Error in verify_seller: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Create tables if they don't exist
with app.app_context():
    pass

if __name__ == '__main__':
   port = int(os.getenv('PORT', 5005))
   app.run(host='0.0.0.0', port=port, debug=os.getenv('DEBUG', 'False').lower() == 'true')