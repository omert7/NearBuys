import os
import json
import uuid
import logging
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
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
logger = logging.getLogger('product_service')

app = Flask(__name__)
CORS(app)

# Initialize Prometheus metrics
metrics_port = int(os.getenv('METRICS_PORT', 8002))
init_metrics('product-service', '1.0.0', metrics_port)
track_requests(app)

# JWT configuration
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')

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

# Health check endpoint
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'service': 'product-service'})

# Category endpoints
@app.route('/categories', methods=['GET'])
def get_categories():
    """Get all categories"""
    # Track categories view
    track_user_activity('categories_view', getattr(request, 'user_role', 'anonymous'))
    
    # Send message to RabbitMQ
    message_queue.publish('product.get_categories', {})
    
    return jsonify({
        'message': 'Categories request received',
        'status': 'processing'
    }), 202

@app.route('/categories', methods=['POST'])
@token_required
@admin_required
def create_category():
    try:
        data = request.get_json()
        
        # Validate required fields
        if 'name' not in data:
            return jsonify({'error': 'Category name is required'}), 400
            
        # Generate category ID
        category_id = str(uuid.uuid4())
        
        # Send message to message processor
        response = message_queue.publish_and_wait('product.category_created', {
            'id': category_id,
            **data
        })
        
        if not response:
            return jsonify({'error': 'Failed to create category'}), 500
            
        return jsonify(response), 201
        
    except Exception as e:
        logger.error(f"Error in create_category: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/categories/<category_id>', methods=['PUT'])
@token_required
@admin_required
def update_category(category_id):
    try:
        data = request.get_json()
        
        # Validate required fields
        if 'name' not in data:
            return jsonify({'error': 'Category name is required'}), 400
            
        # Send message to message processor
        response = message_queue.publish_and_wait('product.category_updated', {
            'id': category_id,
            **data
        })
        
        if not response:
            return jsonify({'error': 'Failed to update category'}), 500
            
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Error in update_category: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/categories/<category_id>', methods=['DELETE'])
@token_required
@admin_required
def delete_category(category_id):
    try:
        # Send message to message processor
        response = message_queue.publish_and_wait('product.category_deleted', {
            'category_id': category_id
        })
        
        if not response:
            return jsonify({'error': 'Failed to delete category'}), 500
            
        return jsonify({'message': 'Category deleted successfully'}), 200
        
    except Exception as e:
        logger.error(f"Error in delete_category: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Product endpoints
@app.route('/products', methods=['GET'])
def get_products():
    """Get all products"""
    # Get query parameters
    category_id = request.args.get('category_id')
    seller_id = request.args.get('seller_id')
    min_price = request.args.get('min_price')
    max_price = request.args.get('max_price')
    search = request.args.get('search')
    
    # Send message to RabbitMQ
    message_queue.publish('product.list', {
        'category_id': category_id,
        'seller_id': seller_id,
        'min_price': min_price,
        'max_price': max_price,
        'search': search
    })
    
    return jsonify({
        'message': 'Products request received',
        'status': 'processing'
    }), 202

@app.route('/api/products', methods=['POST'])
@token_required
@admin_required
def create_product():
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['name', 'description', 'price', 'seller_id']
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400
            
        # Generate product ID
        product_id = str(uuid.uuid4())
        
        # Track product creation
        track_user_activity('product_created', request.user_role)
        
        # Send message to message processor
        response = message_queue.publish_and_wait('product.created', {
            'id': product_id,
            **data
        })
        
        if not response:
            return jsonify({'error': 'Failed to create product'}), 500
            
        return jsonify(response), 201
        
    except Exception as e:
        logger.error(f"Error in create_product: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/products/<product_id>', methods=['GET'])
def get_product(product_id):
    try:
        # Track product view
        track_user_activity('product_view', getattr(request, 'user_role', 'anonymous'))
        
        # Send message to message processor
        response = message_queue.publish_and_wait('product.get', {
            'product_id': product_id
        })
        
        if not response:
            return jsonify({'error': 'Product not found'}), 404
            
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Error in get_product: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/products/<product_id>', methods=['PUT'])
@token_required
@admin_required
def update_product(product_id):
    try:
        data = request.get_json()
        
        # Track product update
        track_user_activity('product_updated', request.user_role)
        
        # Send message to message processor
        response = message_queue.publish_and_wait('product.updated', {
            'id': product_id,
            **data
        })
        
        if not response:
            return jsonify({'error': 'Failed to update product'}), 500
            
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Error in update_product: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/products/<product_id>', methods=['DELETE'])
@token_required
@admin_required
def delete_product(product_id):
    try:
        # Track product deletion
        track_user_activity('product_deleted', request.user_role)
        
        # Send message to message processor
        response = message_queue.publish_and_wait('product.deleted', {
            'product_id': product_id
        })
        
        if not response:
            return jsonify({'error': 'Failed to delete product'}), 500
            
        return jsonify({'message': 'Product deleted successfully'}), 200
        
    except Exception as e:
        logger.error(f"Error in delete_product: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/products/<product_id>/group-buys', methods=['GET'])
def get_product_group_buys(product_id):
    """Get all group buys for a product"""
    # Send message to RabbitMQ
    message_queue.publish('product.get_group_buys', {
        'product_id': product_id
    })
    
    return jsonify({
        'message': 'Group buys request received',
        'status': 'processing'
    }), 202

@app.route('/api/group-buys', methods=['POST'])
@token_required
def create_group_buy():
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['product_id', 'seller_id', 'min_participants', 'target_price']
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400
            
        # Generate group buy ID
        group_buy_id = str(uuid.uuid4())
        
        # Send message to message processor
        response = message_queue.publish_and_wait('group_buy.created', {
            'id': group_buy_id,
            **data
        })
        
        if not response:
            return jsonify({'error': 'Failed to create group buy'}), 500
            
        return jsonify(response), 201
        
    except Exception as e:
        logger.error(f"Error in create_group_buy: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/group-buys/<group_buy_id>', methods=['GET'])
def get_group_buy(group_buy_id):
    """Get group buy by ID"""
    # Send message to RabbitMQ
    message_queue.publish('product.get_group_buy', {
        'group_buy_id': group_buy_id
    })
    
    return jsonify({
        'message': 'Group buy request received',
        'status': 'processing'
    }), 202

@app.route('/api/group-buys/<group_buy_id>', methods=['PUT'])
@token_required
def update_group_buy(group_buy_id):
    try:
        data = request.get_json()
        
        # Send message to message processor
        response = message_queue.publish_and_wait('group_buy.updated', {
            'id': group_buy_id,
            **data
        })
        
        if not response:
            return jsonify({'error': 'Failed to update group buy'}), 500
            
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Error in update_group_buy: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/group-buys/<group_buy_id>', methods=['DELETE'])
@token_required
def delete_group_buy(group_buy_id):
    """Delete a group buy"""
    # Send message to RabbitMQ
    message_queue.publish('product.group_buy_deleted', {
        'group_buy_id': group_buy_id,
        'deleted_by': request.user_id
    })
    
    return jsonify({
        'message': 'Group buy delete request received',
        'status': 'processing'
    }), 202

@app.route('/group-buys/<group_buy_id>/participants', methods=['GET'])
def get_group_buy_participants(group_buy_id):
    """Get all participants in a group buy"""
    # Send message to RabbitMQ
    message_queue.publish('product.get_group_buy_participants', {
        'group_buy_id': group_buy_id
    })
    
    return jsonify({
        'message': 'Participants request received',
        'status': 'processing'
    }), 202

@app.route('/api/group-buys/<group_buy_id>/join', methods=['POST'])
@token_required
def join_group_buy(group_buy_id):
    try:
        # Track group buy join
        track_user_activity('group_buy_joined', request.user_role)
        
        # Send message to message processor
        response = message_queue.publish_and_wait('group_buy.joined', {
            'group_buy_id': group_buy_id,
            'user_id': request.user_id
        })
        
        if not response:
            return jsonify({'error': 'Failed to join group buy'}), 500
            
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Error in join_group_buy: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/group-buys/<group_buy_id>/leave', methods=['POST'])
@token_required
def leave_group_buy(group_buy_id):
    try:
        # Track group buy leave
        track_user_activity('group_buy_left', request.user_role)
        
        # Send message to message processor
        response = message_queue.publish_and_wait('group_buy.left', {
            'group_buy_id': group_buy_id,
            'user_id': request.user_id
        })
        
        if not response:
            return jsonify({'error': 'Failed to leave group buy'}), 500
            
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Error in leave_group_buy: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Create tables if they don't exist
with app.app_context():
    pass


if __name__ == '__main__':
    port = int(os.getenv('PORT', 5004))
    app.run(host='0.0.0.0', port=port, debug=os.getenv('DEBUG', 'False').lower() == 'true')