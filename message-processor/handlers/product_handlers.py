"""
Product event handlers for the message processor.
"""
import json
from typing import Dict, Any
from config.settings import logger
from utils.db import db

def handle_product_created(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle product creation event"""
    session = db.get_session()
    try:
        product_data = message.get('data', {})
        
        if not product_data:
            return {'success': False, 'error': 'Missing product data'}
        
        query = """
            INSERT INTO products (
                name, description, price, seller_id, category_id, 
                stock_quantity, image_url, created_at
            )
            VALUES (
                :name, :description, :price, :seller_id, :category_id,
                :stock_quantity, :image_url, NOW()
            )
            RETURNING id, name, price
        """
        
        result = db.execute_query(query, {
            'name': product_data.get('name'),
            'description': product_data.get('description'),
            'price': product_data.get('price'),
            'seller_id': product_data.get('seller_id'),
            'category_id': product_data.get('category_id'),
            'stock_quantity': product_data.get('stock_quantity', 0),
            'image_url': product_data.get('image_url')
        }, commit=True).fetchone()
        
        return {'success': True, 'product': dict(result)}
    except Exception as e:
        logger.error(f"Error creating product: {str(e)}")
        return {'success': False, 'error': str(e)}
    finally:
        session.close()

def handle_product_category_created(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle product category creation event"""
    try:
        category_data = message.get('data', {})
        
        if not category_data:
            return {'success': False, 'error': 'Missing category data'}
        
        session = db.get_session()
        try:
            query = """
                INSERT INTO product_categories (id, name, description, created_at)
                VALUES (:id, :name, :description, NOW())
                RETURNING id, name, description, created_at
            """
            
            result = db.execute_query(query, {
                'id': category_data.get('id'),
                'name': category_data.get('name'),
                'description': category_data.get('description')
            }, commit=True).fetchone()
            
            return {'success': True, 'category': dict(result)}
        except Exception as e:
            logger.error(f"Error creating category: {str(e)}")
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
    except Exception as e:
        logger.error(f"Error in handle_product_category_created: {str(e)}")
        return {'success': False, 'error': str(e)}

def handle_product_category_updated(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle product category update event"""
    try:
        category_id = message.get('category_id')
        update_data = message.get('update_data', {})
        
        if not category_id or not update_data:
            return {'success': False, 'error': 'Missing required fields'}
        
        session = db.get_session()
        try:
            # Build dynamic update query
            update_fields = []
            params = {'category_id': category_id}
            
            for key, value in update_data.items():
                if key in ['name', 'description']:
                    update_fields.append(f"{key} = :{key}")
                    params[key] = value
            
            if not update_fields:
                return {'success': False, 'error': 'No valid fields to update'}
            
            update_query = f"""
                UPDATE product_categories
                SET {', '.join(update_fields)},
                    updated_at = NOW()
                WHERE id = :category_id
                RETURNING id, name, description
            """
            
            result = db.execute_query(update_query, params, commit=True).fetchone()
            
            if not result:
                return {'success': False, 'error': 'Category not found'}
            
            return {'success': True, 'category': dict(result)}
        except Exception as e:
            logger.error(f"Error updating category: {str(e)}")
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
    except Exception as e:
        logger.error(f"Error in handle_product_category_updated: {str(e)}")
        return {'success': False, 'error': str(e)}

def handle_product_category_deleted(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle product category deletion event"""
    try:
        category_id = message.get('category_id')
        
        if not category_id:
            return {'success': False, 'error': 'Missing category_id'}
        
        session = db.get_session()
        try:
            # Check if category is in use
            check_query = """
                SELECT COUNT(*) FROM products WHERE category_id = :category_id
            """
            count = db.execute_query(check_query, {'category_id': category_id}).fetchone()[0]
            
            if count > 0:
                return {'success': False, 'error': 'Category is in use by products and cannot be deleted'}
            
            # Delete category
            delete_query = """
                DELETE FROM product_categories
                WHERE id = :category_id
            """
            
            db.execute_query(delete_query, {'category_id': category_id}, commit=True)
            
            return {'success': True, 'message': 'Category deleted successfully'}
        except Exception as e:
            logger.error(f"Error deleting category: {str(e)}")
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
    except Exception as e:
        logger.error(f"Error in handle_product_category_deleted: {str(e)}")
        return {'success': False, 'error': str(e)}

def handle_product_updated(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle product update event"""
    try:
        product_id = message.get('product_id')
        update_data = message.get('update_data', {})
        
        if not product_id or not update_data:
            return {'success': False, 'error': 'Missing required fields'}
        
        session = db.get_session()
        try:
            # Build dynamic update query
            update_fields = []
            params = {'product_id': product_id}
            
            for key, value in update_data.items():
                if key in ['name', 'description', 'price', 'category_id', 'stock_quantity', 'image_url']:
                    update_fields.append(f"{key} = :{key}")
                    params[key] = value
            
            if not update_fields:
                return {'success': False, 'error': 'No valid fields to update'}
            
            update_query = f"""
                UPDATE products
                SET {', '.join(update_fields)},
                    updated_at = NOW()
                WHERE id = :product_id
                RETURNING id, name, price
            """
            
            result = db.execute_query(update_query, params, commit=True).fetchone()
            
            if not result:
                return {'success': False, 'error': 'Product not found'}
            
            return {'success': True, 'product': dict(result)}
        except Exception as e:
            logger.error(f"Error updating product: {str(e)}")
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
    except Exception as e:
        logger.error(f"Error in handle_product_updated: {str(e)}")
        return {'success': False, 'error': str(e)}

def handle_product_deleted(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle product deletion event"""
    try:
        product_id = message.get('product_id')
        
        if not product_id:
            return {'success': False, 'error': 'Missing product_id'}
        
        session = db.get_session()
        try:
            query = """
                DELETE FROM products
                WHERE id = :product_id
            """
            
            db.execute_query(query, {'product_id': product_id}, commit=True)
            
            return {'success': True, 'message': 'Product deleted successfully'}
        except Exception as e:
            logger.error(f"Error deleting product: {str(e)}")
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
    except Exception as e:
        logger.error(f"Error in handle_product_deleted: {str(e)}")
        return {'success': False, 'error': str(e)}

# Add more product handlers as needed 