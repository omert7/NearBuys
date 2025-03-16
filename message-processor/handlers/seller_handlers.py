"""
Seller event handlers for the message processor.
"""
import json
from typing import Dict, Any
from config.settings import logger
from utils.db import db

def handle_seller_created(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle seller creation event"""
    session = db.get_session()
    try:
        seller_data = message.get('data', {})
        
        if not seller_data:
            return {'success': False, 'error': 'Missing seller data'}
        
        query = """
            INSERT INTO sellers (
                user_id, business_name, business_description, 
                contact_email, contact_phone, created_at
            )
            VALUES (
                :user_id, :business_name, :business_description,
                :contact_email, :contact_phone, NOW()
            )
            RETURNING id, user_id, business_name
        """
        
        result = db.execute_query(query, {
            'user_id': seller_data.get('user_id'),
            'business_name': seller_data.get('business_name'),
            'business_description': seller_data.get('business_description'),
            'contact_email': seller_data.get('contact_email'),
            'contact_phone': seller_data.get('contact_phone')
        }, commit=True).fetchone()
        
        return {'success': True, 'seller': dict(result)}
    except Exception as e:
        logger.error(f"Error creating seller: {str(e)}")
        return {'success': False, 'error': str(e)}
    finally:
        session.close()

def handle_seller_rated(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle seller rating event"""
    try:
        seller_id = message.get('seller_id')
        rater_id = message.get('rater_id')
        rating = message.get('rating')
        comment = message.get('comment')
        
        if not all([seller_id, rater_id, rating]):
            return {'success': False, 'error': 'Missing required fields'}
        
        session = db.get_session()
        try:
            query = """
                INSERT INTO seller_ratings (seller_id, rater_id, rating, comment, created_at)
                VALUES (:seller_id, :rater_id, :rating, :comment, NOW())
                ON CONFLICT (seller_id, rater_id) DO UPDATE
                SET rating = EXCLUDED.rating,
                    comment = EXCLUDED.comment,
                    updated_at = NOW()
            """
            
            db.execute_query(query, {
                'seller_id': seller_id,
                'rater_id': rater_id,
                'rating': rating,
                'comment': comment
            }, commit=True)
            
            return {'success': True, 'message': 'Rating saved successfully'}
        except Exception as e:
            logger.error(f"Error saving rating: {str(e)}")
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
    except Exception as e:
        logger.error(f"Error in handle_seller_rated: {str(e)}")
        return {'success': False, 'error': str(e)}

def handle_seller_verified(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle seller verification event"""
    try:
        seller_id = message.get('seller_id')
        verified = message.get('verified', False)
        
        if not seller_id:
            return {'success': False, 'error': 'Missing seller_id'}
        
        session = db.get_session()
        try:
            query = """
                UPDATE sellers
                SET 
                    is_verified = :verified,
                    verified_at = CASE WHEN :verified THEN NOW() ELSE NULL END,
                    updated_at = NOW()
                WHERE id = :seller_id
            """
            
            db.execute_query(query, {
                'seller_id': seller_id,
                'verified': verified
            }, commit=True)
            
            return {'success': True, 'message': f'Seller verification status set to {verified}'}
        except Exception as e:
            logger.error(f"Error updating seller verification: {str(e)}")
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
    except Exception as e:
        logger.error(f"Error in handle_seller_verified: {str(e)}")
        return {'success': False, 'error': str(e)}

def handle_seller_updated(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle seller update event"""
    try:
        seller_id = message.get('seller_id')
        update_data = message.get('update_data', {})
        
        if not seller_id or not update_data:
            return {'success': False, 'error': 'Missing required fields'}
        
        session = db.get_session()
        try:
            # Build dynamic update query
            update_fields = []
            params = {'seller_id': seller_id}
            
            for key, value in update_data.items():
                if key in ['business_name', 'business_description', 'contact_email', 'contact_phone']:
                    update_fields.append(f"{key} = :{key}")
                    params[key] = value
            
            if not update_fields:
                return {'success': False, 'error': 'No valid fields to update'}
            
            update_query = f"""
                UPDATE sellers
                SET {', '.join(update_fields)},
                    updated_at = NOW()
                WHERE id = :seller_id
                RETURNING id, business_name
            """
            
            result = db.execute_query(update_query, params, commit=True).fetchone()
            
            if not result:
                return {'success': False, 'error': 'Seller not found'}
            
            return {'success': True, 'seller': dict(result)}
        except Exception as e:
            logger.error(f"Error updating seller: {str(e)}")
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
    except Exception as e:
        logger.error(f"Error in handle_seller_updated: {str(e)}")
        return {'success': False, 'error': str(e)}

def handle_seller_deactivated(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle seller deactivation event"""
    try:
        seller_id = message.get('seller_id')
        
        if not seller_id:
            return {'success': False, 'error': 'Missing seller_id'}
        
        session = db.get_session()
        try:
            query = """
                UPDATE sellers
                SET 
                    is_active = false,
                    deactivated_at = NOW(),
                    updated_at = NOW()
                WHERE id = :seller_id
            """
            
            db.execute_query(query, {'seller_id': seller_id}, commit=True)
            
            return {'success': True, 'message': 'Seller deactivated successfully'}
        except Exception as e:
            logger.error(f"Error deactivating seller: {str(e)}")
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
    except Exception as e:
        logger.error(f"Error in handle_seller_deactivated: {str(e)}")
        return {'success': False, 'error': str(e)}

def handle_seller_reactivated(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle seller reactivation event"""
    try:
        seller_id = message.get('seller_id')
        
        if not seller_id:
            return {'success': False, 'error': 'Missing seller_id'}
        
        session = db.get_session()
        try:
            query = """
                UPDATE sellers
                SET 
                    is_active = true,
                    deactivated_at = NULL,
                    updated_at = NOW()
                WHERE id = :seller_id
            """
            
            db.execute_query(query, {'seller_id': seller_id}, commit=True)
            
            return {'success': True, 'message': 'Seller reactivated successfully'}
        except Exception as e:
            logger.error(f"Error reactivating seller: {str(e)}")
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
    except Exception as e:
        logger.error(f"Error in handle_seller_reactivated: {str(e)}")
        return {'success': False, 'error': str(e)}

# Add more seller handlers as needed 