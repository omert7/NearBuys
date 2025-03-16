"""
Bid event handlers for the message processor.
"""
import json
from typing import Dict, Any
from config.settings import logger
from utils.db import db

def handle_bid_created(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle bid creation event"""
    session = db.get_session()
    try:
        bid_data = message.get('data', {})
        
        if not bid_data:
            return {'success': False, 'error': 'Missing bid data'}
        
        query = """
            INSERT INTO bids (
                product_id, bidder_id, amount, status, created_at
            )
            VALUES (
                :product_id, :bidder_id, :amount, :status, NOW()
            )
            RETURNING id, product_id, bidder_id, amount, status
        """
        
        result = db.execute_query(query, {
            'product_id': bid_data.get('product_id'),
            'bidder_id': bid_data.get('bidder_id'),
            'amount': bid_data.get('amount'),
            'status': 'pending'
        }, commit=True).fetchone()
        
        return {'success': True, 'bid': dict(result)}
    except Exception as e:
        logger.error(f"Error creating bid: {str(e)}")
        return {'success': False, 'error': str(e)}
    finally:
        session.close()

def handle_bid_updated(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle bid update event"""
    try:
        bid_id = message.get('bid_id')
        update_data = message.get('update_data', {})
        
        if not bid_id or not update_data:
            return {'success': False, 'error': 'Missing required fields'}
        
        session = db.get_session()
        try:
            # Build dynamic update query
            update_fields = []
            params = {'bid_id': bid_id}
            
            for key, value in update_data.items():
                if key in ['amount', 'status']:
                    update_fields.append(f"{key} = :{key}")
                    params[key] = value
            
            if not update_fields:
                return {'success': False, 'error': 'No valid fields to update'}
            
            update_query = f"""
                UPDATE bids
                SET {', '.join(update_fields)},
                    updated_at = NOW()
                WHERE id = :bid_id
                RETURNING id, amount, status
            """
            
            result = db.execute_query(update_query, params, commit=True).fetchone()
            
            if not result:
                return {'success': False, 'error': 'Bid not found'}
            
            return {'success': True, 'bid': dict(result)}
        except Exception as e:
            logger.error(f"Error updating bid: {str(e)}")
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
    except Exception as e:
        logger.error(f"Error in handle_bid_updated: {str(e)}")
        return {'success': False, 'error': str(e)}

def handle_bid_deleted(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle bid deletion event"""
    try:
        bid_id = message.get('bid_id')
        
        if not bid_id:
            return {'success': False, 'error': 'Missing bid_id'}
        
        session = db.get_session()
        try:
            query = """
                DELETE FROM bids
                WHERE id = :bid_id
            """
            
            db.execute_query(query, {'bid_id': bid_id}, commit=True)
            
            return {'success': True, 'message': 'Bid deleted successfully'}
        except Exception as e:
            logger.error(f"Error deleting bid: {str(e)}")
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
    except Exception as e:
        logger.error(f"Error in handle_bid_deleted: {str(e)}")
        return {'success': False, 'error': str(e)}

def handle_bid_accepted(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle bid acceptance event"""
    try:
        bid_id = message.get('bid_id')
        
        if not bid_id:
            return {'success': False, 'error': 'Missing bid_id'}
        
        session = db.get_session()
        try:
            # Update bid status
            update_query = """
                UPDATE bids
                SET status = 'accepted',
                    updated_at = NOW()
                WHERE id = :bid_id
                RETURNING id, product_id, bidder_id
            """
            
            result = db.execute_query(update_query, {'bid_id': bid_id}, commit=True).fetchone()
            
            if not result:
                return {'success': False, 'error': 'Bid not found'}
            
            # Reject all other bids for the same product
            reject_others_query = """
                UPDATE bids
                SET status = 'rejected',
                    updated_at = NOW()
                WHERE product_id = :product_id
                AND id != :bid_id
                AND status = 'pending'
            """
            
            db.execute_query(reject_others_query, {
                'product_id': result.product_id,
                'bid_id': bid_id
            }, commit=True)
            
            return {'success': True, 'message': 'Bid accepted successfully'}
        except Exception as e:
            logger.error(f"Error accepting bid: {str(e)}")
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
    except Exception as e:
        logger.error(f"Error in handle_bid_accepted: {str(e)}")
        return {'success': False, 'error': str(e)}

def handle_bid_rejected(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle bid rejection event"""
    try:
        bid_id = message.get('bid_id')
        
        if not bid_id:
            return {'success': False, 'error': 'Missing bid_id'}
        
        session = db.get_session()
        try:
            query = """
                UPDATE bids
                SET status = 'rejected',
                    updated_at = NOW()
                WHERE id = :bid_id
            """
            
            db.execute_query(query, {'bid_id': bid_id}, commit=True)
            
            return {'success': True, 'message': 'Bid rejected successfully'}
        except Exception as e:
            logger.error(f"Error rejecting bid: {str(e)}")
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
    except Exception as e:
        logger.error(f"Error in handle_bid_rejected: {str(e)}")
        return {'success': False, 'error': str(e)}

# Add more bid handlers as needed 