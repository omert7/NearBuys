"""
Group buy event handlers for the message processor.
"""
import json
from typing import Dict, Any
from config.settings import logger
from utils.db import db

def handle_group_buy_created(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle group buy creation event"""
    session = db.get_session()
    try:
        group_buy_data = message.get('data', {})
        
        if not group_buy_data:
            return {'success': False, 'error': 'Missing group buy data'}
        
        query = """
            INSERT INTO group_buys (
                product_id, creator_id, min_participants, max_participants,
                discount_percentage, start_date, end_date, status, created_at
            )
            VALUES (
                :product_id, :creator_id, :min_participants, :max_participants,
                :discount_percentage, :start_date, :end_date, :status, NOW()
            )
            RETURNING id, product_id, creator_id, status
        """
        
        result = db.execute_query(query, {
            'product_id': group_buy_data.get('product_id'),
            'creator_id': group_buy_data.get('creator_id'),
            'min_participants': group_buy_data.get('min_participants'),
            'max_participants': group_buy_data.get('max_participants'),
            'discount_percentage': group_buy_data.get('discount_percentage'),
            'start_date': group_buy_data.get('start_date'),
            'end_date': group_buy_data.get('end_date'),
            'status': 'active'
        }, commit=True).fetchone()
        
        return {'success': True, 'group_buy': dict(result)}
    except Exception as e:
        logger.error(f"Error creating group buy: {str(e)}")
        return {'success': False, 'error': str(e)}
    finally:
        session.close()

def handle_group_buy_updated(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle group buy update event"""
    try:
        group_buy_id = message.get('group_buy_id')
        update_data = message.get('update_data', {})
        
        if not group_buy_id or not update_data:
            return {'success': False, 'error': 'Missing required fields'}
        
        session = db.get_session()
        try:
            # Build dynamic update query
            update_fields = []
            params = {'group_buy_id': group_buy_id}
            
            for key, value in update_data.items():
                if key in ['min_participants', 'max_participants', 'discount_percentage', 'end_date', 'status']:
                    update_fields.append(f"{key} = :{key}")
                    params[key] = value
            
            if not update_fields:
                return {'success': False, 'error': 'No valid fields to update'}
            
            update_query = f"""
                UPDATE group_buys
                SET {', '.join(update_fields)},
                    updated_at = NOW()
                WHERE id = :group_buy_id
                RETURNING id, status
            """
            
            result = db.execute_query(update_query, params, commit=True).fetchone()
            
            if not result:
                return {'success': False, 'error': 'Group buy not found'}
            
            return {'success': True, 'group_buy': dict(result)}
        except Exception as e:
            logger.error(f"Error updating group buy: {str(e)}")
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
    except Exception as e:
        logger.error(f"Error in handle_group_buy_updated: {str(e)}")
        return {'success': False, 'error': str(e)}

def handle_group_buy_deleted(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle group buy deletion event"""
    try:
        group_buy_id = message.get('group_buy_id')
        
        if not group_buy_id:
            return {'success': False, 'error': 'Missing group_buy_id'}
        
        session = db.get_session()
        try:
            # Delete group buy
            delete_query = """
                DELETE FROM group_buys
                WHERE id = :group_buy_id
            """
            
            db.execute_query(delete_query, {'group_buy_id': group_buy_id}, commit=True)
            
            return {'success': True, 'message': 'Group buy deleted successfully'}
        except Exception as e:
            logger.error(f"Error deleting group buy: {str(e)}")
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
    except Exception as e:
        logger.error(f"Error in handle_group_buy_deleted: {str(e)}")
        return {'success': False, 'error': str(e)}

def handle_group_buy_joined(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle group buy join event"""
    try:
        group_buy_id = message.get('group_buy_id')
        user_id = message.get('user_id')
        
        if not group_buy_id or not user_id:
            return {'success': False, 'error': 'Missing required fields'}
        
        session = db.get_session()
        try:
            # Add user as participant
            insert_query = """
                INSERT INTO group_buy_participants (
                    group_buy_id, user_id, joined_at
                )
                VALUES (
                    :group_buy_id, :user_id, NOW()
                )
            """
            
            db.execute_query(insert_query, {
                'group_buy_id': group_buy_id,
                'user_id': user_id
            }, commit=True)
            
            return {'success': True, 'message': 'Successfully joined group buy'}
        except Exception as e:
            logger.error(f"Error joining group buy: {str(e)}")
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
    except Exception as e:
        logger.error(f"Error in handle_group_buy_joined: {str(e)}")
        return {'success': False, 'error': str(e)}

def handle_group_buy_left(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle group buy leave event"""
    try:
        group_buy_id = message.get('group_buy_id')
        user_id = message.get('user_id')
        
        if not group_buy_id or not user_id:
            return {'success': False, 'error': 'Missing required fields'}
        
        session = db.get_session()
        try:
            # Remove user from participants
            delete_query = """
                DELETE FROM group_buy_participants
                WHERE group_buy_id = :group_buy_id AND user_id = :user_id
            """
            
            db.execute_query(delete_query, {
                'group_buy_id': group_buy_id,
                'user_id': user_id
            }, commit=True)
            
            return {'success': True, 'message': 'Successfully left group buy'}
        except Exception as e:
            logger.error(f"Error leaving group buy: {str(e)}")
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
    except Exception as e:
        logger.error(f"Error in handle_group_buy_left: {str(e)}")
        return {'success': False, 'error': str(e)}

# Add more group buy handlers as needed 