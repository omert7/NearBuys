"""
User event handlers for the message processor.
"""
import json
from typing import Dict, Any
import hashlib
import jwt
import datetime
from config.settings import logger
from utils.db import db

def generate_password_hash(password: str) -> str:
    """Generate a password hash"""
    return hashlib.sha256(password.encode()).hexdigest()

def check_password_hash(stored_hash: str, password: str) -> bool:
    """Check if a password matches a hash"""
    return stored_hash == generate_password_hash(password)

def generate_token(user_id: int, role: str) -> str:
    """Generate a JWT token for a user"""
    payload = {
        'user_id': user_id,
        'role': role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
    }
    return jwt.encode(payload, 'your-secret-key', algorithm='HS256')  # יש להשתמש במפתח סודי מתצורה אמיתית

def check_if_user_exists(session, email: str) -> bool:
    """Check if user exists in database"""
    query = "SELECT COUNT(*) FROM users.users WHERE email = :email"
    result = db.execute_query(query, {'email': email}).fetchone()
    return result[0] > 0

def create_user(session, user_data: Dict[str, Any]) -> Dict[str, Any]:
    """Create user in database"""
    query = """
        INSERT INTO users.users (username, email, password)
        VALUES (:username, :email, :password_hash)
        RETURNING id
    """
    return db.execute_query(query, user_data, commit=True).fetchone()

def handle_user_created(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle user creation events and return created user data"""
    session = db.get_session()
    try:
        user_data = message.get('data', {})
        logger.info(f"Processing user creation with data: {user_data}")

        if check_if_user_exists(session, user_data.get('email')):
            return {'status': 'unsuccessful', 'error': 'User already exists'}

        create_user_result = create_user(session, user_data)
        logger.info(f"result: {create_user_result}")

        # Create default profile with correct schema
        profile_query = """INSERT INTO users.profiles (user_id, created_at) VALUES (:user_id, NOW())"""
        
        db.execute_query(profile_query, {'user_id': create_user_result.id}, commit=True)
        
        # Convert row to dict
        user_dict = dict(create_user_result)
        logger.info(f"Successfully created user: {user_dict}")
        user_dict['status'] = 'success'
        
        return user_dict
    except Exception as e:
        logger.error(f"Error creating user: {str(e)}")
        return {'status': 'unsuccessful', 'error': str(e)}
    finally:
        session.close()

def handle_user_login(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle user login and return token"""
    session = db.get_session()
    try:
        user_data = message.get('data', {})
        query = """
            SELECT id, password, role FROM users.users
            WHERE email = :email AND is_active = true
        """
        result = db.execute_query(query, {'email': user_data.get('email')}).fetchone()
        
        if not result or not check_password_hash(result.password, user_data.get('password')):
            raise ValueError("Invalid email or password")
        
        # Generate token
        token = generate_token(result.id, result.role)
        
        # Update last login
        update_query = """
            UPDATE users.users
            SET last_login = NOW()
            WHERE id = :id
        """
        db.execute_query(update_query, {'id': result.id}, commit=True)
        
        return {
            'token': token,
            'user_id': result.id,
            'role': result.role
        }
    except Exception as e:
        logger.error(f"Error handling user login: {str(e)}")
        raise
    finally:
        session.close()

def handle_user_get_profile(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle get user profile and return profile data"""
    session = db.get_session()
    try:
        user_id = message.get('data', {}).get('user_id')
        query = """
            SELECT u.*, p.bio, p.avatar_url
            FROM users.users u
            LEFT JOIN users.profiles p ON u.id = p.user_id
            WHERE u.id = :user_id
        """
        result = db.execute_query(query, {'user_id': user_id}).fetchone()
        
        if not result:
            raise ValueError("User not found")
        
        return dict(result)
    except Exception as e:
        logger.error(f"Error handling get user profile: {str(e)}")
        raise
    finally:
        session.close()

def handle_user_updated(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle user update events"""
    session = db.get_session()
    try:
        user_id = message.get('user_id')
        update_data = message.get('update_data', {})
        
        if not user_id or not update_data:
            return {'success': False, 'error': 'Missing required fields'}
        
        # Build dynamic update query
        update_fields = []
        params = {'user_id': user_id}
        
        for key, value in update_data.items():
            if key in ['username', 'email', 'first_name', 'last_name', 'phone']:
                update_fields.append(f"{key} = :{key}")
                params[key] = value
        
        if not update_fields:
            return {'success': False, 'error': 'No valid fields to update'}
        
        update_query = f"""
            UPDATE users.users
            SET {', '.join(update_fields)},
                updated_at = NOW()
            WHERE id = :user_id
            RETURNING id
        """
        
        result = db.execute_query(update_query, params, commit=True).fetchone()
        
        if not result:
            return {'success': False, 'error': 'User not found'}
        
        return {'success': True, 'message': 'User updated successfully'}
    except Exception as e:
        logger.error(f"Error updating user: {str(e)}")
        return {'success': False, 'error': str(e)}
    finally:
        session.close()

def handle_user_password_change(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle user password change"""
    try:
        user_id = message.get('user_id')
        old_password = message.get('old_password')
        new_password = message.get('new_password')
        
        if not all([user_id, old_password, new_password]):
            return {'success': False, 'error': 'Missing required fields'}
        
        session = db.get_session()
        try:
            # Verify old password
            verify_query = """
                SELECT password_hash FROM users WHERE id = :user_id
            """
            result = db.execute_query(verify_query, {'user_id': user_id}).fetchone()
            
            if not result or not check_password_hash(result.password_hash, old_password):
                return {'success': False, 'error': 'Invalid old password'}
            
            # Update password
            update_query = """
                UPDATE users 
                SET password_hash = :password_hash,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = :user_id
            """
            
            db.execute_query(update_query, {
                'user_id': user_id,
                'password_hash': generate_password_hash(new_password)
            }, commit=True)
            
            return {'success': True, 'message': 'Password updated successfully'}
        except Exception as e:
            logger.error(f"Error changing password: {str(e)}")
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
    except Exception as e:
        logger.error(f"Error in handle_user_password_change: {str(e)}")
        return {'success': False, 'error': str(e)}

def handle_user_rated(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle user rating event"""
    try:
        user_id = message.get('user_id')
        rater_id = message.get('rater_id')
        rating = message.get('rating')
        comment = message.get('comment')
        
        if not all([user_id, rater_id, rating]):
            return {'success': False, 'error': 'Missing required fields'}
        
        session = db.get_session()
        try:
            query = """
                INSERT INTO user_ratings (user_id, rater_id, rating, comment, created_at)
                VALUES (:user_id, :rater_id, :rating, :comment, NOW())
                ON CONFLICT (user_id, rater_id) DO UPDATE
                SET rating = EXCLUDED.rating,
                    comment = EXCLUDED.comment,
                    updated_at = NOW()
            """
            
            db.execute_query(query, {
                'user_id': user_id,
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
        logger.error(f"Error in handle_user_rated: {str(e)}")
        return {'success': False, 'error': str(e)}

def handle_user_address_added(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle user address addition event"""
    try:
        user_id = message.get('user_id')
        address_data = message.get('address_data', {})
        
        if not user_id or not address_data:
            return {'success': False, 'error': 'Missing required fields'}
        
        session = db.get_session()
        try:
            query = """
                INSERT INTO user_addresses (
                    user_id, street, city, state, postal_code, 
                    country, is_default, created_at
                )
                VALUES (
                    :user_id, :street, :city, :state, :postal_code,
                    :country, :is_default, NOW()
                )
                RETURNING id, street, city, state, postal_code, country, is_default
            """
            
            result = db.execute_query(query, {
                'user_id': user_id,
                'street': address_data.get('street'),
                'city': address_data.get('city'),
                'state': address_data.get('state'),
                'postal_code': address_data.get('postal_code'),
                'country': address_data.get('country'),
                'is_default': address_data.get('is_default', False)
            }, commit=True).fetchone()
            
            return {'success': True, 'address': dict(result)}
        except Exception as e:
            logger.error(f"Error adding address: {str(e)}")
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
    except Exception as e:
        logger.error(f"Error in handle_user_address_added: {str(e)}")
        return {'success': False, 'error': str(e)}

def handle_user_address_updated(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle user address update event"""
    try:
        address_id = message.get('address_id')
        address_data = message.get('address_data', {})
        
        if not address_id or not address_data:
            return {'success': False, 'error': 'Missing required fields'}
        
        session = db.get_session()
        try:
            # Build dynamic update query
            update_fields = []
            params = {'address_id': address_id}
            
            for key, value in address_data.items():
                if key in ['street', 'city', 'state', 'postal_code', 'country', 'is_default']:
                    update_fields.append(f"{key} = :{key}")
                    params[key] = value
            
            if not update_fields:
                return {'success': False, 'error': 'No valid fields to update'}
            
            update_query = f"""
                UPDATE user_addresses
                SET {', '.join(update_fields)},
                    updated_at = NOW()
                WHERE id = :address_id
                RETURNING id, street, city, state, postal_code, country, is_default
            """
            
            result = db.execute_query(update_query, params, commit=True).fetchone()
            
            if not result:
                return {'success': False, 'error': 'Address not found'}
            
            return {'success': True, 'address': dict(result)}
        except Exception as e:
            logger.error(f"Error updating address: {str(e)}")
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
    except Exception as e:
        logger.error(f"Error in handle_user_address_updated: {str(e)}")
        return {'success': False, 'error': str(e)}

def handle_user_address_deleted(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle user address deletion event"""
    try:
        address_id = message.get('address_id')
        
        if not address_id:
            return {'success': False, 'error': 'Missing address_id'}
        
        session = db.get_session()
        try:
            query = """
                DELETE FROM user_addresses
                WHERE id = :address_id
            """
            
            db.execute_query(query, {'address_id': address_id}, commit=True)
            
            return {'success': True, 'message': 'Address deleted successfully'}
        except Exception as e:
            logger.error(f"Error deleting address: {str(e)}")
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
    except Exception as e:
        logger.error(f"Error in handle_user_address_deleted: {str(e)}")
        return {'success': False, 'error': str(e)}

def handle_user_preferences_updated(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle user preferences update event"""
    try:
        user_id = message.get('user_id')
        preferences = message.get('preferences', {})
        
        if not user_id or not preferences:
            return {'success': False, 'error': 'Missing required fields'}
        
        session = db.get_session()
        try:
            query = """
                INSERT INTO user_preferences (user_id, preferences, created_at)
                VALUES (:user_id, :preferences, NOW())
                ON CONFLICT (user_id) DO UPDATE
                SET preferences = :preferences,
                    updated_at = NOW()
            """
            
            db.execute_query(query, {
                'user_id': user_id,
                'preferences': json.dumps(preferences)
            }, commit=True)
            
            return {'success': True, 'message': 'Preferences updated successfully'}
        except Exception as e:
            logger.error(f"Error updating preferences: {str(e)}")
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
    except Exception as e:
        logger.error(f"Error in handle_user_preferences_updated: {str(e)}")
        return {'success': False, 'error': str(e)}

def handle_user_privacy_settings_updated(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle user privacy settings update event"""
    try:
        user_id = message.get('user_id')
        privacy_settings = message.get('privacy_settings', {})
        
        if not user_id or not privacy_settings:
            return {'success': False, 'error': 'Missing required fields'}
        
        session = db.get_session()
        try:
            query = """
                INSERT INTO user_privacy_settings (user_id, settings, created_at)
                VALUES (:user_id, :settings, NOW())
                ON CONFLICT (user_id) DO UPDATE
                SET settings = :settings,
                    updated_at = NOW()
            """
            
            db.execute_query(query, {
                'user_id': user_id,
                'settings': json.dumps(privacy_settings)
            }, commit=True)
            
            return {'success': True, 'message': 'Privacy settings updated successfully'}
        except Exception as e:
            logger.error(f"Error updating privacy settings: {str(e)}")
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
    except Exception as e:
        logger.error(f"Error in handle_user_privacy_settings_updated: {str(e)}")
        return {'success': False, 'error': str(e)}

def handle_user_deactivated(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle user deactivation event"""
    try:
        user_id = message.get('user_id')
        
        if not user_id:
            return {'success': False, 'error': 'Missing user_id'}
        
        session = db.get_session()
        try:
            query = """
                UPDATE users.users
                SET is_active = false,
                    deactivated_at = NOW(),
                    updated_at = NOW()
                WHERE id = :user_id
            """
            
            db.execute_query(query, {'user_id': user_id}, commit=True)
            
            return {'success': True, 'message': 'User deactivated successfully'}
        except Exception as e:
            logger.error(f"Error deactivating user: {str(e)}")
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
    except Exception as e:
        logger.error(f"Error in handle_user_deactivated: {str(e)}")
        return {'success': False, 'error': str(e)}

def handle_user_reactivated(message: Dict[str, Any]) -> Dict[str, Any]:
    """Handle user reactivation event"""
    try:
        user_id = message.get('user_id')
        
        if not user_id:
            return {'success': False, 'error': 'Missing user_id'}
        
        session = db.get_session()
        try:
            query = """
                UPDATE users.users
                SET is_active = true,
                    deactivated_at = NULL,
                    updated_at = NOW()
                WHERE id = :user_id
            """
            
            db.execute_query(query, {'user_id': user_id}, commit=True)
            
            return {'success': True, 'message': 'User reactivated successfully'}
        except Exception as e:
            logger.error(f"Error reactivating user: {str(e)}")
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
    except Exception as e:
        logger.error(f"Error in handle_user_reactivated: {str(e)}")
        return {'success': False, 'error': str(e)}

# Add more user handlers as needed 