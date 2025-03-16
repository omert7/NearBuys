"""
Main application file for the message processor.
"""
import json
import logging
import os
from typing import Dict, Any, Callable
from dotenv import load_dotenv
from shared.utils.prometheus_metrics import init_metrics, MESSAGE_PROCESSING_TIME

# Load environment variables
load_dotenv()

# Import configuration
from config.settings import logger

# Import utilities
from utils.db import db
from utils.messaging import message_queue

# Import handlers
from handlers.user_handlers import (
    handle_user_created, handle_user_login, handle_user_get_profile,
    handle_user_updated, handle_user_password_change, handle_user_rated,
    handle_user_address_added, handle_user_address_updated, handle_user_address_deleted,
    handle_user_preferences_updated, handle_user_privacy_settings_updated,
    handle_user_deactivated, handle_user_reactivated
)
from handlers.product_handlers import (
    handle_product_created, handle_product_category_created,
    handle_product_category_updated, handle_product_category_deleted,
    handle_product_updated, handle_product_deleted
)
from handlers.seller_handlers import (
    handle_seller_created, handle_seller_rated, handle_seller_verified,
    handle_seller_updated, handle_seller_deactivated, handle_seller_reactivated
)
from handlers.group_buy_handlers import (
    handle_group_buy_created, handle_group_buy_updated,
    handle_group_buy_deleted, handle_group_buy_joined, handle_group_buy_left
)
from handlers.bid_handlers import (
    handle_bid_created, handle_bid_updated, handle_bid_deleted,
    handle_bid_accepted, handle_bid_rejected
)

# Initialize Prometheus metrics
metrics_port = int(os.getenv('METRICS_PORT', 8004))
init_metrics('message-processor', '1.0.0', metrics_port)

class MessageProcessor:
    def __init__(self):
        """Initialize the message processor"""
        # Message handlers for different event types
        self.handlers = {
            'user.created': handle_user_created,
            'user.login': handle_user_login,
            'user.get_profile': handle_user_get_profile,
            'user.updated': handle_user_updated,
            'user.password_change': handle_user_password_change,
            'user.rated': handle_user_rated,
            'user.address_added': handle_user_address_added,
            'user.address_updated': handle_user_address_updated,
            'user.address_deleted': handle_user_address_deleted,
            'user.preferences_updated': handle_user_preferences_updated,
            'user.privacy_settings_updated': handle_user_privacy_settings_updated,
            'user.deactivated': handle_user_deactivated,
            'user.reactivated': handle_user_reactivated,
            'product.created': handle_product_created,
            'product.category_created': handle_product_category_created,
            'product.category_updated': handle_product_category_updated,
            'product.category_deleted': handle_product_category_deleted,
            'product.updated': handle_product_updated,
            'product.deleted': handle_product_deleted,
            'seller.created': handle_seller_created,
            'seller.rated': handle_seller_rated,
            'seller.verified': handle_seller_verified,
            'seller.updated': handle_seller_updated,
            'seller.deactivated': handle_seller_deactivated,
            'seller.reactivated': handle_seller_reactivated,
            'group_buy.created': handle_group_buy_created,
            'group_buy.updated': handle_group_buy_updated,
            'group_buy.deleted': handle_group_buy_deleted,
            'group_buy.joined': handle_group_buy_joined,
            'group_buy.left': handle_group_buy_left,
            'bid.created': handle_bid_created,
            'bid.updated': handle_bid_updated,
            'bid.deleted': handle_bid_deleted,
            'bid.accepted': handle_bid_accepted,
            'bid.rejected': handle_bid_rejected
        }
        
        # Setup queues and exchanges
        self.setup_queues()

    def setup_queues(self):
        """Setup RabbitMQ queues and exchanges"""
        # Setup message queue
        message_queue.setup_queues()
        
        # Register consumers for each queue
        for queue_name in ['user_events', 'product_events', 'seller_events', 'group_buy_events', 'bid_events']:
            message_queue.register_consumer(queue_name, self.process_message)
        
        logger.info("Successfully registered consumers for all queues")

    def process_message(self, ch, method, properties, body):
        """Process incoming messages"""
        event_type = None
        start_time = None
        try:
            # Start timing the message processing
            import time
            start_time = time.time()
            
            # Convert bytes to string then parse JSON
            message_str = body.decode('utf-8')
            message = json.loads(message_str)
            event_type = message.get('event_type')
            
            logger.info(f"Received message with routing key: {method.routing_key}, event_type: {event_type}")
            
            if event_type in self.handlers:
                logger.info(f"Processing event: {event_type} with data: {message.get('data')}")
                
                # Call the appropriate handler
                response = self.handlers[event_type](message)
                
                # Send response if handler returned data and we have a correlation_id
                if response and properties.correlation_id:
                    logger.info(f"Sending response for event: {event_type} with correlation_id: {properties.correlation_id}")
                    # Use correct routing key based on reply_to if available
                    response_routing_key = f"{event_type}.response"
                    if properties.reply_to:
                        logger.info(f"Using reply_to queue: {properties.reply_to}")
                        response_routing_key = properties.reply_to
                    message_queue.send_response(response_routing_key, response, properties.correlation_id)
                    logger.info(f"Response sent to {response_routing_key} with data: {response}")
                
                # Acknowledge the message
                ch.basic_ack(delivery_tag=method.delivery_tag)
                logger.info(f"Message acknowledged for event: {event_type}")
                
                # Record message processing time
                if start_time and event_type:
                    processing_time = time.time() - start_time
                    MESSAGE_PROCESSING_TIME.labels(event_type=event_type).observe(processing_time)
            else:
                logger.warning(f"Unknown event type: {event_type}")
                # Reject the message without requeuing since we don't know how to handle it
                ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
                
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON message: {str(e)}, message body: {body}")
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
        except Exception as e:
            logger.error(f"Error processing message: {str(e)}")
            # Send error response if we have a correlation_id
            if event_type and properties and hasattr(properties, 'correlation_id') and properties.correlation_id:
                error_response = {
                    'error': str(e),
                    'correlation_id': properties.correlation_id
                }
                error_routing_key = f"{event_type}.error"
                logger.info(f"Sending error response to {error_routing_key}: {error_response}")
                try:
                    message_queue.send_response(error_routing_key, error_response, properties.correlation_id)
                except Exception as e_response:
                    logger.error(f"Failed to send error response: {str(e_response)}")
            
            # Requeue the message for later processing
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)
            
            # Record processing time for failed messages
            if start_time and event_type:
                processing_time = time.time() - start_time
                MESSAGE_PROCESSING_TIME.labels(event_type=f"{event_type}_failed").observe(processing_time)

    def run(self):
        """Start consuming messages"""
        logger.info("Starting message processor...")
        try:
            message_queue.start_consuming()
        except KeyboardInterrupt:
            logger.info("Stopping message processor...")
        finally:
            message_queue.stop()

if __name__ == '__main__':
    processor = MessageProcessor()
    processor.run() 