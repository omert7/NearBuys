"""
Messaging utilities for the message processor.
"""
import json
import pika
from config.settings import RABBITMQ_URL, EXCHANGE_NAME, EXCHANGE_TYPE, QUEUE_DEFINITIONS, logger

class MessageQueue:
    """Message queue connection manager"""
    
    def __init__(self, rabbitmq_url=None):
        """Initialize message queue connection"""
        self.rabbitmq_url = rabbitmq_url or RABBITMQ_URL
        self.connection = None
        self.channel = None
        self.connect()
        
    def connect(self):
        """Connect to RabbitMQ"""
        try:
            self.connection = pika.BlockingConnection(pika.URLParameters(self.rabbitmq_url))
            self.channel = self.connection.channel()
            logger.info(f"Connected to RabbitMQ at {self.rabbitmq_url}")
        except Exception as e:
            logger.error(f"Failed to connect to RabbitMQ: {str(e)}")
            raise
    
    def setup_queues(self):
        """Setup RabbitMQ queues and exchanges"""
        # Declare exchange
        self.channel.exchange_declare(
            exchange=EXCHANGE_NAME,
            exchange_type=EXCHANGE_TYPE,
            durable=True
        )
        
        # Declare queues for each service with corresponding routing patterns
        for queue_name, routing_patterns in QUEUE_DEFINITIONS.items():
            # First check if queue exists (optional - skip if not)
            try:
                self.channel.queue_delete(queue=queue_name)
                logger.info(f"Deleted existing queue: {queue_name}")
            except Exception as e:
                logger.warning(f"Queue {queue_name} might not exist yet: {str(e)}")
            
            # Create queue
            self.channel.queue_declare(queue=queue_name, durable=True)
            
            # Bind with multiple patterns
            for pattern in routing_patterns:
                logger.info(f"Binding queue {queue_name} to routing key {pattern}")
                self.channel.queue_bind(
                    exchange=EXCHANGE_NAME,
                    queue=queue_name,
                    routing_key=pattern
                )
        
        logger.info("Successfully set up message queues")
    
    def register_consumer(self, queue_name, callback):
        """Register a consumer for a queue"""
        self.channel.basic_consume(
            queue=queue_name,
            on_message_callback=callback,
            auto_ack=False
        )
        logger.info(f"Registered consumer for queue: {queue_name}")
    
    def send_response(self, routing_key, response_data, correlation_id=None):
        """Send response back to service"""
        try:
            properties = pika.BasicProperties(
                delivery_mode=2,  # make message persistent
                content_type='application/json'
            )
            
            if correlation_id:
                properties.correlation_id = correlation_id
            
            self.channel.basic_publish(
                exchange=EXCHANGE_NAME,
                routing_key=routing_key,
                body=json.dumps(response_data),
                properties=properties
            )
            logger.info(f"Response sent to {routing_key} with correlation_id: {correlation_id}")
        except Exception as e:
            logger.error(f"Error sending response: {str(e)}")
            raise
    
    def start_consuming(self):
        """Start consuming messages"""
        try:
            logger.info("Starting to consume messages")
            self.channel.start_consuming()
        except KeyboardInterrupt:
            logger.info("Stopping message consumption")
            self.stop()
        except Exception as e:
            logger.error(f"Error consuming messages: {str(e)}")
            self.stop()
            raise
    
    def stop(self):
        """Close connection"""
        if self.connection and self.connection.is_open:
            self.connection.close()
            logger.info("Closed RabbitMQ connection")

# Create a default message queue instance
message_queue = MessageQueue() 