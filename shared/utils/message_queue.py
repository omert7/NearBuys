import json
import pika
import os
from dotenv import load_dotenv
import logging

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MessageQueue:
    def __init__(self):
        self.rabbitmq_url = os.getenv('RABBITMQ_URL')
        self.connection = None
        self.channel = None
        self._connect()

    def _connect(self):
        try:
            # Create a connection to RabbitMQ
            parameters = pika.URLParameters(self.rabbitmq_url)
            self.connection = pika.BlockingConnection(parameters)
            self.channel = self.connection.channel()
            
            # Declare exchanges
            self.channel.exchange_declare(
                exchange='neighborbuy',
                exchange_type='topic',
                durable=True
            )
            
            # Declare queues
            self.channel.queue_declare(queue='user_events', durable=True)
            self.channel.queue_declare(queue='product_events', durable=True)
            self.channel.queue_declare(queue='seller_events', durable=True)
            
            # Bind queues to exchange
            self.channel.queue_bind(
                exchange='neighborbuy',
                queue='user_events',
                routing_key='user.#'
            )
            self.channel.queue_bind(
                exchange='neighborbuy',
                queue='product_events',
                routing_key='product.#'
            )
            self.channel.queue_bind(
                exchange='neighborbuy',
                queue='seller_events',
                routing_key='seller.#'
            )
            
            logger.info("Connected to RabbitMQ")
        except Exception as e:
            logger.error(f"Failed to connect to RabbitMQ: {str(e)}")
            # Implement retry logic if needed

    def publish(self, routing_key, message):
        """Publish a message to the exchange with the given routing key"""
        if not self.connection or self.connection.is_closed:
            self._connect()
            
        try:
            self.channel.basic_publish(
                exchange='neighborbuy',
                routing_key=routing_key,
                body=json.dumps(message),
                properties=pika.BasicProperties(
                    delivery_mode=2,  # make message persistent
                    content_type='application/json'
                )
            )
            logger.info(f"Published message to {routing_key}")
            return True
        except Exception as e:
            logger.error(f"Failed to publish message: {str(e)}")
            return False

    def consume(self, queue_name, callback):
        """Set up a consumer for the given queue"""
        if not self.connection or self.connection.is_closed:
            self._connect()
            
        try:
            self.channel.basic_consume(
                queue=queue_name,
                on_message_callback=callback,
                auto_ack=True
            )
            logger.info(f"Set up consumer for {queue_name}")
        except Exception as e:
            logger.error(f"Failed to set up consumer: {str(e)}")

    def start_consuming(self):
        """Start consuming messages"""
        if not self.connection or self.connection.is_closed:
            self._connect()
            
        try:
            logger.info("Started consuming messages")
            self.channel.start_consuming()
        except Exception as e:
            logger.error(f"Error while consuming messages: {str(e)}")

    def close(self):
        """Close the connection"""
        if self.connection and not self.connection.is_closed:
            self.connection.close()
            logger.info("Closed connection to RabbitMQ")