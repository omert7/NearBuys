import json
import pika
import os
from dotenv import load_dotenv
import logging
import uuid
import time
import threading
from typing import Dict, Any, Optional
from pika.exceptions import AMQPConnectionError, AMQPChannelError, ConnectionClosedByBroker, StreamLostError
from pika.adapters.blocking_connection import BlockingChannel
from shared.utils.prometheus_metrics import track_message_queue_operation, MESSAGE_QUEUE_OPERATIONS

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MessageQueue:
    def __init__(self, max_retries=5, retry_delay=5):
        self.rabbitmq_url = os.getenv('RABBITMQ_URL', 'amqp://guest:guest@rabbitmq:5672/')
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.connection = None
        self.channel = None
        self.heartbeat_interval = 5  # Seconds between heartbeats
        self.is_running = True
        self.connection_lock = threading.RLock()
        self.heartbeat_thread = None
        self._connect()
        self._start_heartbeat_thread()
        
    def _start_heartbeat_thread(self):
        """Start a background thread that ensures heartbeats are sent regularly"""
        self.heartbeat_thread = threading.Thread(target=self._heartbeat_worker, daemon=True)
        self.heartbeat_thread.start()
        logger.info("Started heartbeat thread")
        
    def _heartbeat_worker(self):
        """Worker that runs in background to ensure heartbeats"""
        while self.is_running:
            try:
                with self.connection_lock:
                    if self.connection and not self.connection.is_closed:
                        # Process data events to send heartbeats
                        self.connection.process_data_events(0)
                        logger.debug("Heartbeat sent")
            except (AMQPConnectionError, AMQPChannelError, ConnectionClosedByBroker, StreamLostError) as e:
                logger.warning(f"Connection error in heartbeat thread: {str(e)}")
                try:
                    self._ensure_connection()
                except Exception as e:
                    logger.error(f"Failed to reconnect in heartbeat thread: {str(e)}")
            except Exception as e:
                logger.error(f"Error in heartbeat thread: {str(e)}")
                
            # Sleep for heartbeat interval
            time.sleep(self.heartbeat_interval)
        
    @track_message_queue_operation('connection', 'connect')
    def _connect(self):
        """Establish connection to RabbitMQ with retries"""
        with self.connection_lock:
            for attempt in range(self.max_retries):
                try:
                    parameters = pika.URLParameters(self.rabbitmq_url)
                    parameters.heartbeat = 10  # Further reduce heartbeat timeout
                    parameters.blocked_connection_timeout = 20
                    parameters.connection_attempts = 3
                    parameters.retry_delay = 5
                    parameters.socket_timeout = 10
                    
                    self.connection = pika.BlockingConnection(parameters)
                    self.channel = self.connection.channel()
                    
                    # Declare exchange
                    self.channel.exchange_declare(
                        exchange='neighborbuy',
                        exchange_type='topic',
                        durable=True
                    )
                    
                    # Declare response queue with explicit queue name (not auto-delete)
                    self.response_queue = f'response_queue_{uuid.uuid4()}'
                    self.channel.queue_declare(queue=self.response_queue, durable=True, exclusive=True)
                    self.channel.queue_bind(
                        exchange='neighborbuy',
                        queue=self.response_queue,
                        routing_key='*.response'
                    )
                    
                    # Bind the response queue to specific routing keys
                    self.channel.queue_bind(
                        exchange='neighborbuy',
                        queue=self.response_queue,
                        routing_key=self.response_queue  # Bind to the queue name itself for direct routing
                    )
                    
                    # Declare error queue
                    self.error_queue = f'error_queue_{uuid.uuid4()}'
                    self.channel.queue_declare(queue=self.error_queue, durable=True, exclusive=True)
                    self.channel.queue_bind(
                        exchange='neighborbuy',
                        queue=self.error_queue,
                        routing_key='*.error'
                    )
                    
                    # Store responses
                    self.responses = {}
                    self.errors = {}
                    
                    # Start consuming responses and errors
                    self.channel.basic_consume(
                        queue=self.response_queue,
                        on_message_callback=self._handle_response,
                        auto_ack=True  # Auto acknowledge to ensure we don't miss messages
                    )
                    self.channel.basic_consume(
                        queue=self.error_queue,
                        on_message_callback=self._handle_error,
                        auto_ack=True  # Auto acknowledge
                    )
                    
                    logger.info(f"Successfully connected to RabbitMQ with response queue: {self.response_queue}")
                    return
                    
                except (AMQPConnectionError, AMQPChannelError, ConnectionClosedByBroker) as e:
                    if attempt == self.max_retries - 1:
                        logger.error(f"Failed to connect to RabbitMQ after {self.max_retries} attempts: {str(e)}")
                        raise
                    logger.warning(f"Connection attempt {attempt + 1} failed, retrying in {self.retry_delay} seconds...")
                    time.sleep(self.retry_delay)

    @track_message_queue_operation('connection', 'ensure_connection')
    def _ensure_connection(self):
        """Ensure connection is alive, reconnect if needed"""
        with self.connection_lock:
            try:
                if not self.connection or self.connection.is_closed:
                    logger.info("Connection is closed, attempting to reconnect...")
                    self._connect()
                elif self.channel and self.channel.is_closed:
                    logger.info("Channel is closed, attempting to reconnect...")
                    self.channel = self.connection.channel()
                    self._setup_channel()
            except Exception as e:
                logger.error(f"Error ensuring connection: {str(e)}")
                self._connect()
            
    @track_message_queue_operation('channel', 'setup')
    def _setup_channel(self):
        """Setup channel with required exchanges and queues"""
        with self.connection_lock:
            try:
                # Declare exchange
                self.channel.exchange_declare(
                    exchange='neighborbuy',
                    exchange_type='topic',
                    durable=True
                )
                
                # Declare response queue with explicit queue name (not auto-delete)
                self.response_queue = f'response_queue_{uuid.uuid4()}'
                self.channel.queue_declare(queue=self.response_queue, durable=True, exclusive=True)
                self.channel.queue_bind(
                    exchange='neighborbuy',
                    queue=self.response_queue,
                    routing_key='*.response'
                )
                
                # Bind the response queue to specific routing keys
                self.channel.queue_bind(
                    exchange='neighborbuy',
                    queue=self.response_queue,
                    routing_key=self.response_queue  # Bind to the queue name itself for direct routing
                )
                
                # Declare error queue
                self.error_queue = f'error_queue_{uuid.uuid4()}'
                self.channel.queue_declare(queue=self.error_queue, durable=True, exclusive=True)
                self.channel.queue_bind(
                    exchange='neighborbuy',
                    queue=self.error_queue,
                    routing_key='*.error'
                )
                
                # Start consuming responses and errors
                self.channel.basic_consume(
                    queue=self.response_queue,
                    on_message_callback=self._handle_response,
                    auto_ack=True  # Auto acknowledge to ensure we don't miss messages
                )
                self.channel.basic_consume(
                    queue=self.error_queue,
                    on_message_callback=self._handle_error,
                    auto_ack=True  # Auto acknowledge
                )
                
                logger.info(f"Successfully set up channel with response queue: {self.response_queue}")
            except Exception as e:
                logger.error(f"Error setting up channel: {str(e)}")
                raise
            
    @track_message_queue_operation('response', 'handle')
    def _handle_response(self, ch, method, properties, body):
        """Handle response messages"""
        try:
            # Log raw message first
            logger.info(f"Received raw response: method={method.routing_key}, properties={properties}, body_size={len(body)}")
            
            response = json.loads(body)
            logger.info(f"Decoded response body: {response}")
            
            correlation_id = properties.correlation_id
            if correlation_id:
                logger.info(f"Processing response with correlation_id: {correlation_id}")
                self.responses[correlation_id] = response
                logger.info(f"Stored response with key {correlation_id}, responses now has {len(self.responses)} items")
            else:
                logger.warning(f"Received response without correlation_id: {response}")
                
            # Always acknowledge the message
            ch.basic_ack(delivery_tag=method.delivery_tag)
            logger.info(f"Message acknowledged, delivery_tag={method.delivery_tag}")
        except Exception as e:
            logger.error(f"Error handling response: {str(e)}")
            # Still acknowledge to avoid stuck messages
            ch.basic_ack(delivery_tag=method.delivery_tag)

    @track_message_queue_operation('error', 'handle')
    def _handle_error(self, ch, method, properties, body):
        """Handle error messages"""
        try:
            # Log raw message first
            logger.info(f"Received raw error: method={method.routing_key}, properties={properties}, body_size={len(body)}")
            
            error = json.loads(body)
            logger.info(f"Decoded error body: {error}")
            
            correlation_id = properties.correlation_id
            if correlation_id:
                logger.info(f"Processing error with correlation_id: {correlation_id}")
                self.errors[correlation_id] = error
                logger.info(f"Stored error with key {correlation_id}, errors now has {len(self.errors)} items")
            else:
                logger.warning(f"Received error without correlation_id: {error}")
                
            # Always acknowledge the message
            ch.basic_ack(delivery_tag=method.delivery_tag)
            logger.info(f"Error message acknowledged, delivery_tag={method.delivery_tag}")
        except Exception as e:
            logger.error(f"Error handling error message: {str(e)}")
            # Still acknowledge to avoid stuck messages
            ch.basic_ack(delivery_tag=method.delivery_tag)

    @track_message_queue_operation('message', 'publish_and_wait')
    def publish_and_wait(self, event_type: str, data: Dict[str, Any], timeout: int = 30) -> Optional[Dict[str, Any]]:
        """
        Publish a message and wait for response
        
        Args:
            event_type: Type of event (e.g., 'user.created')
            data: Event data
            timeout: Timeout in seconds
            
        Returns:
            Response data or None if timeout/error
        """
        self._ensure_connection()
        
        correlation_id = str(uuid.uuid4())
        
        # Clear any existing responses/errors for this correlation_id
        self.responses.pop(correlation_id, None)
        self.errors.pop(correlation_id, None)
        
        # Prepare message
        message = {
            'event_type': event_type,
            'data': data
        }
        logger.info(f"Publishing message with event_type: {event_type}, correlation_id: {correlation_id}")
        
        try:
            # Publish message
            with self.connection_lock:
                self.channel.basic_publish(
                    exchange='neighborbuy',
                    routing_key=event_type,
                    body=json.dumps(message),
                    properties=pika.BasicProperties(
                        correlation_id=correlation_id,
                        delivery_mode=2,  # make message persistent
                        content_type='application/json',
                        reply_to=self.response_queue  # Add reply_to for direct routing
                    )
                )
            
            # Track in Prometheus
            MESSAGE_QUEUE_OPERATIONS.labels(
                operation='publish', 
                status='success', 
                queue=event_type
            ).inc()
            
            logger.info(f"Message published to {event_type}, waiting for response on {self.response_queue}")
            
            # Wait for response
            start_time = time.time()
            while time.time() - start_time < timeout:
                try:
                    # IMPORTANT: Process data events AND consume messages
                    # This is critical as it causes message queue to actively consume
                    # waiting messages and trigger our callback handlers
                    with self.connection_lock:
                        # Set time_limit=1 to make this call non-blocking but still process messages
                        self.connection.process_data_events(time_limit=1)
                        
                        # Do a direct get from response queue as well
                        method_frame, properties, body = self.channel.basic_get(queue=self.response_queue, auto_ack=True)
                        if method_frame and properties and properties.correlation_id == correlation_id:
                            try:
                                response = json.loads(body)
                                logger.info(f"Direct get found response for {correlation_id}: {response}")
                                return response
                            except Exception as e:
                                logger.error(f"Error parsing response from direct get: {e}")
                        
                    logger.info(f"Checking responses for {correlation_id}, current responses: {list(self.responses.keys())}")
                    
                    # Check if we've received a response via consumer callback
                    if correlation_id in self.responses:
                        response = self.responses.pop(correlation_id)
                        logger.info(f"Found response for {correlation_id}: {response}")
                        return response
                    
                    # Check if we've received an error
                    if correlation_id in self.errors:
                        error = self.errors.pop(correlation_id)
                        logger.error(f"Found error for {correlation_id}: {error}")
                        raise Exception(f"Error processing message: {error.get('error')}")
                    
                    # Short delay to prevent CPU hogging
                    time.sleep(0.1)
                    
                except (AMQPConnectionError, AMQPChannelError, ConnectionClosedByBroker, StreamLostError) as e:
                    logger.error(f"Connection error while waiting for response: {str(e)}")
                    self._ensure_connection()
                    continue
            
            # If we get here, we timed out waiting for a response
            logger.warning(f"Timeout waiting for response to {event_type}")
            
            # Track timeout in Prometheus
            MESSAGE_QUEUE_OPERATIONS.labels(
                operation='response_timeout', 
                status='error', 
                queue=event_type
            ).inc()
            
            # Last attempt - try specific direct gets
            logger.info(f"Doing a final direct get attempt for {correlation_id}")
            try:
                with self.connection_lock:
                    for i in range(5):  # Try up to 5 times
                        method_frame, properties, body = self.channel.basic_get(queue=self.response_queue, auto_ack=True)
                        if method_frame and properties and properties.correlation_id == correlation_id:
                            try:
                                response = json.loads(body)
                                logger.info(f"Final get attempt found response for {correlation_id}: {response}")
                                return response
                            except Exception as e:
                                logger.error(f"Error parsing response from final get attempt: {e}")
                        time.sleep(0.2)  # Short delay between attempts
            except Exception as e:
                logger.error(f"Error in final get attempt: {e}")
                
            raise TimeoutError(f"Timeout waiting for response to {event_type}")
            
        except Exception as e:
            logger.error(f"Error in publish_and_wait: {str(e)}")
            
            # Track error in Prometheus
            MESSAGE_QUEUE_OPERATIONS.labels(
                operation='publish_error', 
                status='error', 
                queue=event_type
            ).inc()
            
            self._ensure_connection()
            raise

    @track_message_queue_operation('message', 'publish')
    def publish(self, event_type: str, data: Dict[str, Any]):
        """Publish a message without waiting for response"""
        self._ensure_connection()
        
        message = {
            'event_type': event_type,
            'data': data
        }
        
        try:
            with self.connection_lock:
                self.channel.basic_publish(
                    exchange='neighborbuy',
                    routing_key=event_type,
                    body=json.dumps(message),
                    properties=pika.BasicProperties(
                        delivery_mode=2,  # make message persistent
                        content_type='application/json'
                    )
                )
                
            # Track in Prometheus
            MESSAGE_QUEUE_OPERATIONS.labels(
                operation='publish', 
                status='success', 
                queue=event_type
            ).inc()
        except Exception as e:
            logger.error(f"Error publishing message: {str(e)}")
            
            # Track error in Prometheus
            MESSAGE_QUEUE_OPERATIONS.labels(
                operation='publish_error', 
                status='error', 
                queue=event_type
            ).inc()
            
            self._ensure_connection()
            raise

    def close(self):
        """Close the connection"""
        try:
            # Stop heartbeat thread
            self.is_running = False
            if self.heartbeat_thread:
                self.heartbeat_thread.join(timeout=2.0)
                
            with self.connection_lock:
                if self.channel and not self.channel.is_closed:
                    self.channel.close()
                if self.connection and not self.connection.is_closed:
                    self.connection.close()
                    
            logger.info("Successfully closed RabbitMQ connection")
        except Exception as e:
            logger.error(f"Error closing connection: {str(e)}")
            
    def send_response(self, routing_key, response, correlation_id):
        """Send a response message to the specified routing key"""
        self._ensure_connection()
        
        try:
            with self.connection_lock:
                self.channel.basic_publish(
                    exchange='neighborbuy',
                    routing_key=routing_key,
                    body=json.dumps(response),
                    properties=pika.BasicProperties(
                        correlation_id=correlation_id,
                        delivery_mode=2,  # make message persistent
                        content_type='application/json'
                    )
                )
                
            # Track in Prometheus
            MESSAGE_QUEUE_OPERATIONS.labels(
                operation='response_sent', 
                status='success', 
                queue=routing_key
            ).inc()
            
        except Exception as e:
            logger.error(f"Error sending response: {str(e)}")
            
            # Track error in Prometheus
            MESSAGE_QUEUE_OPERATIONS.labels(
                operation='response_error', 
                status='error', 
                queue=routing_key
            ).inc()
            
            self._ensure_connection()
            raise