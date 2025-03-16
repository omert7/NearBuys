"""
Configuration settings for the message processor.
"""
import os
import logging
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# RabbitMQ settings
RABBITMQ_URL = os.getenv('RABBITMQ_URL', 'amqp://guest:guest@rabbitmq:5672/')

# Database settings
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://postgres:password@postgres-db:5432/neighborbuy')

# Exchange settings
EXCHANGE_NAME = 'neighborbuy'
EXCHANGE_TYPE = 'topic'

# Queue definitions
QUEUE_DEFINITIONS = {
    'user_events': ['user.*', '*.user.*'],
    'product_events': ['product.*', '*.product.*'],
    'seller_events': ['seller.*', '*.seller.*'],
    'group_buy_events': ['group_buy.*', '*.group_buy.*'],
    'bid_events': ['bid.*', '*.bid.*']
} 