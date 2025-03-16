"""
Shared Prometheus metrics for all services.
"""
import time
from prometheus_client import Counter, Histogram, Gauge, Info, start_http_server
from flask import request, Flask
from functools import wraps

# Metrics
REQUEST_COUNT = Counter(
    'http_requests_total', 
    'Total HTTP Requests Count', 
    ['method', 'endpoint', 'status']
)

REQUEST_LATENCY = Histogram(
    'http_request_duration_seconds', 
    'HTTP Request Latency', 
    ['method', 'endpoint']
)

ACTIVE_REQUESTS = Gauge(
    'http_active_requests', 
    'Active HTTP Requests',
    ['method', 'endpoint']
)

USER_ACTIVITY = Counter(
    'user_activity_total', 
    'User Activity Count', 
    ['activity_type', 'user_role']
)

MESSAGE_QUEUE_OPERATIONS = Counter(
    'message_queue_operations_total', 
    'Message Queue Operations', 
    ['operation', 'status', 'queue']
)

MESSAGE_PROCESSING_TIME = Histogram(
    'message_processing_seconds', 
    'Message Processing Time', 
    ['event_type']
)

DB_QUERY_TIME = Histogram(
    'db_query_seconds', 
    'Database Query Time', 
    ['operation', 'table']
)

ERROR_COUNT = Counter(
    'error_total', 
    'Total Errors', 
    ['service', 'endpoint', 'error_type']
)

SERVICE_INFO = Info('service', 'Service Information')

def init_metrics(app_name, app_version="1.0.0", port=8000):
    """Initialize the metrics server on the specified port."""
    SERVICE_INFO.info({
        'name': app_name,
        'version': app_version
    })
    start_http_server(port)

def track_requests(app: Flask):
    """
    Track request metrics for a Flask app.
    
    Usage:
    track_requests(app)  # Call this after creating your Flask app
    """
    @app.before_request
    def before_request():
        request.start_time = time.time()
        endpoint = request.endpoint or 'unknown'
        method = request.method
        
        ACTIVE_REQUESTS.labels(method=method, endpoint=endpoint).inc()
    
    @app.after_request
    def after_request(response):
        endpoint = request.endpoint or 'unknown'
        method = request.method
        status = response.status_code
        
        # Record request count
        REQUEST_COUNT.labels(method=method, endpoint=endpoint, status=status).inc()
        
        # Record latency
        latency = time.time() - request.start_time
        REQUEST_LATENCY.labels(method=method, endpoint=endpoint).observe(latency)
        
        # Decrement active requests
        ACTIVE_REQUESTS.labels(method=method, endpoint=endpoint).dec()
        
        return response
    
    @app.errorhandler(Exception)
    def handle_exception(e):
        endpoint = request.endpoint or 'unknown'
        ERROR_COUNT.labels(service=app.name, endpoint=endpoint, error_type=type(e).__name__).inc()
        # Re-raise the exception to let Flask handle it
        raise e

def track_user_activity(activity_type, user_role="unknown"):
    """Track user activity"""
    USER_ACTIVITY.labels(activity_type=activity_type, user_role=user_role).inc()

def track_db_operation(operation_func):
    """Decorator to track database operation time"""
    @wraps(operation_func)
    def wrapper(*args, **kwargs):
        table = kwargs.get('table', 'unknown')
        operation = operation_func.__name__
        
        start_time = time.time()
        try:
            result = operation_func(*args, **kwargs)
            DB_QUERY_TIME.labels(operation=operation, table=table).observe(time.time() - start_time)
            return result
        except Exception as e:
            ERROR_COUNT.labels(service="database", endpoint=operation, error_type=type(e).__name__).inc()
            raise
        
    return wrapper

def track_message_queue_operation(queue_name, operation):
    """Track message queue operations"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                MESSAGE_QUEUE_OPERATIONS.labels(
                    operation=operation, 
                    status="success", 
                    queue=queue_name
                ).inc()
                
                # For specific operations, track processing time
                if operation in ['process', 'consume']:
                    event_type = kwargs.get('event_type', 'unknown')
                    MESSAGE_PROCESSING_TIME.labels(event_type=event_type).observe(time.time() - start_time)
                
                return result
            except Exception as e:
                MESSAGE_QUEUE_OPERATIONS.labels(
                    operation=operation, 
                    status="error", 
                    queue=queue_name
                ).inc()
                raise
        return wrapper
    return decorator 