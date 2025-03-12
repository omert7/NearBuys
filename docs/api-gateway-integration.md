# Integrating User Service with API Gateway

This guide documents how the User Service integrates with the API Gateway in the NeighborBuy microservices architecture.

## API Gateway Configuration Updates

### 1. Service Registry

Add the User Service to the API Gateway's service registry:

```python
SERVICE_REGISTRY = {
    'auth': os.getenv('AUTH_SERVICE_URL', 'http://localhost:5001'),
    'products': os.getenv('PRODUCTS_SERVICE_URL', 'http://localhost:5002'),
    'users': os.getenv('USERS_SERVICE_URL', 'http://localhost:5003'),  # User Service
    'orders': os.getenv('ORDERS_SERVICE_URL', 'http://localhost:5004'),
    'search': os.getenv('SEARCH_SERVICE_URL', 'http://localhost:5005'),
    'notifications': os.getenv('NOTIFICATIONS_SERVICE_URL', 'http://localhost:5006'),
}
```

### 2. Public Routes

Update the public routes to include User Service's authentication endpoints:

```python
PUBLIC_ROUTES = [
    '/auth/login',
    '/auth/register',
    '/products/browse',
    '/products/search',
    '/users/login',              # User login endpoint
    '/users/register',           # User registration endpoint
    '/users/oauth/login',        # OAuth login initiation
    '/users/oauth/callback',     # OAuth callback
    '/users/reactivate',         # Account reactivation
]
```

## Environment Configuration

Update the API Gateway's `.env` file to include the User Service URL:

```
USERS_SERVICE_URL=http://localhost:5003
```

In production or with Docker Compose, this would be:

```
USERS_SERVICE_URL=http://user-service:5003
```

## Authentication Flow

### Standard Authentication

1. Client sends credentials to `/users/login`
2. API Gateway forwards request to User Service
3. User Service validates credentials and returns JWT token
4. API Gateway returns token to client
5. Client includes token in subsequent requests
6. API Gateway validates token before forwarding requests to services

### Social Authentication

1. Client initiates OAuth flow via `/users/oauth/login/google`
2. API Gateway forwards to User Service which redirects to Google
3. After authentication, Google redirects to `/users/oauth/callback/google`
4. API Gateway forwards callback to User Service
5. User Service processes OAuth data and returns JWT token
6. API Gateway forwards token to client

## Route Mapping

The API Gateway uses the first segment of the path to determine which service should handle the request:

| URL Pattern | Service |
|-------------|---------|
| `/users/*` | User Service |
| `/auth/*` | Auth Service |
| `/products/*` | Product Service |
| etc. | ... |

## User Context Propagation

When the API Gateway authenticates a request, it extracts user information from the JWT token and forwards it to the appropriate service in the request headers:

```
X-User-ID: user-uuid
X-User-Role: buyer/seller/admin
```

Services can then use these headers to determine the authenticated user and their permissions.

## Example Client Usage

### Registration

```http
POST /users/register HTTP/1.1
Host: api.neighborbuy.com
Content-Type: application/json

{
  "email": "john@example.com",
  "password": "SecureP@ssw0rd",
  "first_name": "John",
  "last_name": "Doe",
  "phone": "555-123-4567"
}
```

### Login

```http
POST /users/login HTTP/1.1
Host: api.neighborbuy.com
Content-Type: application/json

{
  "email": "john@example.com",
  "password": "SecureP@ssw0rd"
}
```

### Authenticated Request

```http
GET /users/me HTTP/1.1
Host: api.neighborbuy.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

## Monitoring and Health Checks

The API Gateway performs health checks on all services, including the User Service. This is crucial for implementing circuit breakers and handling service unavailability gracefully.

Health check endpoint: `/users/health`

## Deployment Architecture

In the Docker Compose configuration, the API Gateway and User Service are deployed as separate containers that communicate over a Docker network:

```
api-gateway <--> user-service <--> postgres-db
```

This setup provides isolation between services while enabling efficient network communication within the containerized environment.

## Security Considerations

1. **JWT Secret Sharing**: Both the API Gateway and User Service need access to the same JWT secret key for token validation. This should be carefully managed in your deployment strategy.

2. **HTTPS Termination**: The API Gateway should handle HTTPS termination, meaning all internal service communication can happen over HTTP within the secure network.

3. **Rate Limiting**: The API Gateway implements rate limiting to protect the User Service from potential abuse or DoS attacks.

4. **Input Validation**: Both the API Gateway and User Service validate inputs to prevent injection attacks and other security issues.

## Testing the Integration

Use the following commands to test that the API Gateway is correctly routing requests to the User Service:

```bash
# Health check
curl http://localhost:5000/users/health

# Register a new user
curl -X POST http://localhost:5000/users/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"Test@123!","first_name":"Test","last_name":"User"}'

# Login
curl -X POST http://localhost:5000/users/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"Test@123!"}'
```

If everything is working correctly, you should receive appropriate responses from the User Service via the API Gateway.