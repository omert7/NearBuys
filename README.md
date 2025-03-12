# NeighborBuy

NeighborBuy is a neighborhood-based group buying platform that enables users to discover, join, and create group buying opportunities to increase purchasing power and get better deals.

## Overview

This application is built using a hybrid microservices architecture with the following components:

- **API Gateway**: Routes requests to appropriate microservices
- **User Service**: Manages user accounts, authentication, and profiles
- **Product Service**: Handles products, categories, and group buys
- **Seller Service**: Manages seller accounts and bidding
- **Message Queue (RabbitMQ)**: Facilitates event-based communication between services
- **Database (PostgreSQL)**: Single database with separate schemas for each service domain

## Features

- User registration and authentication
- Create and join group buying opportunities
- Seller registration and profile management
- Bidding system for sellers to compete for group buys
- Rating system for users and sellers
- Location-based group buy discovery

## Architecture

The application uses a hybrid architecture that combines microservices with a shared database approach:

1. **Microservices with Clear Boundaries**: Each service has its own codebase and functionality
2. **Consolidated Database with Schema Separation**: Single PostgreSQL database with separate schemas for each service domain
3. **Message Queue for Event Communication**: Services communicate through RabbitMQ events
4. **Shared Utilities**: Common code is shared via a mounted directory

## Prerequisites

- Docker and Docker Compose
- Git

## Installation and Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/neighborbuy.git
   cd neighborbuy
   ```

2. Create the shared directory structure:
   ```bash
   mkdir -p shared/utils
   touch shared/utils/__init__.py
   ```

3. Create the message queue utility:
   ```bash
   # Add the message_queue.py to shared/utils/
   # (Copy the message queue implementation to this file)
   ```

4. Set up environment variables for each service in their respective .env files

5. Build and start the services:
   ```bash
   docker-compose build
   docker-compose up -d
   ```

## Running the Application

Start all services:

```bash
docker-compose up -d
```

Check service status:

```bash
docker-compose ps
```

View logs:

```bash
# All logs
docker-compose logs

# Specific service logs
docker-compose logs api-gateway
docker-compose logs user-service
docker-compose logs product-service
docker-compose logs seller-service
```

Stop the application:

```bash
docker-compose down
```

## API Endpoints

### User Service

- `POST /users/register` - Register a new user
- `POST /users/login` - Authenticate and get a token
- `GET /users/me` - Get current user profile
- `PUT /users/me` - Update user profile
- `GET /users/<user_id>` - Get a user's public profile

### Product Service

- `GET /products` - List all products
- `POST /products` - Create a new product
- `GET /products/<id>` - Get product details
- `GET /products/search` - Search products
- `GET /products/categories` - List product categories
- `POST /products/group-buys` - Create a new group buy
- `GET /products/group-buys` - List group buys
- `POST /products/group-buys/<id>/join` - Join a group buy
- `GET /products/group-buys/<id>/bids` - Get bids for a group buy
- `POST /products/group-buys/<id>/select-bid` - Select winning bid

### Seller Service

- `POST /sellers` - Register as a seller
- `GET /sellers/me` - Get seller profile
- `PUT /sellers/me` - Update seller profile
- `POST /bid` - Submit a bid on a group buy
- `GET /bids` - Get seller's bids
- `PUT /bids/<bid_id>` - Update a bid
- `GET /sellers/<id>/ratings` - Get seller ratings
- `POST /sellers/<id>/rate` - Rate a seller
- `GET /sellers/dashboard` - Get seller dashboard data

## Database Schema

The database is organized into three schemas:

1. **users schema**:
   - users - User accounts and authentication
   - profiles - User profile information
   - addresses - User addresses
   - ratings - User-to-user ratings

2. **products schema**:
   - categories - Product categories
   - products - Product listings
   - group_buys - Group buying opportunities
   - group_buy_participants - Users participating in group buys

3. **sellers schema**:
   - sellers - Seller profiles
   - bids - Bids on group buys
   - seller_ratings - Ratings for sellers

## Message Queue

The application uses RabbitMQ for event-based communication between services:

- **Exchange**: `neighborbuy` (topic exchange)
- **Queues**:
  - `user_events` - Events related to users
  - `product_events` - Events related to products and group buys
  - `seller_events` - Events related to sellers and bids

**Key Events**:
- `user.created` - New user registration
- `product.group_buy.created` - New group buy created
- `seller.bid.created` - New bid submitted
- `product.bid.selected` - Winning bid selected

## Testing the Application

### 1. Register a User
```bash
curl -X POST http://localhost:5000/users/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "password123",
    "full_name": "Test User"
  }'
```

### 2. Login
```bash
curl -X POST http://localhost:5000/users/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "password123"
  }'
```

### 3. Create a product
```bash
curl -X POST http://localhost:5000/products/products \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -d '{
    "name": "Wireless Earbuds",
    "description": "High-quality wireless earbuds with noise cancellation",
    "category_id": 1,
    "base_price": 79.99,
    "image_url": "https://example.com/earbuds.jpg"
  }'
```

### 4. Create a Group Buy
```bash
curl -X POST http://localhost:5000/products/group-buys \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -d '{
    "product_id": 1,
    "name": "Wireless Earbuds Group Buy",
    "description": "Let's buy these earbuds together to get a discount!",
    "min_participants": 5,
    "max_participants": 20,
    "price_per_unit": 59.99,
    "end_date": "2023-12-31T23:59:59",
    "location": {
      "lat": 37.7749,
      "lng": -122.4194,
      "radius": 10000
    },
    "accepts_seller_bids": true
  }'
```

## Troubleshooting

### Database Connectivity Issues
- Check connection strings in `.env` files
- Ensure database container is running with `docker-compose ps`
- Inspect database logs with `docker-compose logs postgres-db`

### Service Communication Issues
- Verify service URLs in `.env` files use container names, not localhost
- Check network configuration in `docker-compose.yml`
- Test service-to-service communication with health endpoints

### RabbitMQ Issues
- Check if RabbitMQ is running: `docker-compose ps rabbitmq`
- View RabbitMQ logs: `docker-compose logs rabbitmq`
- Access the RabbitMQ management console at http://localhost:15672/
- Test connectivity from a service: `docker-compose exec user-service python -c "import pika; pika.BlockingConnection(pika.ConnectionParameters('rabbitmq'))"`

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Hat tip to anyone whose code was used
- Inspiration
- etc.
