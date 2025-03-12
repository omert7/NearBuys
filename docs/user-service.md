# NeighborBuy User Service

A comprehensive user management microservice for the NeighborBuy platform. This service handles user registration, authentication, profile management, address verification, and reputation tracking.

## Features

- **User Management**
  - Registration and authentication
  - Social login with OAuth (Google, Facebook)
  - Password management
  - Account activation/deactivation

- **Profile Management**
  - User preferences
  - Privacy settings
  - Bio and personal information

- **Address Management**
  - Multiple addresses per user
  - Primary address designation
  - Address verification

- **Reputation System**
  - User ratings and reviews
  - Rating aggregation and statistics

- **Role-Based Access Control**
  - Different user roles (buyer, seller, admin)
  - Permission management

## API Endpoints

### Authentication

- `POST /register` - Register a new user
- `POST /login` - Authenticate user and get token
- `GET /oauth/login/<provider>` - Initiate OAuth login
- `GET /oauth/callback/<provider>` - Handle OAuth callback
- `POST /reactivate` - Reactivate a deactivated account

### User Profile

- `GET /me` - Get current user profile
- `PUT /me` - Update current user profile
- `PUT /me/password` - Change password
- `GET /users/<user_id>` - Get public user profile
- `POST /deactivate` - Deactivate account

### Ratings

- `GET /users/<user_id>/ratings` - Get ratings for a user
- `POST /users/<user_id>/ratings` - Rate a user

### Addresses

- `GET /addresses` - Get all addresses for current user
- `POST /addresses` - Add a new address
- `PUT /addresses/<address_id>` - Update an address
- `DELETE /addresses/<address_id>` - Delete an address
- `POST /verify-address/<address_id>` - Initiate address verification

### Preferences and Privacy

- `GET /preferences` - Get user preferences
- `PUT /preferences` - Update user preferences
- `GET /privacy-settings` - Get privacy settings
- `PUT /privacy-settings` - Update privacy settings

### Admin

- `GET /admin/users` - List all users
- `GET /admin/users/<user_id>` - Get detailed user info
- `PUT /admin/users/<user_id>` - Update user
- `POST /admin/verify-address/<address_id>` - Manually verify address

## Getting Started

### Prerequisites

- Python 3.8+
- PostgreSQL 12+
- pip (Python package manager)

### Installation

1. Clone this repository
```bash
git clone https://github.com/yourusername/neighborbuy-user-service.git
cd neighborbuy-user-service
```

2. Create a virtual environment and activate it
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install the required packages
```bash
pip install -r requirements.txt
```

4. Create a `.env` file with your configuration (see `.env.example`)

5. Set up the PostgreSQL database
```bash
# Create database
createdb neighborbuy_users

# Initialize schema (using provided SQL file)
psql -d neighborbuy_users -f schema.sql
```

6. Run the user service
```bash
python app.py
```

### Docker Deployment

1. Build the Docker image
```bash
docker build -t neighborbuy-user-service .
```

2. Run the container
```bash
docker run -p 5003:5003 --env-file .env neighborbuy-user-service
```

Alternatively, use Docker Compose to run the service with PostgreSQL:
```bash
docker-compose up -d
```

## Authentication Flow

### Standard Login

1. User submits email and password to `/login`
2. Service validates credentials and returns JWT token
3. Token is included in subsequent API requests as Bearer token

### OAuth Login

1. Frontend redirects user to `/oauth/login/<provider>`
2. User authenticates with OAuth provider
3. Provider redirects back to `/oauth/callback/<provider>`
4. Service verifies OAuth credentials and returns JWT token

## Data Models

### User

- id: UUID (Primary Key)
- email: String (Unique)
- password_hash: String (Nullable for OAuth users)
- first_name: String
- last_name: String
- phone: String (Optional)
- role: String (buyer, seller, admin)
- oauth_provider: String (google, facebook, etc.)
- oauth_id: String
- created_at: DateTime
- updated_at: DateTime
- last_login: DateTime
- is_active: Boolean
- is_email_verified: Boolean
- avatar_url: String

### Profile

- id: UUID (Primary Key)
- user_id: UUID (Foreign Key)
- bio: Text
- preferences: JSONB
- privacy_settings: JSONB
- created_at: DateTime
- updated_at: DateTime

### Address

- id: UUID (Primary Key)
- user_id: UUID (Foreign Key)
- street: String
- city: String
- state: String
- zip_code: String
- country: String
- is_primary: Boolean
- lat: Float (Optional)
- lng: Float (Optional)
- is_verified: Boolean
- created_at: DateTime
- updated_at: DateTime

### Rating

- id: UUID (Primary Key)
- from_user_id: UUID (Foreign Key)
- to_user_id: UUID (Foreign Key)
- rating: Integer (1-5)
- review: Text (Optional)
- transaction_id: UUID (Optional)
- created_at: DateTime
- updated_at: DateTime

## Configuration

The user service is configured using environment variables:

- `PORT`: The port the service will listen on (default: 5003)
- `DEBUG`: Enable debug mode (default: False)
- `DATABASE_URL`: PostgreSQL connection string
- `JWT_SECRET_KEY`: Secret key for JWT generation/validation
- `JWT_ACCESS_TOKEN_EXPIRES`: Token expiration time in seconds
- OAuth provider settings:
  - `GOOGLE_CLIENT_ID`
  - `GOOGLE_CLIENT_SECRET`
  - `FACEBOOK_CLIENT_ID`
  - `FACEBOOK_CLIENT_SECRET`

## Security Considerations

- All passwords are stored as hashes (not plain text)
- JWT tokens expire after a configurable time
- Role-based access controls protect admin endpoints
- Input validation on all endpoints
- Rate limiting is handled at the API Gateway level
- Privacy settings control what information is shared
- Address verification helps prevent fraud

## Integration with API Gateway

The user service integrates with the NeighborBuy API Gateway, which routes requests to the appropriate service based on the URL path. All user-related requests with a path prefix of `/users/` will be routed to this service.

## License

This project is licensed under the MIT License - see the LICENSE file for details.