-- Create schemas for each service
CREATE SCHEMA IF NOT EXISTS users;
CREATE SCHEMA IF NOT EXISTS products;
CREATE SCHEMA IF NOT EXISTS sellers;

-- Users schema
CREATE TABLE users.users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE users.profiles (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users.users(id),
    avatar_url TEXT,
    bio TEXT,
    location_sharing BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE users.addresses (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users.users(id),
    address_line1 VARCHAR(255) NOT NULL,
    address_line2 VARCHAR(255),
    city VARCHAR(100) NOT NULL,
    state VARCHAR(100),
    postal_code VARCHAR(20) NOT NULL,
    country VARCHAR(100) NOT NULL,
    is_default BOOLEAN DEFAULT FALSE,
    latitude DECIMAL(10,8),
    longitude DECIMAL(11,8),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE users.ratings (
    id SERIAL PRIMARY KEY,
    rater_id INTEGER REFERENCES users.users(id),
    rated_id INTEGER REFERENCES users.users(id),
    rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
    comment TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (rater_id, rated_id)
);

-- Products schema
CREATE TABLE products.categories (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE products.products (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    category_id INTEGER REFERENCES products.categories(id),
    base_price DECIMAL(10,2),
    image_url TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER NOT NULL REFERENCES users.users(id)
);

CREATE TABLE products.group_buys (
    id SERIAL PRIMARY KEY,
    product_id INTEGER REFERENCES products.products(id),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    min_participants INTEGER DEFAULT 1,
    max_participants INTEGER,
    current_participants INTEGER DEFAULT 0,
    price_per_unit DECIMAL(10,2),
    status VARCHAR(50) DEFAULT 'active',
    start_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    end_date TIMESTAMP,
    created_by INTEGER NOT NULL REFERENCES users.users(id),
    location_lat DECIMAL(10,8),
    location_lng DECIMAL(11,8),
    location_radius INTEGER DEFAULT 5000,
    accepts_seller_bids BOOLEAN DEFAULT TRUE,
    bidding_status VARCHAR(50) DEFAULT 'open',
    winning_bid_id INTEGER NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE products.group_buy_participants (
    id SERIAL PRIMARY KEY,
    group_buy_id INTEGER REFERENCES products.group_buys(id),
    user_id INTEGER NOT NULL REFERENCES users.users(id),
    join_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    quantity INTEGER DEFAULT 1,
    status VARCHAR(50) DEFAULT 'active'
);

-- Sellers schema
CREATE TABLE sellers.sellers (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL UNIQUE REFERENCES users.users(id),
    business_name VARCHAR(255) NOT NULL,
    business_description TEXT,
    verification_status VARCHAR(50) DEFAULT 'pending',
    creation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    contact_email VARCHAR(255),
    contact_phone VARCHAR(50),
    website VARCHAR(255),
    tax_id VARCHAR(100),
    is_active BOOLEAN DEFAULT TRUE
);

CREATE TABLE sellers.bids (
    id SERIAL PRIMARY KEY,
    seller_id INTEGER NOT NULL REFERENCES sellers.sellers(id),
    group_buy_id INTEGER NOT NULL REFERENCES products.group_buys(id),
    price DECIMAL(10,2) NOT NULL,
    description TEXT,
    terms TEXT,
    status VARCHAR(50) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expiration_date TIMESTAMP,
    is_winning_bid BOOLEAN DEFAULT FALSE
);

CREATE TABLE sellers.seller_ratings (
    id SERIAL PRIMARY KEY,
    seller_id INTEGER NOT NULL REFERENCES sellers.sellers(id),
    user_id INTEGER NOT NULL REFERENCES users.users(id),
    rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
    comment TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (seller_id, user_id)
);

-- Insert default categories
INSERT INTO products.categories (name, description) VALUES
    ('Electronics', 'Electronic devices and gadgets'),
    ('Home & Garden', 'Products for home and garden'),
    ('Groceries', 'Food and household supplies'),
    ('Clothing', 'Apparel and accessories'),
    ('Sports & Outdoors', 'Sporting goods and outdoor equipment');