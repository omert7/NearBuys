CREATE TABLE categories (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    category_id INTEGER REFERENCES categories(id),
    base_price DECIMAL(10,2),
    image_url TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER NOT NULL
);

CREATE TABLE group_buys (
    id SERIAL PRIMARY KEY,
    product_id INTEGER REFERENCES products(id),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    min_participants INTEGER DEFAULT 1,
    max_participants INTEGER,
    current_participants INTEGER DEFAULT 0,
    price_per_unit DECIMAL(10,2),
    status VARCHAR(50) DEFAULT 'active',
    start_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    end_date TIMESTAMP,
    created_by INTEGER NOT NULL,
    location_lat DECIMAL(10,8),
    location_lng DECIMAL(11,8),
    location_radius INTEGER DEFAULT 5000,
    accepts_seller_bids BOOLEAN DEFAULT TRUE,
    bidding_status VARCHAR(50) DEFAULT 'open',
    winning_bid_id INTEGER NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE group_buy_participants (
    id SERIAL PRIMARY KEY,
    group_buy_id INTEGER REFERENCES group_buys(id),
    user_id INTEGER NOT NULL,
    join_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    quantity INTEGER DEFAULT 1,
    status VARCHAR(50) DEFAULT 'active'
);