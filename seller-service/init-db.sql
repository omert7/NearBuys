CREATE TABLE sellers (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL UNIQUE,
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

CREATE TABLE bids (
    id SERIAL PRIMARY KEY,
    seller_id INTEGER NOT NULL,
    group_buy_id INTEGER NOT NULL,
    price DECIMAL(10,2) NOT NULL,
    description TEXT,
    terms TEXT,
    status VARCHAR(50) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expiration_date TIMESTAMP,
    is_winning_bid BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (seller_id) REFERENCES sellers(id)
);

CREATE TABLE seller_ratings (
    id SERIAL PRIMARY KEY,
    seller_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
    comment TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (seller_id) REFERENCES sellers(id),
    UNIQUE (seller_id, user_id)
);