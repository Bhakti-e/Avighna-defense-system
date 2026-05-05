-- AVIGHNA PostgreSQL Database Setup
-- Run this after PostgreSQL installation

-- Create database
CREATE DATABASE avighna_defense;

-- Connect to the database
\c avighna_defense;

-- Create extension for UUID support (optional but useful)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE avighna_defense TO postgres;

-- Verify connection
SELECT version();
