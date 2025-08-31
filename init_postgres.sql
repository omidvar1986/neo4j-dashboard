-- Initialize PostgreSQL database for Neo4j Dashboard
-- This script runs when the PostgreSQL container starts for the first time

-- Create the database if it doesn't exist
SELECT 'CREATE DATABASE neo_dashboard'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'neo_dashboard')\gexec

-- Connect to the neo_dashboard database
\c neo_dashboard;

-- Create the user if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'neo4j_dashboard_user') THEN
        CREATE ROLE neo4j_dashboard_user WITH LOGIN PASSWORD 'Milad1986';
    END IF;
END
$$;

-- Grant privileges to the user
GRANT ALL PRIVILEGES ON DATABASE neo_dashboard TO neo4j_dashboard_user;
GRANT ALL PRIVILEGES ON SCHEMA public TO neo4j_dashboard_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO neo4j_dashboard_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO neo4j_dashboard_user;

-- Set default privileges for future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO neo4j_dashboard_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO neo4j_dashboard_user;
