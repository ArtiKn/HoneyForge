-- Postgres bootstrap: role, database, grants (task 1.3).
-- Runs once on first cluster init; idempotent. The role password comes from
-- POSTGRES_PASSWORD (see .env), not from this file.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'honeyforge') THEN
    CREATE ROLE honeyforge LOGIN;
  END IF;
END
$$;

SELECT 'CREATE DATABASE honeyforge OWNER honeyforge'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'honeyforge')
\gexec

GRANT ALL PRIVILEGES ON DATABASE honeyforge TO honeyforge;

\connect honeyforge

ALTER SCHEMA public OWNER TO honeyforge;
GRANT ALL ON SCHEMA public TO honeyforge;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO honeyforge;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO honeyforge;

CREATE EXTENSION IF NOT EXISTS pgcrypto;
