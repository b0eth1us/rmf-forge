-- RMF Forge initial schema
-- SQLAlchemy also creates these via Base.metadata.create_all,
-- but this init script ensures the DB is ready before the app starts.

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
