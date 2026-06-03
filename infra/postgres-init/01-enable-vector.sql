-- Enable pgvector for Letta's archival/vector memory.
-- Runs automatically on FIRST initialization of the Postgres data volume
-- (files in /docker-entrypoint-initdb.d/ are executed once, at db creation).
CREATE EXTENSION IF NOT EXISTS vector;
