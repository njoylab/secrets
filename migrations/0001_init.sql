-- 0001: initial schema
--
-- Secrets are stored as AES-256-GCM payloads sealed with a key that lives
-- outside the database. Only the SHA-256 hash of the bearer token is indexed;
-- the token itself is never persisted. Expiry is always evaluated against the
-- database clock so that consumption cannot be influenced by client time.

CREATE TABLE IF NOT EXISTS secrets (
    token_hash    text        PRIMARY KEY,
    ciphertext    text        NOT NULL,
    password_hash text,
    expires_at    timestamptz NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);

-- Supports the periodic cleanup of expired rows.
CREATE INDEX IF NOT EXISTS secrets_expires_at_idx ON secrets (expires_at);

-- Fixed-window rate limit counters shared across all application instances.
CREATE TABLE IF NOT EXISTS rate_limits (
    bucket            text        NOT NULL,
    subject           text        NOT NULL,
    window_started_at timestamptz NOT NULL,
    hits              integer     NOT NULL,
    CONSTRAINT rate_limits_pkey PRIMARY KEY (bucket, subject),
    CONSTRAINT rate_limits_hits_positive CHECK (hits >= 0)
);

-- Supports the periodic cleanup of idle counters.
CREATE INDEX IF NOT EXISTS rate_limits_window_idx ON rate_limits (window_started_at);