-- 0002: control link and close receipts
--
-- Every secret gets a second, independent 256-bit token whose only SHA-256 hash
-- is stored here. It never reveals content and never consumes the secret: it only
-- reports whether the row is still pending and can cancel it.
--
-- Rows created before this migration have no control hash; the column is
-- therefore nullable and the unique index treats NULLs as distinct.
ALTER TABLE secrets
    ADD COLUMN IF NOT EXISTS control_hash text;

CREATE UNIQUE INDEX IF NOT EXISTS secrets_control_hash_idx ON secrets (control_hash);

-- A receipt is what a control link shows once the row is gone. It carries no
-- ciphertext and no token, only the state the secret ended in and when it closed,
-- so it can never be used to reconstruct anything. Receipts outlive the row by
-- seven days past closing, and no longer than that unless the row was set to
-- expire later.
CREATE TABLE IF NOT EXISTS secret_receipts (
    control_hash text        PRIMARY KEY,
    state        text        NOT NULL,
    expires_at   timestamptz NOT NULL,
    closed_at    timestamptz NOT NULL,
    purge_after  timestamptz NOT NULL,
    CONSTRAINT secret_receipts_state CHECK (state IN ('read', 'expired', 'cancelled'))
);

-- Supports the periodic purge of receipts past their retention.
CREATE INDEX IF NOT EXISTS secret_receipts_purge_idx ON secret_receipts (purge_after);
