-- 0005: auth key for every reveal, clean cut from the verifier format
--
-- Every secret now stores auth_hash, a keyed hash of an auth key the browser
-- derives with HKDF from the fragment key and, when set, the password: the
-- application stores HMAC-SHA256(subkey, SHA-256(auth key)), with the subkey
-- derived from the deployment key, so this column is useless for guessing
-- without that key. A reveal must present the auth key before the row is
-- deleted, so a wrong password or a damaged fragment key never consumes, and
-- password guesses can only be made online through the rate limited reveal
-- endpoint. The sealed verifier that allowed offline guessing is gone.
--
-- Rows created before this migration use a content key and a password scheme
-- the new client cannot reproduce, so they could never be opened again. They are
-- closed here instead of lingering until expiry. Each one with a control link
-- gets a receipt, `expired` if it had already expired and `cancelled` otherwise,
-- so its creator sees that the link no longer works.
-- The receipt holds only the control hash, the state and timestamps, as any
-- receipt does; no ciphertext is copied anywhere.
WITH closed AS (
    DELETE FROM secrets
    RETURNING control_hash, expires_at
)
INSERT INTO secret_receipts (control_hash, state, expires_at, closed_at, purge_after)
SELECT control_hash,
       CASE WHEN expires_at <= now() THEN 'expired' ELSE 'cancelled' END,
       expires_at,
       now(),
       GREATEST(expires_at, now() + interval '7 days')
  FROM closed
 WHERE control_hash IS NOT NULL
ON CONFLICT (control_hash) DO NOTHING;

ALTER TABLE secrets
    DROP COLUMN IF EXISTS password_hash,
    DROP COLUMN IF EXISTS password_verifier,
    DROP COLUMN IF EXISTS reveal_proof_hash,
    ADD COLUMN auth_hash text NOT NULL
        CONSTRAINT secrets_auth_hash_shape CHECK (auth_hash ~ '^[0-9a-f]{64}$'),
    ADD COLUMN has_password boolean NOT NULL;
