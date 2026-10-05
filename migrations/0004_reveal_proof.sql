-- Existing links retain their original verifier format until they expire.
ALTER TABLE secrets ADD COLUMN IF NOT EXISTS reveal_proof_hash text
    CHECK (reveal_proof_hash IS NULL OR reveal_proof_hash ~ '^[0-9a-f]{64}$');
