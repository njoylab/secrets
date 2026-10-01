-- 0003: client-side password verifier
--
-- New secrets mix an optional password into the content key in the browser.
-- The password never reaches the server. What is stored is a short sealed
-- check, wrapped again with the deployment key, so a wrong password can be
-- rejected before the secret row is deleted.
--
-- password_hash stays for rows created before this migration. Those still
-- gate reveal with scrypt. New rows leave it null.

ALTER TABLE secrets
    ADD COLUMN IF NOT EXISTS password_verifier text;
