-- Capture store login credentials at original onboarding submission.
-- Accounts remain inactive until admin approval. Legacy approved stores are unchanged.
BEGIN;
ALTER TABLE store_onboarding_applications
 ADD COLUMN pending_store_user_id uuid UNIQUE REFERENCES users(id) ON DELETE RESTRICT;
CREATE INDEX store_onboarding_pending_user_idx ON store_onboarding_applications(pending_store_user_id)
 WHERE pending_store_user_id IS NOT NULL;
COMMIT;
