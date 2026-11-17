-- Store onboarding invitations, applications and encrypted compliance documents.
-- Apply only after migrations 001-016. Does not change existing stores or representative records.
BEGIN;
CREATE TABLE store_onboarding_invites (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 representative_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 store_email text NOT NULL CHECK (length(store_email) BETWEEN 3 AND 254),
 token_hash text NOT NULL UNIQUE,
 expires_at timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 revoked_at timestamptz
);
CREATE INDEX store_onboarding_invites_rep_idx ON store_onboarding_invites(representative_id,created_at DESC);
CREATE TABLE store_onboarding_applications (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 invite_id uuid NOT NULL UNIQUE REFERENCES store_onboarding_invites(id) ON DELETE RESTRICT,
 legal_business_name text NOT NULL,
 doing_business_as text,
 contact_name text NOT NULL,
 contact_phone text NOT NULL,
 address_line1 text NOT NULL,
 address_line2 text,
 city text NOT NULL,
 state_region text NOT NULL,
 postal_code text NOT NULL,
 ein_ciphertext bytea,
 ein_last4 char(4),
 status text NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','submitted','changes_requested','approved','rejected')),
 submitted_at timestamptz,
 reviewed_at timestamptz,
 reviewed_by uuid REFERENCES users(id),
 review_reason text,
 approved_store_id uuid UNIQUE REFERENCES stores(id),
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX store_onboarding_applications_status_idx ON store_onboarding_applications(status,submitted_at DESC);
CREATE TABLE store_onboarding_documents (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 application_id uuid NOT NULL REFERENCES store_onboarding_applications(id) ON DELETE CASCADE,
 document_type text NOT NULL CHECK(document_type IN ('ein_letter','business_license','tobacco_license','other_license')),
 label text NOT NULL,
 expiration_date date,
 filename text NOT NULL,
 mime_type text NOT NULL CHECK(mime_type IN ('application/pdf','image/jpeg','image/png')),
 byte_size int NOT NULL CHECK(byte_size BETWEEN 1 AND 10485760),
 storage_key text NOT NULL UNIQUE,
 review_status text NOT NULL DEFAULT 'pending_review' CHECK(review_status IN ('pending_review','verified','rejected')),
 rejection_reason text,
 submitted_at timestamptz NOT NULL DEFAULT now(),
 reviewed_by uuid REFERENCES users(id),
 reviewed_at timestamptz
);
CREATE INDEX store_onboarding_documents_app_idx ON store_onboarding_documents(application_id,submitted_at DESC);
CREATE TABLE store_onboarding_audit (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 application_id uuid NOT NULL REFERENCES store_onboarding_applications(id) ON DELETE RESTRICT,
 document_id uuid REFERENCES store_onboarding_documents(id) ON DELETE SET NULL,
 actor_id uuid REFERENCES users(id),
 action text NOT NULL,
 reason text,
 occurred_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX store_onboarding_audit_app_idx ON store_onboarding_audit(application_id,occurred_at DESC);
COMMIT;
