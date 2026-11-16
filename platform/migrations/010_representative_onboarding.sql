BEGIN;
-- Onboarding is independent of login activation. Existing representatives remain
-- pending until reviewed; no identity images, SSNs, or bank details live here.
CREATE TABLE representative_onboarding (
  representative_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  legal_first_name text,
  legal_last_name text,
  mobile_phone text,
  alternate_phone text,
  address_line1 text,
  address_line2 text,
  city text,
  state_region text,
  postal_code text,
  country_code char(2) NOT NULL DEFAULT 'US',
  preferred_contact_method text CHECK (preferred_contact_method IN ('email','mobile','phone')),
  tax_document_status text NOT NULL DEFAULT 'not_submitted'
    CHECK (tax_document_status IN ('not_submitted','pending_review','verified','rejected')),
  identity_document_status text NOT NULL DEFAULT 'not_submitted'
    CHECK (identity_document_status IN ('not_submitted','pending_review','verified','rejected')),
  contractor_agreement_status text NOT NULL DEFAULT 'not_submitted'
    CHECK (contractor_agreement_status IN ('not_submitted','pending_review','verified','rejected')),
  approval_status text NOT NULL DEFAULT 'pending'
    CHECK (approval_status IN ('pending','approved','rejected','suspended')),
  reviewed_by uuid REFERENCES users(id) ON DELETE SET NULL,
  reviewed_at timestamptz,
  review_notes text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT approval_requires_verified_documents CHECK (
    approval_status <> 'approved' OR
    (tax_document_status='verified' AND identity_document_status='verified'
     AND contractor_agreement_status='verified'
     AND legal_first_name IS NOT NULL AND legal_last_name IS NOT NULL
     AND mobile_phone IS NOT NULL AND address_line1 IS NOT NULL
     AND city IS NOT NULL AND state_region IS NOT NULL AND postal_code IS NOT NULL
     AND reviewed_by IS NOT NULL AND reviewed_at IS NOT NULL)
  )
);
INSERT INTO representative_onboarding(representative_id)
SELECT id FROM users WHERE role='representative'
ON CONFLICT DO NOTHING;
CREATE OR REPLACE FUNCTION initialize_representative_onboarding() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.role='representative' THEN
    INSERT INTO representative_onboarding(representative_id) VALUES(NEW.id);
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER initialize_representative_onboarding_after_insert
AFTER INSERT ON users FOR EACH ROW
EXECUTE FUNCTION initialize_representative_onboarding();
CREATE TABLE representative_onboarding_reviews (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  representative_id uuid NOT NULL REFERENCES users(id),
  reviewed_by uuid NOT NULL REFERENCES users(id),
  old_status text NOT NULL,
  new_status text NOT NULL,
  reason text,
  created_at timestamptz NOT NULL DEFAULT now()
);
COMMIT;
