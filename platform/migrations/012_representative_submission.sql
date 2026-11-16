BEGIN;
ALTER TABLE representative_onboarding ADD COLUMN submitted_at timestamptz;
CREATE TABLE representative_onboarding_submissions (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 representative_id uuid NOT NULL REFERENCES users(id),
 submitted_at timestamptz NOT NULL DEFAULT now(),
 identity_status text NOT NULL,
 tax_status text NOT NULL,
 agreement_status text NOT NULL
);
CREATE INDEX representative_onboarding_submissions_rep_idx ON representative_onboarding_submissions(representative_id,submitted_at DESC);
COMMIT;
