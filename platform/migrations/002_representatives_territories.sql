-- Highline Connect representative profiles and territory assignments.
-- Additive migration; existing users and authentication data remain unchanged.
BEGIN;

CREATE TABLE IF NOT EXISTS representative_profiles (
  user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  phone text,
  company_name text,
  notes text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT representative_profile_phone_length CHECK (phone IS NULL OR length(phone) <= 40),
  CONSTRAINT representative_profile_company_length CHECK (company_name IS NULL OR length(company_name) <= 160),
  CONSTRAINT representative_profile_notes_length CHECK (notes IS NULL OR length(notes) <= 2000)
);

CREATE TABLE IF NOT EXISTS territories (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE,
  description text,
  active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT territory_name_length CHECK (length(trim(name)) BETWEEN 1 AND 120),
  CONSTRAINT territory_description_length CHECK (description IS NULL OR length(description) <= 1000)
);

CREATE TABLE IF NOT EXISTS representative_territories (
  representative_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  territory_id uuid NOT NULL REFERENCES territories(id) ON DELETE RESTRICT,
  assigned_by uuid REFERENCES users(id) ON DELETE SET NULL,
  assigned_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (representative_id, territory_id)
);
CREATE INDEX IF NOT EXISTS representative_territories_territory_idx
  ON representative_territories(territory_id);

-- Prevent assigning administrator accounts to sales territories.
CREATE OR REPLACE FUNCTION enforce_representative_territory_role()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM users WHERE id = NEW.representative_id AND role = 'representative'
  ) THEN
    RAISE EXCEPTION 'Territory assignments require a representative account';
  END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS representative_territory_role_guard ON representative_territories;
CREATE TRIGGER representative_territory_role_guard
BEFORE INSERT OR UPDATE OF representative_id ON representative_territories
FOR EACH ROW EXECUTE FUNCTION enforce_representative_territory_role();

COMMIT;
