-- Highline Connect store registry and assignment history.
-- Additive migration; order and commission attribution will be modeled separately.
BEGIN;

CREATE TABLE IF NOT EXISTS stores (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  address_line1 text NOT NULL,
  address_line2 text,
  city text NOT NULL,
  state_region text NOT NULL,
  postal_code text NOT NULL,
  country_code char(2) NOT NULL DEFAULT 'US',
  contact_name text,
  contact_email text,
  contact_phone text,
  notes text,
  territory_id uuid REFERENCES territories(id) ON DELETE RESTRICT,
  primary_representative_id uuid REFERENCES users(id) ON DELETE RESTRICT,
  active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT store_name_length CHECK (length(trim(name)) BETWEEN 1 AND 200),
  CONSTRAINT store_address_length CHECK (length(trim(address_line1)) BETWEEN 1 AND 250),
  CONSTRAINT store_city_length CHECK (length(trim(city)) BETWEEN 1 AND 120),
  CONSTRAINT store_region_length CHECK (length(trim(state_region)) BETWEEN 1 AND 120),
  CONSTRAINT store_postal_length CHECK (length(trim(postal_code)) BETWEEN 1 AND 30),
  CONSTRAINT store_contact_email_length CHECK (contact_email IS NULL OR length(contact_email) <= 254),
  CONSTRAINT store_notes_length CHECK (notes IS NULL OR length(notes) <= 2000),
  CONSTRAINT store_representative_requires_territory CHECK (primary_representative_id IS NULL OR territory_id IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS stores_territory_idx ON stores(territory_id);
CREATE INDEX IF NOT EXISTS stores_representative_idx ON stores(primary_representative_id);

CREATE TABLE IF NOT EXISTS store_assignment_events (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  store_id uuid NOT NULL REFERENCES stores(id) ON DELETE RESTRICT,
  previous_territory_id uuid REFERENCES territories(id) ON DELETE SET NULL,
  new_territory_id uuid REFERENCES territories(id) ON DELETE SET NULL,
  previous_representative_id uuid REFERENCES users(id) ON DELETE SET NULL,
  new_representative_id uuid REFERENCES users(id) ON DELETE SET NULL,
  changed_by uuid REFERENCES users(id) ON DELETE SET NULL,
  changed_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT store_assignment_changed CHECK (
    previous_territory_id IS DISTINCT FROM new_territory_id OR
    previous_representative_id IS DISTINCT FROM new_representative_id
  )
);
CREATE INDEX IF NOT EXISTS store_assignment_events_store_idx
  ON store_assignment_events(store_id, changed_at DESC, id DESC);

-- Enforce that a store's primary representative is active and assigned to its territory.
-- The application will lock assignment rows while making changes.
CREATE OR REPLACE FUNCTION validate_store_primary_assignment()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.primary_representative_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM users u
    JOIN representative_territories rt ON rt.representative_id = u.id
    JOIN territories t ON t.id = rt.territory_id
    WHERE u.id = NEW.primary_representative_id
      AND rt.territory_id = NEW.territory_id
      AND u.role = 'representative' AND u.active = true AND t.active = true
  ) THEN
    RAISE EXCEPTION 'Store representative must be active and assigned to its territory';
  END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS store_primary_assignment_guard ON stores;
CREATE TRIGGER store_primary_assignment_guard
BEFORE INSERT OR UPDATE OF primary_representative_id, territory_id ON stores
FOR EACH ROW EXECUTE FUNCTION validate_store_primary_assignment();

COMMIT;
