BEGIN;
-- Guard every write path, including future API routes and direct SQL imports.
CREATE OR REPLACE FUNCTION require_approved_representative_assignment()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE target_rep uuid;
BEGIN
  IF TG_TABLE_NAME = 'representative_territories' THEN
    target_rep := NEW.representative_id;
  ELSE
    target_rep := NEW.primary_representative_id;
  END IF;
  IF target_rep IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM users u
    JOIN representative_onboarding o ON o.representative_id=u.id
    WHERE u.id=target_rep AND u.role='representative'
      AND u.active=true AND o.approval_status='approved'
  ) THEN
    RAISE EXCEPTION 'Representative must have approved onboarding and an active account before assignment'
      USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS enforce_approved_territory_rep ON representative_territories;
CREATE TRIGGER enforce_approved_territory_rep
BEFORE INSERT OR UPDATE OF representative_id ON representative_territories
FOR EACH ROW EXECUTE FUNCTION require_approved_representative_assignment();
DROP TRIGGER IF EXISTS enforce_approved_store_rep ON stores;
CREATE TRIGGER enforce_approved_store_rep
BEFORE INSERT OR UPDATE OF primary_representative_id ON stores
FOR EACH ROW EXECUTE FUNCTION require_approved_representative_assignment();
COMMIT;
