-- Persist store coordinates so map loads never repeatedly geocode addresses.
BEGIN;
ALTER TABLE stores ADD COLUMN IF NOT EXISTS latitude double precision;
ALTER TABLE stores ADD COLUMN IF NOT EXISTS longitude double precision;
ALTER TABLE stores ADD CONSTRAINT stores_valid_coordinates CHECK (
 (latitude IS NULL AND longitude IS NULL) OR
 (latitude BETWEEN -90 AND 90 AND longitude BETWEEN -180 AND 180)
);
COMMIT;
