-- A representative's store portfolio is the default territory for stores they originate.
-- This is an ownership grouping, not a claim to exclusive geographic boundaries.
BEGIN;
CREATE TABLE representative_store_portfolios (
 representative_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE RESTRICT,
 territory_id uuid NOT NULL UNIQUE REFERENCES territories(id) ON DELETE RESTRICT,
 created_at timestamptz NOT NULL DEFAULT now()
);
COMMIT;
