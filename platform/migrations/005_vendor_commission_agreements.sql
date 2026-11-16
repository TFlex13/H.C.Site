-- Vendor-funded service fees: one negotiated vendor rate, allocated internally.
-- Percentages are percentage points of the same vendor gross-profit base.
-- Orders and earned commissions will snapshot these terms in a later migration.
BEGIN;
CREATE TABLE vendors (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE,
  active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT vendor_name_length CHECK (length(trim(name)) BETWEEN 1 AND 200)
);
CREATE TABLE vendor_commission_agreements (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  vendor_id uuid NOT NULL REFERENCES vendors(id) ON DELETE RESTRICT,
  service_fee_percent numeric(7,4) NOT NULL,
  highline_percent numeric(7,4) NOT NULL,
  representative_percent numeric(7,4) NOT NULL,
  effective_from timestamptz NOT NULL DEFAULT now(),
  effective_until timestamptz,
  created_by uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT valid_commission_percentages CHECK (
    service_fee_percent BETWEEN 0 AND 100
    AND highline_percent BETWEEN 0 AND 100
    AND representative_percent BETWEEN 0 AND 100
    AND highline_percent + representative_percent = service_fee_percent
  ),
  CONSTRAINT valid_agreement_period CHECK (effective_until IS NULL OR effective_until > effective_from)
);
-- Prevent ambiguous overlapping agreements for the same vendor.
CREATE EXTENSION IF NOT EXISTS btree_gist;
ALTER TABLE vendor_commission_agreements
  ADD CONSTRAINT vendor_commission_agreement_no_overlap
  EXCLUDE USING gist (
    vendor_id WITH =,
    tstzrange(effective_from, effective_until, '[)') WITH &&
  );
CREATE INDEX vendor_commission_agreements_vendor_idx
  ON vendor_commission_agreements(vendor_id, effective_from DESC);
COMMIT;
