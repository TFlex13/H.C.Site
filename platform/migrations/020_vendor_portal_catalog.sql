-- Vendor accounts and product catalog proposals, additive migration.
BEGIN;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
ALTER TABLE users ADD CONSTRAINT users_role_check CHECK(role IN ('admin','representative','vendor'));
CREATE TABLE vendor_memberships(
 user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE RESTRICT,
 vendor_id uuid NOT NULL REFERENCES vendors(id) ON DELETE RESTRICT,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX vendor_memberships_vendor_idx ON vendor_memberships(vendor_id);
CREATE TABLE vendor_invitations(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 vendor_id uuid NOT NULL REFERENCES vendors(id) ON DELETE RESTRICT,
 email text NOT NULL,
 token_hash text NOT NULL UNIQUE,
 invited_by uuid REFERENCES users(id) ON DELETE SET NULL,
 expires_at timestamptz NOT NULL,
 accepted_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(),
 CONSTRAINT vendor_invitation_email_length CHECK(length(email) BETWEEN 3 AND 254)
);
CREATE INDEX vendor_invitation_vendor_idx ON vendor_invitations(vendor_id,created_at DESC);
CREATE TABLE vendor_products(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 vendor_id uuid NOT NULL REFERENCES vendors(id) ON DELETE RESTRICT,
 sku text NOT NULL,
 name text NOT NULL,
 description text,
 category text,
 unit_label text NOT NULL DEFAULT 'each',
 active boolean NOT NULL DEFAULT false,
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(vendor_id,sku),
 CHECK(length(trim(sku)) BETWEEN 1 AND 80),
 CHECK(length(trim(name)) BETWEEN 1 AND 200)
);
CREATE TABLE vendor_product_offers(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 product_id uuid NOT NULL REFERENCES vendor_products(id) ON DELETE RESTRICT,
 vendor_id uuid NOT NULL REFERENCES vendors(id) ON DELETE RESTRICT,
 wholesale_price numeric(14,4) NOT NULL CHECK(wholesale_price>=0),
 vendor_unit_cost numeric(14,4) NOT NULL CHECK(vendor_unit_cost>=0 AND vendor_unit_cost<=wholesale_price),
 proposed_service_fee_percent numeric(7,4) NOT NULL CHECK(proposed_service_fee_percent BETWEEN 0 AND 100),
 status text NOT NULL DEFAULT 'pending_review' CHECK(status IN ('pending_review','approved','rejected','superseded')),
 submitted_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 submitted_at timestamptz NOT NULL DEFAULT now(),
 reviewed_by uuid REFERENCES users(id),
 reviewed_at timestamptz,
 review_reason text,
 CHECK(wholesale_price <= 9999999999)
);
CREATE UNIQUE INDEX vendor_offer_one_pending ON vendor_product_offers(product_id) WHERE status='pending_review';
CREATE INDEX vendor_offer_vendor_idx ON vendor_product_offers(vendor_id,submitted_at DESC);
CREATE TABLE vendor_catalog_audit(
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 vendor_id uuid NOT NULL REFERENCES vendors(id) ON DELETE RESTRICT,
 product_id uuid REFERENCES vendor_products(id) ON DELETE RESTRICT,
 offer_id uuid REFERENCES vendor_product_offers(id) ON DELETE RESTRICT,
 actor_id uuid REFERENCES users(id) ON DELETE SET NULL,
 action text NOT NULL,
 detail text,
 occurred_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX vendor_catalog_audit_vendor_idx ON vendor_catalog_audit(vendor_id,occurred_at DESC);
COMMIT;
