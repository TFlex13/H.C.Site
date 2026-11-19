-- Store account activation and representative/store catalog order requests.
-- Requests do not create commission ledger entries, take payment, or authorize fulfillment.
BEGIN;
ALTER TABLE users DROP CONSTRAINT users_role_check;
ALTER TABLE users ADD CONSTRAINT users_role_check CHECK(role IN ('admin','representative','vendor','store'));
CREATE TABLE store_memberships(
 user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE RESTRICT,
 store_id uuid NOT NULL REFERENCES stores(id) ON DELETE RESTRICT,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX store_memberships_store_idx ON store_memberships(store_id);
CREATE TABLE store_account_invitations(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 store_id uuid NOT NULL REFERENCES stores(id) ON DELETE RESTRICT,
 email text NOT NULL,
 token_hash text NOT NULL UNIQUE,
 invited_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 expires_at timestamptz NOT NULL,
 accepted_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(),
 CHECK(length(email) BETWEEN 3 AND 254)
);
CREATE INDEX store_account_invites_store_idx ON store_account_invitations(store_id,created_at DESC);
CREATE TABLE catalog_order_requests(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 store_id uuid NOT NULL REFERENCES stores(id) ON DELETE RESTRICT,
 representative_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 requested_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 requested_by_role text NOT NULL CHECK(requested_by_role IN ('representative','store')),
 status text NOT NULL DEFAULT 'submitted' CHECK(status IN ('submitted','cancelled','reviewed')),
 currency_code char(3) NOT NULL DEFAULT 'USD' CHECK(currency_code='USD'),
 total_wholesale numeric(16,4) NOT NULL CHECK(total_wholesale>=0),
 requested_at timestamptz NOT NULL DEFAULT now(),
 reviewed_by uuid REFERENCES users(id),
 reviewed_at timestamptz,
 CHECK(total_wholesale<=999999999999)
);
CREATE INDEX catalog_order_requests_store_idx ON catalog_order_requests(store_id,requested_at DESC);
CREATE INDEX catalog_order_requests_rep_idx ON catalog_order_requests(representative_id,requested_at DESC);
CREATE TABLE catalog_order_request_items(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 request_id uuid NOT NULL REFERENCES catalog_order_requests(id) ON DELETE RESTRICT,
 product_id uuid NOT NULL REFERENCES vendor_products(id) ON DELETE RESTRICT,
 offer_id uuid NOT NULL REFERENCES vendor_product_offers(id) ON DELETE RESTRICT,
 vendor_id uuid NOT NULL REFERENCES vendors(id) ON DELETE RESTRICT,
 sku text NOT NULL,
 product_name text NOT NULL,
 quantity integer NOT NULL CHECK(quantity BETWEEN 1 AND 10000),
 unit_wholesale_price numeric(14,4) NOT NULL CHECK(unit_wholesale_price>=0),
 extended_wholesale numeric(16,4) NOT NULL CHECK(extended_wholesale=unit_wholesale_price*quantity),
 UNIQUE(request_id,product_id)
);
CREATE INDEX catalog_order_request_items_request_idx ON catalog_order_request_items(request_id);
COMMIT;