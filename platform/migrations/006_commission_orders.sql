-- Order ledger foundation. No orders are automatically payable at ingestion.
-- Financial amounts are immutable snapshots; corrections require future reversal entries.
BEGIN;
CREATE TABLE commission_orders (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  external_order_reference text NOT NULL,
  vendor_id uuid NOT NULL REFERENCES vendors(id) ON DELETE RESTRICT,
  store_id uuid NOT NULL REFERENCES stores(id) ON DELETE RESTRICT,
  representative_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  agreement_id uuid NOT NULL REFERENCES vendor_commission_agreements(id) ON DELETE RESTRICT,
  currency_code char(3) NOT NULL DEFAULT 'USD',
  quantity integer NOT NULL,
  unit_wholesale_price numeric(14,4) NOT NULL,
  unit_vendor_cost numeric(14,4) NOT NULL,
  gross_profit numeric(16,4) NOT NULL,
  service_fee_percent numeric(7,4) NOT NULL,
  highline_percent numeric(7,4) NOT NULL,
  representative_percent numeric(7,4) NOT NULL,
  service_fee_amount numeric(16,4) NOT NULL,
  highline_amount numeric(16,4) NOT NULL,
  representative_amount numeric(16,4) NOT NULL,
  status text NOT NULL DEFAULT 'pending',
  recorded_by uuid REFERENCES users(id) ON DELETE SET NULL,
  recorded_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT commission_order_reference_length CHECK (length(trim(external_order_reference)) BETWEEN 1 AND 200),
  CONSTRAINT commission_order_unique_vendor_reference UNIQUE(vendor_id,external_order_reference),
  CONSTRAINT commission_order_quantity CHECK (quantity > 0),
  CONSTRAINT commission_order_prices CHECK (unit_wholesale_price >= 0 AND unit_vendor_cost >= 0 AND unit_wholesale_price >= unit_vendor_cost),
  CONSTRAINT commission_order_profit CHECK (gross_profit = (unit_wholesale_price - unit_vendor_cost) * quantity),
  CONSTRAINT commission_order_split CHECK (
    service_fee_percent BETWEEN 0 AND 100 AND highline_percent BETWEEN 0 AND 100
    AND representative_percent BETWEEN 0 AND 100
    AND highline_percent + representative_percent = service_fee_percent
  ),
  CONSTRAINT commission_order_amounts CHECK (
    service_fee_amount >= 0 AND highline_amount >= 0 AND representative_amount >= 0
    AND highline_amount + representative_amount = service_fee_amount
  ),
  CONSTRAINT commission_order_status CHECK (status IN ('pending','approved','voided')),
  CONSTRAINT commission_order_currency CHECK (currency_code = 'USD')
);
CREATE INDEX commission_orders_store_idx ON commission_orders(store_id,recorded_at DESC);
CREATE INDEX commission_orders_representative_idx ON commission_orders(representative_id,recorded_at DESC);
CREATE INDEX commission_orders_vendor_idx ON commission_orders(vendor_id,recorded_at DESC);
-- Guard immutable financial snapshots and attribution, including against direct SQL updates.
CREATE OR REPLACE FUNCTION guard_commission_order_snapshot()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'Commission orders cannot be deleted; use a reversal workflow';
  END IF;
  IF (to_jsonb(NEW) - 'status') IS DISTINCT FROM (to_jsonb(OLD) - 'status') THEN
    RAISE EXCEPTION 'Commission order financial snapshot is immutable';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER commission_order_immutable_guard
BEFORE UPDATE OR DELETE ON commission_orders
FOR EACH ROW EXECUTE FUNCTION guard_commission_order_snapshot();
COMMIT;
