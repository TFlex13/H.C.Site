-- A receipt confirms the full vendor service fee for one approved order.
-- Partial receipts, adjustments and payouts are deliberately separate future workflows.
BEGIN;
CREATE TABLE commission_vendor_receipts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  order_id uuid NOT NULL UNIQUE REFERENCES commission_orders(id) ON DELETE RESTRICT,
  vendor_id uuid NOT NULL REFERENCES vendors(id) ON DELETE RESTRICT,
  payment_reference text NOT NULL CHECK (length(trim(payment_reference)) BETWEEN 1 AND 200),
  amount numeric(16,4) NOT NULL CHECK (amount > 0),
  currency_code char(3) NOT NULL DEFAULT 'USD' CHECK (currency_code = 'USD'),
  received_on date NOT NULL,
  recorded_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  recorded_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(vendor_id,payment_reference,order_id)
);
CREATE INDEX commission_vendor_receipts_vendor_idx ON commission_vendor_receipts(vendor_id,received_on DESC);
CREATE OR REPLACE FUNCTION guard_commission_vendor_receipt()
RETURNS trigger LANGUAGE plpgsql AS $receipt_guard$
DECLARE
  order_row commission_orders%ROWTYPE;
BEGIN
  IF TG_OP <> 'INSERT' THEN
    RAISE EXCEPTION 'Vendor receipts are immutable; use a future correction workflow';
  END IF;
  SELECT * INTO order_row FROM commission_orders WHERE id=NEW.order_id FOR UPDATE;
  IF NOT FOUND OR order_row.status <> 'approved' THEN
    RAISE EXCEPTION 'Vendor receipt requires an approved order';
  END IF;
  IF NEW.vendor_id <> order_row.vendor_id OR NEW.amount <> order_row.service_fee_amount
     OR NEW.currency_code <> order_row.currency_code THEN
    RAISE EXCEPTION 'Vendor receipt must match the approved order fee and vendor';
  END IF;
  RETURN NEW;
END;
$receipt_guard$;
CREATE TRIGGER commission_vendor_receipt_guard
BEFORE INSERT OR UPDATE OR DELETE ON commission_vendor_receipts
FOR EACH ROW EXECUTE FUNCTION guard_commission_vendor_receipt();
COMMIT;
