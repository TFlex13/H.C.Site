-- One full representative payout per reconciled order. No automatic transfers.
BEGIN;
CREATE TABLE commission_representative_payouts (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 order_id uuid NOT NULL UNIQUE REFERENCES commission_orders(id) ON DELETE RESTRICT,
 vendor_receipt_id uuid NOT NULL UNIQUE REFERENCES commission_vendor_receipts(id) ON DELETE RESTRICT,
 representative_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 payment_reference text NOT NULL CHECK(length(trim(payment_reference)) BETWEEN 1 AND 200),
 amount numeric(16,4) NOT NULL CHECK(amount > 0),
 currency_code char(3) NOT NULL DEFAULT 'USD' CHECK(currency_code='USD'),
 paid_on date NOT NULL,
 recorded_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 recorded_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX commission_representative_payouts_rep_idx ON commission_representative_payouts(representative_id,paid_on DESC);
CREATE OR REPLACE FUNCTION guard_commission_representative_payout()
RETURNS trigger LANGUAGE plpgsql AS $payout_guard$
DECLARE
 order_row commission_orders%ROWTYPE;
 receipt_row commission_vendor_receipts%ROWTYPE;
BEGIN
 IF TG_OP <> 'INSERT' THEN
   RAISE EXCEPTION 'Representative payout records are immutable';
 END IF;
 SELECT * INTO order_row FROM commission_orders WHERE id=NEW.order_id FOR UPDATE;
 IF NOT FOUND OR order_row.status <> 'approved' OR order_row.representative_amount <= 0 THEN
   RAISE EXCEPTION 'Payout requires an approved order with positive representative earnings';
 END IF;
 SELECT * INTO receipt_row FROM commission_vendor_receipts WHERE id=NEW.vendor_receipt_id AND order_id=NEW.order_id;
 IF NOT FOUND THEN RAISE EXCEPTION 'Payout requires a matching vendor receipt'; END IF;
 IF NEW.representative_id <> order_row.representative_id
   OR NEW.amount <> order_row.representative_amount
   OR NEW.currency_code <> order_row.currency_code THEN
   RAISE EXCEPTION 'Payout must match the historical representative commission';
 END IF;
 RETURN NEW;
END;
$payout_guard$;
CREATE TRIGGER commission_representative_payout_guard
BEFORE INSERT OR UPDATE OR DELETE ON commission_representative_payouts
FOR EACH ROW EXECUTE FUNCTION guard_commission_representative_payout();
COMMIT;
