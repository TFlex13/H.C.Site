-- Approval is an accounting decision, not proof of vendor payment or a payout.
BEGIN;
CREATE TABLE commission_order_decisions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  order_id uuid NOT NULL REFERENCES commission_orders(id) ON DELETE RESTRICT,
  previous_status text NOT NULL CHECK (previous_status = 'pending'),
  new_status text NOT NULL CHECK (new_status IN ('approved','voided')),
  decided_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  reason text NOT NULL CHECK (length(trim(reason)) BETWEEN 5 AND 1000),
  decided_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT commission_order_one_decision UNIQUE(order_id)
);
CREATE OR REPLACE FUNCTION guard_commission_order_decision_history()
RETURNS trigger LANGUAGE plpgsql AS $decision_guard$
BEGIN
  RAISE EXCEPTION 'Commission decision history is immutable';
END;
$decision_guard$;
CREATE TRIGGER commission_decision_history_immutable_guard
BEFORE UPDATE OR DELETE ON commission_order_decisions
FOR EACH ROW EXECUTE FUNCTION guard_commission_order_decision_history();
CREATE INDEX commission_order_decisions_actor_idx ON commission_order_decisions(decided_by,decided_at DESC);
CREATE OR REPLACE FUNCTION guard_commission_order_snapshot()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  decision_actor uuid;
  decision_reason text;
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'Commission orders cannot be deleted';
  END IF;
  IF (to_jsonb(NEW) - 'status') IS DISTINCT FROM (to_jsonb(OLD) - 'status') THEN
    RAISE EXCEPTION 'Commission order financial snapshot is immutable';
  END IF;
  IF NEW.status = OLD.status THEN RETURN NEW; END IF;
  IF OLD.status <> 'pending' OR NEW.status NOT IN ('approved','voided') THEN
    RAISE EXCEPTION 'Only pending orders can be approved or voided';
  END IF;
  decision_actor := nullif(current_setting('highline.decision_actor',true),'')::uuid;
  decision_reason := nullif(current_setting('highline.decision_reason',true),'');
  IF decision_actor IS NULL OR decision_reason IS NULL OR length(trim(decision_reason)) NOT BETWEEN 5 AND 1000 THEN
    RAISE EXCEPTION 'Commission decision requires actor and reason';
  END IF;
  INSERT INTO commission_order_decisions(order_id,previous_status,new_status,decided_by,reason)
  VALUES(OLD.id,OLD.status,NEW.status,decision_actor,trim(decision_reason));
  RETURN NEW;
END;
$$;
COMMIT;
