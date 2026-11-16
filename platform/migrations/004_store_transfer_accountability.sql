-- Record the effective time and administrator's reason for every future store transfer.
-- Existing events are historical and retain a documented legacy reason.
BEGIN;
ALTER TABLE store_assignment_events
  ADD COLUMN IF NOT EXISTS reason text NOT NULL DEFAULT 'Legacy assignment before transfer reasons were required',
  ADD COLUMN IF NOT EXISTS effective_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE store_assignment_events
  ADD CONSTRAINT store_assignment_reason_length CHECK (length(trim(reason)) BETWEEN 5 AND 1000);
CREATE INDEX IF NOT EXISTS store_assignment_events_effective_idx
  ON store_assignment_events(store_id, effective_at DESC, id DESC);
COMMIT;
