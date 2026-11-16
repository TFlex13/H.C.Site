BEGIN;
CREATE TABLE representative_document_access_audit (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 representative_id uuid NOT NULL REFERENCES users(id),
 document_type text NOT NULL CHECK (document_type IN ('id_front','id_back','w9')),
 document_id uuid NOT NULL,
 administrator_id uuid NOT NULL REFERENCES users(id),
 action text NOT NULL CHECK (action IN ('view','verified','rejected')),
 reason text,
 occurred_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX representative_document_access_audit_rep_idx ON representative_document_access_audit(representative_id,occurred_at DESC);
COMMIT;
