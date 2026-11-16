BEGIN;
CREATE TABLE representative_documents (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 representative_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 document_type text NOT NULL CHECK (document_type IN ('id_front','id_back','w9')),
 original_filename text NOT NULL,
 mime_type text NOT NULL,
 byte_size integer NOT NULL CHECK (byte_size > 0 AND byte_size <= 10485760),
 storage_key text NOT NULL UNIQUE,
 submitted_at timestamptz NOT NULL DEFAULT now(),
 reviewed_at timestamptz,
 reviewed_by uuid REFERENCES users(id),
 review_status text NOT NULL DEFAULT 'pending_review' CHECK (review_status IN ('pending_review','verified','rejected')),
 UNIQUE (representative_id,document_type)
);
CREATE INDEX representative_documents_rep_idx ON representative_documents(representative_id);
COMMIT;
