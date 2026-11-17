BEGIN;
-- Immutable agreement byte snapshots, separate from user-uploaded test PDFs.
CREATE TABLE contractor_agreement_versions (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 version_label text NOT NULL UNIQUE,
 document_sha256 char(64) NOT NULL CHECK (document_sha256 ~ '^[a-f0-9]{64}$'),
 document_pdf bytea NOT NULL CHECK (octet_length(document_pdf)>0),
 status text NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','approved','retired')),
 created_at timestamptz NOT NULL DEFAULT now(),
 approved_by uuid REFERENCES users(id),
 approved_at timestamptz,
 CONSTRAINT approved_version_requires_review CHECK (status <> 'approved' OR (approved_by IS NOT NULL AND approved_at IS NOT NULL))
);
CREATE TABLE contractor_agreement_signing_policy (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 enabled boolean NOT NULL DEFAULT false,
 updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO contractor_agreement_signing_policy(singleton,enabled) VALUES(true,false);
CREATE TABLE contractor_agreement_signatures (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 representative_id uuid NOT NULL REFERENCES users(id),
 version_id uuid NOT NULL REFERENCES contractor_agreement_versions(id),
 document_sha256 char(64) NOT NULL CHECK(document_sha256 ~ '^[a-f0-9]{64}$'),
 consent_record jsonb NOT NULL,
 signing_evidence jsonb NOT NULL,
 signed_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(representative_id,version_id)
);
CREATE OR REPLACE FUNCTION require_enabled_approved_agreement_signature()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM contractor_agreement_signing_policy WHERE singleton=true AND enabled=true)
    OR NOT EXISTS (
      SELECT 1 FROM contractor_agreement_versions v
      WHERE v.id=NEW.version_id AND v.status='approved'
        AND v.document_sha256=NEW.document_sha256
    ) THEN
    RAISE EXCEPTION 'Agreement signing is disabled or the version has not been approved'
      USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER enforce_approved_agreement_signature
BEFORE INSERT OR UPDATE ON contractor_agreement_signatures
FOR EACH ROW EXECUTE FUNCTION require_enabled_approved_agreement_signature();
-- Version snapshots are append-only: corrections must create a new version.
CREATE OR REPLACE FUNCTION protect_contractor_agreement_snapshot()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.version_label IS DISTINCT FROM OLD.version_label
   OR NEW.document_sha256 IS DISTINCT FROM OLD.document_sha256
   OR NEW.document_pdf IS DISTINCT FROM OLD.document_pdf THEN
   RAISE EXCEPTION 'Agreement version snapshots cannot be modified'
     USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER immutable_agreement_version
BEFORE UPDATE ON contractor_agreement_versions
FOR EACH ROW EXECUTE FUNCTION protect_contractor_agreement_snapshot();
COMMIT;
