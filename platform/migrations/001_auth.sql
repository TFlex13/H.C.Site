BEGIN;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE IF NOT EXISTS users (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 email text NOT NULL UNIQUE,
 password_hash text NOT NULL,
 display_name text NOT NULL,
 role text NOT NULL CHECK (role IN ('admin','representative')),
 active boolean NOT NULL DEFAULT true,
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(),
 CONSTRAINT email_normalized CHECK (email = lower(trim(email)))
);
CREATE TABLE IF NOT EXISTS invitations (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 email text NOT NULL,
 role text NOT NULL DEFAULT 'representative' CHECK (role = 'representative'),
 token_hash text NOT NULL UNIQUE,
 invited_by uuid NOT NULL REFERENCES users(id),
 expires_at timestamptz NOT NULL,
 accepted_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS invitations_email_idx ON invitations(email);
CREATE TABLE IF NOT EXISTS sessions (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 token_hash text NOT NULL UNIQUE,
 expires_at timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id);
CREATE TABLE IF NOT EXISTS auth_audit_events (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 actor_id uuid REFERENCES users(id) ON DELETE SET NULL,
 action text NOT NULL,
 subject_email text,
 created_at timestamptz NOT NULL DEFAULT now()
);
COMMIT;
