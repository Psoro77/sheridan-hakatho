-- Additive schema: never alters the ML export tables or other applications.
CREATE SCHEMA IF NOT EXISTS breachlight_app;
CREATE TABLE IF NOT EXISTS breachlight_app.vulnerabilities (
 cve_id text PRIMARY KEY,
 model_rank integer NOT NULL CHECK (model_rank BETWEEN 1 AND 500),
 snapshot_month text NOT NULL,
 record jsonb NOT NULL,
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS breachlight_rank_idx ON breachlight_app.vulnerabilities(model_rank);
CREATE TABLE IF NOT EXISTS breachlight_app.snapshot_months (
 month text PRIMARY KEY,
 total integer NOT NULL,
 selected integer NOT NULL
);
CREATE TABLE IF NOT EXISTS breachlight_app.metadata (key text PRIMARY KEY, value jsonb NOT NULL);
CREATE TABLE IF NOT EXISTS breachlight_app.workspaces (
 workspace_id text PRIMARY KEY,
 state jsonb NOT NULL,
 revision integer NOT NULL DEFAULT 1,
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS breachlight_app.briefings (
 evidence_hash text PRIMARY KEY,
 cve_id text NOT NULL REFERENCES breachlight_app.vulnerabilities(cve_id),
 model text NOT NULL,
 response jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
-- Tickets filed in GitHub or Jira from the defense plan and defense paths (one per item and provider).
CREATE TABLE IF NOT EXISTS breachlight_app.tickets (
 workspace_id text NOT NULL,
 ticket_key text NOT NULL,
 provider text NOT NULL,
 external_key text NOT NULL,
 url text NOT NULL,
 title text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (workspace_id, ticket_key, provider)
);
CREATE TABLE IF NOT EXISTS breachlight_app.events (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 workspace_id text NOT NULL,
 event_type text NOT NULL,
 details jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
