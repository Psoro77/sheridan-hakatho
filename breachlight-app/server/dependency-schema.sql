CREATE TABLE IF NOT EXISTS breachlight_app.dependency_scans (
 id uuid PRIMARY KEY,
 workspace_id text NOT NULL,
 report jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS breachlight_dependency_scan_latest ON breachlight_app.dependency_scans(workspace_id,created_at DESC);
CREATE TABLE IF NOT EXISTS breachlight_app.dependency_briefings (
 evidence_hash text PRIMARY KEY,
 scan_id uuid NOT NULL REFERENCES breachlight_app.dependency_scans(id),
 package_key text NOT NULL,
 response jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
