-- +goose Up

-- A workspace is one separately tracked part of the organization, such as a
-- business unit. Everything the organization collects or decides belongs to
-- exactly one. Frameworks, check versions, users and sessions are shared.
CREATE TABLE workspaces (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    key        text        NOT NULL UNIQUE CHECK (key ~ '^[a-z][a-z0-9-]{0,31}$'),
    name       text        NOT NULL CHECK (name <> ''),
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Everything that existed before workspaces belongs to this one.
INSERT INTO workspaces (key, name) VALUES ('default', 'Default workspace');

-- Until the interface can choose a workspace, rows fall into the default
-- one. Adding a column with a constant default rewrites nothing and fires
-- no row trigger, so the insert-only tables are untouched.
ALTER TABLE resources            ADD COLUMN workspace_id bigint NOT NULL DEFAULT 1 REFERENCES workspaces (id);
ALTER TABLE collection_runs      ADD COLUMN workspace_id bigint NOT NULL DEFAULT 1 REFERENCES workspaces (id);
ALTER TABLE evidence_payloads    ADD COLUMN workspace_id bigint NOT NULL DEFAULT 1 REFERENCES workspaces (id);
ALTER TABLE observations         ADD COLUMN workspace_id bigint NOT NULL DEFAULT 1 REFERENCES workspaces (id);
ALTER TABLE evaluations          ADD COLUMN workspace_id bigint NOT NULL DEFAULT 1 REFERENCES workspaces (id);
ALTER TABLE findings             ADD COLUMN workspace_id bigint NOT NULL DEFAULT 1 REFERENCES workspaces (id);
ALTER TABLE evidence_submissions ADD COLUMN workspace_id bigint NOT NULL DEFAULT 1 REFERENCES workspaces (id);
ALTER TABLE exceptions           ADD COLUMN workspace_id bigint NOT NULL DEFAULT 1 REFERENCES workspaces (id);
ALTER TABLE remediation_notes    ADD COLUMN workspace_id bigint NOT NULL DEFAULT 1 REFERENCES workspaces (id);
ALTER TABLE decision_log         ADD COLUMN workspace_id bigint NOT NULL DEFAULT 1 REFERENCES workspaces (id);

-- The same repository or account may be tracked in two workspaces.
ALTER TABLE resources
    DROP CONSTRAINT resources_provider_kind_external_id_key,
    ADD CONSTRAINT resources_workspace_external_key UNIQUE (workspace_id, provider, kind, external_id);

-- A payload is recorded once per workspace, so one workspace cannot learn
-- from a conflict that another already holds the same bytes.
ALTER TABLE observations         DROP CONSTRAINT observations_payload_sha256_fkey;
ALTER TABLE evidence_submissions DROP CONSTRAINT evidence_submissions_payload_sha256_fkey;
ALTER TABLE evidence_payloads
    DROP CONSTRAINT evidence_payloads_pkey,
    ADD PRIMARY KEY (workspace_id, sha256);
ALTER TABLE observations
    ADD CONSTRAINT observations_payload_fkey
    FOREIGN KEY (workspace_id, payload_sha256) REFERENCES evidence_payloads (workspace_id, sha256);
ALTER TABLE evidence_submissions
    ADD CONSTRAINT evidence_submissions_payload_fkey
    FOREIGN KEY (workspace_id, payload_sha256) REFERENCES evidence_payloads (workspace_id, sha256);

CREATE INDEX findings_workspace_idx ON findings (workspace_id, id);
CREATE INDEX decision_log_workspace_idx ON decision_log (workspace_id, id);

-- +goose Down
DROP INDEX decision_log_workspace_idx;
DROP INDEX findings_workspace_idx;
ALTER TABLE evidence_submissions DROP CONSTRAINT evidence_submissions_payload_fkey;
ALTER TABLE observations         DROP CONSTRAINT observations_payload_fkey;
ALTER TABLE evidence_payloads
    DROP CONSTRAINT evidence_payloads_pkey,
    ADD PRIMARY KEY (sha256);
ALTER TABLE observations
    ADD CONSTRAINT observations_payload_sha256_fkey FOREIGN KEY (payload_sha256) REFERENCES evidence_payloads (sha256);
ALTER TABLE evidence_submissions
    ADD CONSTRAINT evidence_submissions_payload_sha256_fkey FOREIGN KEY (payload_sha256) REFERENCES evidence_payloads (sha256);
ALTER TABLE resources
    DROP CONSTRAINT resources_workspace_external_key,
    ADD CONSTRAINT resources_provider_kind_external_id_key UNIQUE (provider, kind, external_id);
ALTER TABLE decision_log         DROP COLUMN workspace_id;
ALTER TABLE remediation_notes    DROP COLUMN workspace_id;
ALTER TABLE exceptions           DROP COLUMN workspace_id;
ALTER TABLE evidence_submissions DROP COLUMN workspace_id;
ALTER TABLE findings             DROP COLUMN workspace_id;
ALTER TABLE evaluations          DROP COLUMN workspace_id;
ALTER TABLE observations         DROP COLUMN workspace_id;
ALTER TABLE evidence_payloads    DROP COLUMN workspace_id;
ALTER TABLE collection_runs      DROP COLUMN workspace_id;
ALTER TABLE resources            DROP COLUMN workspace_id;
DROP TABLE workspaces;
