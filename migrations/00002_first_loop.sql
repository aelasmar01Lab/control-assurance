-- +goose Up

-- Something a check can be about, such as one GitHub repository.
CREATE TABLE resources (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    provider     text        NOT NULL CHECK (provider <> ''),
    kind         text        NOT NULL CHECK (kind <> ''),
    external_id  text        NOT NULL CHECK (external_id <> ''),
    scope        text        NOT NULL CHECK (scope IN ('in_scope', 'out_of_scope')),
    scope_reason text        NOT NULL DEFAULT '',
    decided_by   text        NOT NULL CHECK (decided_by <> ''),
    created_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (provider, kind, external_id),
    -- Out of scope requires a reason.
    CHECK (scope = 'in_scope' OR scope_reason <> '')
);

-- One row per collection attempt, including failures. A failed run carries an
-- error class and never produces an observation.
CREATE TABLE collection_runs (
    id                 bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    integration        text        NOT NULL CHECK (integration <> ''),
    resource_id        bigint      NOT NULL REFERENCES resources (id),
    started_at         timestamptz NOT NULL,
    finished_at        timestamptz,
    outcome            text        NOT NULL CHECK (outcome IN ('running', 'succeeded', 'failed')),
    error_class        text        NOT NULL DEFAULT '',
    error_detail       text        NOT NULL DEFAULT '',
    -- True only when every page of the source listing was read.
    inventory_complete boolean     NOT NULL DEFAULT false,
    CHECK ((outcome = 'failed') = (error_class <> '')),
    CHECK ((outcome = 'running') = (finished_at IS NULL)),
    CHECK (outcome = 'succeeded' OR NOT inventory_complete)
);
CREATE INDEX collection_runs_resource_idx ON collection_runs (resource_id, started_at DESC);

-- Evidence bytes live in the content-addressed store; this row points at them.
CREATE TABLE evidence_payloads (
    sha256      text        PRIMARY KEY CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    size_bytes  bigint      NOT NULL CHECK (size_bytes >= 0),
    media_type  text        NOT NULL CHECK (media_type <> ''),
    storage_ref text        NOT NULL CHECK (storage_ref <> ''),
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- What a successful run saw. Many observations may share one payload.
CREATE TABLE observations (
    id                 bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_id             bigint      NOT NULL REFERENCES collection_runs (id),
    resource_id        bigint      NOT NULL REFERENCES resources (id),
    kind               text        NOT NULL CHECK (kind <> ''),
    collected_at       timestamptz NOT NULL,
    source_timestamp   timestamptz,
    payload_sha256     text        NOT NULL REFERENCES evidence_payloads (sha256),
    normalizer_version text        NOT NULL CHECK (normalizer_version <> '')
);
CREATE INDEX observations_resource_idx ON observations (resource_id, kind, collected_at DESC);

-- The check definitions that have produced evaluations. Changing a check's
-- logic or wording means a new version, never an edit.
CREATE TABLE check_versions (
    key                text NOT NULL CHECK (key <> ''),
    version            text NOT NULL CHECK (version <> ''),
    observation_kind   text NOT NULL CHECK (observation_kind <> ''),
    assertion          text NOT NULL CHECK (assertion <> ''),
    establishes        text NOT NULL CHECK (establishes <> ''),
    does_not_establish text NOT NULL CHECK (does_not_establish <> ''),
    PRIMARY KEY (key, version)
);

-- One check version applied to one observation. This is the only link between
-- what was seen and what was decided.
CREATE TABLE evaluations (
    id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    observation_id bigint      NOT NULL REFERENCES observations (id),
    check_key      text        NOT NULL,
    check_version  text        NOT NULL,
    result         text        NOT NULL CHECK (result IN ('pass', 'fail', 'not_evaluated')),
    explanation    text        NOT NULL CHECK (explanation <> ''),
    evaluated_at   timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (check_key, check_version) REFERENCES check_versions (key, version),
    UNIQUE (observation_id, check_key, check_version)
);

-- Opened by a failing evaluation, closed only by a later passing one.
CREATE TABLE findings (
    id                    bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    check_key             text        NOT NULL,
    resource_id           bigint      NOT NULL REFERENCES resources (id),
    opening_evaluation_id bigint      NOT NULL REFERENCES evaluations (id),
    closing_evaluation_id bigint      REFERENCES evaluations (id),
    opened_at             timestamptz NOT NULL DEFAULT now(),
    closed_at             timestamptz,
    CHECK ((closing_evaluation_id IS NULL) = (closed_at IS NULL))
);
-- At most one open finding per check and resource.
CREATE UNIQUE INDEX findings_one_open_idx ON findings (check_key, resource_id)
    WHERE closing_evaluation_id IS NULL;

-- History is insert-only, whichever database role asks.
CREATE TRIGGER evidence_payloads_immutable
    BEFORE UPDATE OR DELETE ON evidence_payloads
    FOR EACH ROW EXECUTE FUNCTION reject_change();
CREATE TRIGGER observations_immutable
    BEFORE UPDATE OR DELETE ON observations
    FOR EACH ROW EXECUTE FUNCTION reject_change();
CREATE TRIGGER check_versions_immutable
    BEFORE UPDATE OR DELETE ON check_versions
    FOR EACH ROW EXECUTE FUNCTION reject_change();
CREATE TRIGGER evaluations_immutable
    BEFORE UPDATE OR DELETE ON evaluations
    FOR EACH ROW EXECUTE FUNCTION reject_change();

-- A finding may only be closed, once, by a passing evaluation that came after
-- the one that opened it. Nothing else about it may change.
-- +goose StatementBegin
CREATE FUNCTION guard_finding_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'findings cannot be deleted' USING ERRCODE = 'restrict_violation';
    END IF;
    IF OLD.closing_evaluation_id IS NOT NULL THEN
        RAISE EXCEPTION 'finding % is already closed', OLD.id USING ERRCODE = 'restrict_violation';
    END IF;
    IF NEW.id <> OLD.id
       OR NEW.check_key <> OLD.check_key
       OR NEW.resource_id <> OLD.resource_id
       OR NEW.opening_evaluation_id <> OLD.opening_evaluation_id
       OR NEW.opened_at <> OLD.opened_at THEN
        RAISE EXCEPTION 'only the closing fields of a finding may change' USING ERRCODE = 'restrict_violation';
    END IF;
    IF NEW.closing_evaluation_id IS NULL
       OR NEW.closing_evaluation_id <= OLD.opening_evaluation_id
       OR NOT EXISTS (
           SELECT 1 FROM evaluations e
           WHERE e.id = NEW.closing_evaluation_id
             AND e.result = 'pass'
             AND e.check_key = OLD.check_key
       ) THEN
        RAISE EXCEPTION 'a finding is closed only by a later passing evaluation of the same check'
            USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER findings_guard
    BEFORE UPDATE OR DELETE ON findings
    FOR EACH ROW EXECUTE FUNCTION guard_finding_change();

-- +goose Down
DROP TABLE findings;
DROP FUNCTION guard_finding_change();
DROP TABLE evaluations;
DROP TABLE check_versions;
DROP TABLE observations;
DROP TABLE evidence_payloads;
DROP TABLE collection_runs;
DROP TABLE resources;
