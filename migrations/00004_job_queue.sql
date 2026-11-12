-- +goose Up

-- collection_runs becomes the job queue as well as the record of attempts.
-- A run is queued, claimed by a worker (running), then succeeded or failed.
-- It is still one row per attempt: a retry is a new row that points at the
-- attempt it follows.

-- A run left running by the first release has no worker to finish it.
UPDATE collection_runs
SET outcome = 'failed', finished_at = started_at,
    error_class = 'interrupted', error_detail = 'left running before the job queue existed'
WHERE outcome = 'running';

ALTER TABLE collection_runs
    DROP CONSTRAINT collection_runs_outcome_check,
    DROP CONSTRAINT collection_runs_check1,
    ALTER COLUMN started_at DROP NOT NULL,
    -- The kind of observation the run collects, such as github.branch_rules.
    ADD COLUMN kind text NOT NULL DEFAULT 'github.branch_rules' CHECK (kind <> ''),
    ADD COLUMN queued_at timestamptz,
    -- The run may not be claimed before this time; a retry waits here.
    ADD COLUMN run_after timestamptz,
    ADD COLUMN attempt integer NOT NULL DEFAULT 1 CHECK (attempt >= 1),
    ADD COLUMN retry_of bigint REFERENCES collection_runs (id),
    ADD COLUMN cause text NOT NULL DEFAULT 'manual' CHECK (cause IN ('manual', 'schedule', 'retry')),
    -- A running run whose lease has passed belongs to a worker that stopped.
    ADD COLUMN lease_expires_at timestamptz;

UPDATE collection_runs SET queued_at = started_at, run_after = started_at;

ALTER TABLE collection_runs
    ALTER COLUMN kind DROP DEFAULT,
    ALTER COLUMN queued_at SET NOT NULL,
    ALTER COLUMN run_after SET NOT NULL,
    ADD CONSTRAINT collection_runs_outcome_check
        CHECK (outcome IN ('queued', 'running', 'succeeded', 'failed')),
    ADD CONSTRAINT collection_runs_times_check CHECK (
        (outcome = 'queued' AND started_at IS NULL AND finished_at IS NULL)
        OR (outcome = 'running' AND started_at IS NOT NULL AND finished_at IS NULL)
        OR (outcome IN ('succeeded', 'failed') AND started_at IS NOT NULL AND finished_at IS NOT NULL)),
    ADD CONSTRAINT collection_runs_retry_check CHECK ((cause = 'retry') = (retry_of IS NOT NULL));

-- At most one unfinished attempt per job, so asking twice queues once and
-- two workers never collect the same thing at the same time.
CREATE UNIQUE INDEX collection_runs_one_pending_idx ON collection_runs (kind, resource_id)
    WHERE outcome IN ('queued', 'running');
CREATE INDEX collection_runs_queue_idx ON collection_runs (run_after, id) WHERE outcome = 'queued';

-- A finished run is history: it cannot change or be deleted.
-- +goose StatementBegin
CREATE FUNCTION guard_run_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'collection runs cannot be deleted' USING ERRCODE = 'restrict_violation';
    END IF;
    IF OLD.outcome IN ('succeeded', 'failed') THEN
        RAISE EXCEPTION 'collection run % has finished and cannot change', OLD.id
            USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER collection_runs_guard
    BEFORE UPDATE OR DELETE ON collection_runs
    FOR EACH ROW EXECUTE FUNCTION guard_run_change();

-- +goose Down
DROP TRIGGER collection_runs_guard ON collection_runs;
DROP FUNCTION guard_run_change();
DROP INDEX collection_runs_queue_idx;
DROP INDEX collection_runs_one_pending_idx;
DELETE FROM collection_runs WHERE outcome = 'queued';
ALTER TABLE collection_runs
    DROP CONSTRAINT collection_runs_retry_check,
    DROP CONSTRAINT collection_runs_times_check,
    DROP CONSTRAINT collection_runs_outcome_check,
    DROP COLUMN lease_expires_at,
    DROP COLUMN cause,
    DROP COLUMN retry_of,
    DROP COLUMN attempt,
    DROP COLUMN run_after,
    DROP COLUMN queued_at,
    DROP COLUMN kind,
    ALTER COLUMN started_at SET NOT NULL,
    ADD CONSTRAINT collection_runs_outcome_check CHECK (outcome IN ('running', 'succeeded', 'failed')),
    ADD CONSTRAINT collection_runs_check1 CHECK ((outcome = 'running') = (finished_at IS NULL));
