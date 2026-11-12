-- +goose Up

CREATE TABLE users (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username      text        NOT NULL UNIQUE CHECK (username ~ '^[a-z][a-z0-9-]{1,31}$'),
    display_name  text        NOT NULL CHECK (display_name <> ''),
    role          text        NOT NULL CHECK (role IN ('operator', 'control_owner', 'reviewer', 'auditor')),
    password_hash text        NOT NULL CHECK (password_hash <> ''),
    created_at    timestamptz NOT NULL DEFAULT now()
);

-- Server-side sessions, in the layout the session library expects.
CREATE TABLE sessions (
    token  text        PRIMARY KEY,
    data   bytea       NOT NULL,
    expiry timestamptz NOT NULL
);
CREATE INDEX sessions_expiry_idx ON sessions (expiry);

-- Manual evidence for a control. Submitting and reviewing are separate
-- actions by separate users.
CREATE TABLE evidence_submissions (
    id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    control_key    text        NOT NULL CHECK (control_key <> ''),
    period_start   date        NOT NULL,
    period_end     date        NOT NULL CHECK (period_end >= period_start),
    payload_sha256 text        NOT NULL REFERENCES evidence_payloads (sha256),
    filename       text        NOT NULL CHECK (filename <> ''),
    note           text        NOT NULL DEFAULT '',
    submitted_by   bigint      NOT NULL REFERENCES users (id),
    submitted_at   timestamptz NOT NULL,
    review_status  text        NOT NULL DEFAULT 'pending'
                               CHECK (review_status IN ('pending', 'accepted', 'rejected')),
    reviewed_by    bigint      REFERENCES users (id),
    reviewed_at    timestamptz,
    review_reason  text        NOT NULL DEFAULT '',
    valid_until    date,
    -- Separation of duties, as a constraint.
    CONSTRAINT evidence_reviewer_is_not_submitter CHECK (reviewed_by <> submitted_by),
    CHECK ((review_status = 'pending') = (reviewed_by IS NULL)),
    CHECK ((review_status = 'pending') = (reviewed_at IS NULL)),
    CHECK ((review_status = 'accepted') = (valid_until IS NOT NULL)),
    CHECK (review_status <> 'rejected' OR review_reason <> '')
);

-- A time-limited acceptance of a finding. It never alters an evaluation.
CREATE TABLE exceptions (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    finding_id      bigint      NOT NULL REFERENCES findings (id),
    requested_by    bigint      NOT NULL REFERENCES users (id),
    justification   text        NOT NULL CHECK (justification <> ''),
    requested_at    timestamptz NOT NULL,
    -- Expiry is mandatory.
    expires_at      timestamptz NOT NULL,
    status          text        NOT NULL DEFAULT 'requested'
                                CHECK (status IN ('requested', 'approved', 'rejected')),
    decided_by      bigint      REFERENCES users (id),
    decided_at      timestamptz,
    decision_reason text        NOT NULL DEFAULT '',
    CHECK (expires_at > requested_at),
    -- Separation of duties, as a constraint.
    CONSTRAINT exception_approver_is_not_requester CHECK (decided_by <> requested_by),
    CHECK ((status = 'requested') = (decided_by IS NULL)),
    CHECK ((status = 'requested') = (decided_at IS NULL)),
    CHECK (status = 'requested' OR decision_reason <> '')
);
-- At most one undecided request per finding.
CREATE UNIQUE INDEX exceptions_one_pending_idx ON exceptions (finding_id) WHERE status = 'requested';

CREATE TABLE remediation_notes (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    finding_id bigint      NOT NULL REFERENCES findings (id),
    author_id  bigint      NOT NULL REFERENCES users (id),
    body       text        NOT NULL CHECK (body <> ''),
    created_at timestamptz NOT NULL
);

-- Who did what, to what, and why.
CREATE TABLE decision_log (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_id    bigint      NOT NULL REFERENCES users (id),
    action      text        NOT NULL CHECK (action <> ''),
    object_type text        NOT NULL CHECK (object_type <> ''),
    object_id   bigint      NOT NULL,
    reason      text        NOT NULL DEFAULT '',
    at          timestamptz NOT NULL
);

CREATE TRIGGER remediation_notes_immutable
    BEFORE UPDATE OR DELETE ON remediation_notes
    FOR EACH ROW EXECUTE FUNCTION reject_change();
CREATE TRIGGER decision_log_immutable
    BEFORE UPDATE OR DELETE ON decision_log
    FOR EACH ROW EXECUTE FUNCTION reject_change();

-- A row that is decided once: it may change only while its status column
-- still holds the undecided value, and then only in the listed columns.
-- Arguments: status column, undecided value, comma-separated mutable columns.
-- +goose StatementBegin
CREATE FUNCTION guard_decide_once() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    mutable text[] := string_to_array(TG_ARGV[2], ',');
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION '% rows cannot be deleted', TG_TABLE_NAME USING ERRCODE = 'restrict_violation';
    END IF;
    IF to_jsonb(OLD) ->> TG_ARGV[0] <> TG_ARGV[1] THEN
        RAISE EXCEPTION '% % has already been decided', TG_TABLE_NAME, OLD.id USING ERRCODE = 'restrict_violation';
    END IF;
    IF (to_jsonb(OLD) - mutable) <> (to_jsonb(NEW) - mutable) THEN
        RAISE EXCEPTION 'only the decision fields of % may change', TG_TABLE_NAME USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER evidence_submissions_guard
    BEFORE UPDATE OR DELETE ON evidence_submissions
    FOR EACH ROW EXECUTE FUNCTION guard_decide_once(
        'review_status', 'pending', 'review_status,reviewed_by,reviewed_at,review_reason,valid_until');

CREATE TRIGGER exceptions_guard
    BEFORE UPDATE OR DELETE ON exceptions
    FOR EACH ROW EXECUTE FUNCTION guard_decide_once(
        'status', 'requested', 'status,decided_by,decided_at,decision_reason');

-- +goose Down
DROP TABLE decision_log;
DROP TABLE remediation_notes;
DROP TABLE exceptions;
DROP TABLE evidence_submissions;
DROP FUNCTION guard_decide_once();
DROP TABLE sessions;
DROP TABLE users;
