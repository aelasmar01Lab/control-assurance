-- +goose Up

-- Every wording of every control that has been loaded, and whether a person
-- had reviewed it. Controls are edited as files; this is the record of what
-- was in force when. Insert-only: a changed control is a new row.
CREATE TABLE control_revisions (
    id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    control_key    text        NOT NULL CHECK (control_key <> ''),
    -- The hash of the control's content without its review block.
    content_sha256 text        NOT NULL CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
    content        jsonb       NOT NULL,
    review_status  text        NOT NULL CHECK (review_status IN ('draft', 'reviewed')),
    reviewed_by    text        NOT NULL DEFAULT '',
    reviewed_on    text        NOT NULL DEFAULT '',
    loaded_at      timestamptz NOT NULL,
    CHECK ((review_status = 'reviewed') = (reviewed_by <> ''))
);
CREATE INDEX control_revisions_key_idx ON control_revisions (control_key, id DESC);

CREATE TRIGGER control_revisions_immutable
    BEFORE UPDATE OR DELETE ON control_revisions
    FOR EACH ROW EXECUTE FUNCTION reject_change();

-- +goose Down
DROP TABLE control_revisions;
