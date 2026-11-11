-- +goose Up

-- One row per imported framework release. A new release is a new row; earlier
-- releases and their requirements stay.
CREATE TABLE framework_versions (
    id                bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    key               text        NOT NULL CHECK (key ~ '^[a-z][a-z0-9-]*$'),
    title             text        NOT NULL CHECK (title <> ''),
    version           text        NOT NULL CHECK (version <> ''),
    license           text        NOT NULL CHECK (license <> ''),
    source_repository text        NOT NULL,
    source_commit     text        NOT NULL CHECK (source_commit ~ '^[0-9a-f]{40}$'),
    source_path       text        NOT NULL,
    source_retrieved  date        NOT NULL,
    source_sha256     text        NOT NULL CHECK (source_sha256 ~ '^[0-9a-f]{64}$'),
    content_sha256    text        NOT NULL CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
    imported_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (key, version)
);

CREATE TABLE requirements (
    id                   bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    framework_version_id bigint  NOT NULL REFERENCES framework_versions (id),
    identifier           text    NOT NULL CHECK (identifier <> ''),
    group_title          text    NOT NULL CHECK (group_title <> ''),
    title                text    NOT NULL CHECK (title <> ''),
    body                 text    NOT NULL CHECK (body <> ''),
    position             integer NOT NULL CHECK (position > 0),
    UNIQUE (framework_version_id, identifier),
    UNIQUE (framework_version_id, position)
);

-- Framework content is read-only after import, whichever database role asks.
-- +goose StatementBegin
CREATE FUNCTION reject_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is not allowed on %: rows are immutable after import',
        TG_OP, TG_TABLE_NAME
        USING ERRCODE = 'restrict_violation';
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER framework_versions_immutable
    BEFORE UPDATE OR DELETE ON framework_versions
    FOR EACH ROW EXECUTE FUNCTION reject_change();

CREATE TRIGGER requirements_immutable
    BEFORE UPDATE OR DELETE ON requirements
    FOR EACH ROW EXECUTE FUNCTION reject_change();

-- +goose Down
DROP TABLE requirements;
DROP TABLE framework_versions;
DROP FUNCTION reject_change();
