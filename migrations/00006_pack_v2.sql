-- +goose Up

-- Pack schema version 2. A pack now says what rights it has over the
-- framework's text, may come from a URL or a document as well as a git
-- commit, may be a profile of another pack, and may carry identifiers and
-- the project's own labels in place of upstream's titles and text.
ALTER TABLE framework_versions RENAME COLUMN source_repository TO source_url;
ALTER TABLE framework_versions
    DROP CONSTRAINT framework_versions_source_commit_check,
    DROP CONSTRAINT framework_versions_source_sha256_check,
    ADD CONSTRAINT framework_versions_source_commit_check CHECK (source_commit ~ '^([0-9a-f]{40})?$'),
    ADD CONSTRAINT framework_versions_source_sha256_check CHECK (source_sha256 ~ '^([0-9a-f]{64})?$'),
    ADD COLUMN text_rights text NOT NULL DEFAULT 'full'
        CHECK (text_rights IN ('full', 'identifiers_only', 'own_composition')),
    ADD COLUMN attribution text NOT NULL DEFAULT '',
    ADD COLUMN source_kind text NOT NULL DEFAULT 'git' CHECK (source_kind IN ('git', 'url', 'document')),
    ADD COLUMN profile_of  text NOT NULL DEFAULT '';
ALTER TABLE framework_versions
    ALTER COLUMN text_rights DROP DEFAULT,
    ALTER COLUMN source_kind DROP DEFAULT;

ALTER TABLE requirements
    DROP CONSTRAINT requirements_title_check,
    DROP CONSTRAINT requirements_body_check,
    ADD COLUMN parent_identifier text NOT NULL DEFAULT '',
    ADD COLUMN label             text NOT NULL DEFAULT '',
    -- Upstream text is held only where the pack has the right to carry it.
    ADD CONSTRAINT requirements_named_check CHECK (title <> '' OR body <> '' OR label <> '');

-- The MVSP pack file was rewritten in the new header form. Its requirement
-- text is byte for byte what it was, so the imported row is the same
-- release; only the hash of the file changed. This is the one place a
-- framework row is updated, and the trigger is put back straight after.
ALTER TABLE framework_versions DISABLE TRIGGER framework_versions_immutable;
UPDATE framework_versions
SET content_sha256 = '9e4eeefaae9a17a4557dd1ab1f92e2548f8252afe8fc508e87e2076b4d177724'
WHERE key = 'mvsp' AND version = 'v3.0-20231109'
  AND content_sha256 = '2cd2a488c88b57ab82c135b0f9e4e4a5f3a1333a758f00906457836abebb56d5';
ALTER TABLE framework_versions ENABLE TRIGGER framework_versions_immutable;

-- +goose Down
ALTER TABLE framework_versions DISABLE TRIGGER framework_versions_immutable;
UPDATE framework_versions
SET content_sha256 = '2cd2a488c88b57ab82c135b0f9e4e4a5f3a1333a758f00906457836abebb56d5'
WHERE key = 'mvsp' AND version = 'v3.0-20231109'
  AND content_sha256 = '9e4eeefaae9a17a4557dd1ab1f92e2548f8252afe8fc508e87e2076b4d177724';
ALTER TABLE framework_versions ENABLE TRIGGER framework_versions_immutable;
ALTER TABLE requirements
    DROP CONSTRAINT requirements_named_check,
    DROP COLUMN label,
    DROP COLUMN parent_identifier,
    ADD CONSTRAINT requirements_title_check CHECK (title <> ''),
    ADD CONSTRAINT requirements_body_check CHECK (body <> '');
ALTER TABLE framework_versions
    DROP COLUMN profile_of,
    DROP COLUMN source_kind,
    DROP COLUMN attribution,
    DROP COLUMN text_rights,
    DROP CONSTRAINT framework_versions_source_sha256_check,
    DROP CONSTRAINT framework_versions_source_commit_check,
    ADD CONSTRAINT framework_versions_source_commit_check CHECK (source_commit ~ '^[0-9a-f]{40}$'),
    ADD CONSTRAINT framework_versions_source_sha256_check CHECK (source_sha256 ~ '^[0-9a-f]{64}$');
ALTER TABLE framework_versions RENAME COLUMN source_url TO source_repository;
