-- +goose Up

-- A heading is a node of a framework's hierarchy, such as a function or a
-- category. It is kept for its place and wording, and is not assessed.
ALTER TABLE requirements ADD COLUMN heading boolean NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE requirements DROP COLUMN heading;
