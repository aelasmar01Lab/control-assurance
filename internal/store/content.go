package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// ControlRevision is one wording of a control as it was loaded.
type ControlRevision struct {
	ID            int64     `json:"id"`
	ControlKey    string    `json:"control_key"`
	ContentSHA256 string    `json:"content_sha256"`
	ReviewStatus  string    `json:"review_status"`
	ReviewedBy    string    `json:"reviewed_by,omitempty"`
	ReviewedOn    string    `json:"reviewed_on,omitempty"`
	LoadedAt      time.Time `json:"loaded_at"`
	// Content is the control's content as JSON, as it was hashed.
	Content []byte `json:"-"`
}

// RecordControlRevision records a control as loaded, unless the newest
// revision of that control already has the same content and review. It
// reports whether a row was added.
func (s *Store) RecordControlRevision(ctx context.Context, r ControlRevision) (added bool, err error) {
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		var hash, status, by, on string
		err := tx.QueryRow(ctx, `
			SELECT content_sha256, review_status, reviewed_by, reviewed_on
			FROM control_revisions WHERE control_key = $1 ORDER BY id DESC LIMIT 1`,
			r.ControlKey).Scan(&hash, &status, &by, &on)
		switch {
		case err == nil && hash == r.ContentSHA256 && status == r.ReviewStatus && by == r.ReviewedBy && on == r.ReviewedOn:
			return nil
		case err != nil && !errors.Is(err, pgx.ErrNoRows):
			return err
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO control_revisions
				(control_key, content_sha256, content, review_status, reviewed_by, reviewed_on, loaded_at)
			VALUES ($1, $2, $3::jsonb, $4, $5, $6, $7)`,
			r.ControlKey, r.ContentSHA256, string(r.Content), r.ReviewStatus, r.ReviewedBy, r.ReviewedOn, r.LoadedAt)
		added = err == nil
		return err
	})
	return added, err
}

// ControlRevisions returns every recorded revision, oldest first.
func (s *Store) ControlRevisions(ctx context.Context) ([]ControlRevision, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, control_key, content_sha256, review_status, reviewed_by, reviewed_on, loaded_at
		FROM control_revisions ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ControlRevision{}
	for rows.Next() {
		var r ControlRevision
		if err := rows.Scan(&r.ID, &r.ControlKey, &r.ContentSHA256, &r.ReviewStatus, &r.ReviewedBy, &r.ReviewedOn, &r.LoadedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
