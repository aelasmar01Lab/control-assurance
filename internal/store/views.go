package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// EvaluationRow is one evaluation with the evidence it rests on.
type EvaluationRow struct {
	EvaluationID  int64
	ObservationID int64
	Resource      string
	CheckKey      string
	CheckVersion  string
	Result        string
	Explanation   string
	PayloadSHA256 string
	CollectedAt   time.Time
	EvaluatedAt   time.Time
	// AsOf is the moment the evidence describes: the source's own
	// timestamp when it gave one, otherwise the time of collection.
	AsOf time.Time
}

const evaluationColumns = `
	e.id, o.id, r.external_id, e.check_key, e.check_version, e.result,
	e.explanation, o.payload_sha256, o.collected_at, e.evaluated_at,
	COALESCE(o.source_timestamp, o.collected_at)
	FROM evaluations e
	JOIN observations o ON o.id = e.observation_id
	JOIN resources r ON r.id = o.resource_id`

// LatestResults returns, for each resource and check, the evaluation of the
// newest observation. It is the current result; a failed collection run adds
// no observation and so never changes it.
func (s *Store) LatestResults(ctx context.Context) ([]EvaluationRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT * FROM (
			SELECT DISTINCT ON (r.id, e.check_key)`+evaluationColumns+`
			ORDER BY r.id, e.check_key, o.id DESC, e.id DESC
		) latest
		ORDER BY 3, 4`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[EvaluationRow])
}

// Evaluations returns the most recent evaluations, newest first.
func (s *Store) Evaluations(ctx context.Context, limit int) ([]EvaluationRow, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT`+evaluationColumns+` ORDER BY e.id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[EvaluationRow])
}

// PayloadHashes returns the SHA-256 of every evidence payload on record.
func (s *Store) PayloadHashes(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT sha256 FROM evidence_payloads ORDER BY sha256`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// AllEvaluations returns every evaluation, oldest first.
func (s *Store) AllEvaluations(ctx context.Context) ([]EvaluationRow, error) {
	rows, err := s.pool.Query(ctx, `SELECT`+evaluationColumns+` ORDER BY e.id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[EvaluationRow])
}

// ObservationRow is what one successful collection run saw.
type ObservationRow struct {
	ID                int64
	RunID             int64
	Provider          string
	ResourceKind      string
	Resource          string
	Kind              string
	CollectedAt       time.Time
	SourceTimestamp   *time.Time
	PayloadSHA256     string
	PayloadSize       int64
	NormalizerVersion string
}

// Observations returns the observations collected in [from, to), oldest first.
func (s *Store) Observations(ctx context.Context, from, to time.Time) ([]ObservationRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT o.id, o.run_id, r.provider, r.kind, r.external_id, o.kind, o.collected_at, o.source_timestamp,
		       o.payload_sha256, p.size_bytes, o.normalizer_version
		FROM observations o
		JOIN resources r ON r.id = o.resource_id
		JOIN evidence_payloads p ON p.sha256 = o.payload_sha256
		WHERE o.collected_at >= $1 AND o.collected_at < $2
		ORDER BY o.id`, from, to)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[ObservationRow])
}

// FindingRow is a finding with the evaluations that opened and closed it.
type FindingRow struct {
	ID                  int64
	Resource            string
	CheckKey            string
	OpenedAt            time.Time
	OpeningEvaluationID int64
	OpeningExplanation  string
	ClosedAt            *time.Time
	ClosingEvaluationID *int64
	ClosingExplanation  *string
}

// Open reports whether the finding is still open.
func (f FindingRow) Open() bool { return f.ClosingEvaluationID == nil }

const findingsQuery = `
	SELECT f.id, r.external_id, f.check_key, f.opened_at,
	       f.opening_evaluation_id, eo.explanation,
	       f.closed_at, f.closing_evaluation_id, ec.explanation
	FROM findings f
	JOIN resources r ON r.id = f.resource_id
	JOIN evaluations eo ON eo.id = f.opening_evaluation_id
	LEFT JOIN evaluations ec ON ec.id = f.closing_evaluation_id`

// Findings returns every finding, open ones first, then newest first.
func (s *Store) Findings(ctx context.Context) ([]FindingRow, error) {
	rows, err := s.pool.Query(ctx, findingsQuery+`
		ORDER BY (f.closing_evaluation_id IS NOT NULL), f.id DESC`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[FindingRow])
}

// RequirementCount returns how many requirements are imported per framework version.
func (s *Store) RequirementCount(ctx context.Context) (map[string]int, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT fv.key || ' ' || fv.version, count(rq.id)
		FROM framework_versions fv LEFT JOIN requirements rq ON rq.framework_version_id = fv.id
		GROUP BY 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var name string
		var n int
		if err := rows.Scan(&name, &n); err != nil {
			return nil, err
		}
		out[name] = n
	}
	return out, rows.Err()
}
