package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound means the requested row does not exist.
var ErrNotFound = errors.New("not found")

// ErrAlreadyDecided means a review or decision was attempted on something
// that has already been reviewed or decided.
var ErrAlreadyDecided = errors.New("already decided")

// Pool exposes the connection pool for the session store.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

func notFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// logTx appends to the decision log inside the transaction that makes the change.
func logTx(ctx context.Context, tx pgx.Tx, actorID int64, action, objectType string, objectID int64, reason string, at time.Time) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO decision_log (actor_id, action, object_type, object_id, reason, at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		actorID, action, objectType, objectID, reason, at)
	return err
}

// User is an account.
type User struct {
	ID           int64
	Username     string
	DisplayName  string
	Role         string
	PasswordHash string
}

const userColumns = `id, username, display_name, role, password_hash FROM users`

// CreateUser adds an account.
func (s *Store) CreateUser(ctx context.Context, username, displayName, role, passwordHash string) (int64, error) {
	var id int64
	err := s.pool.QueryRow(ctx, `
		INSERT INTO users (username, display_name, role, password_hash)
		VALUES ($1, $2, $3, $4) RETURNING id`,
		username, displayName, role, passwordHash).Scan(&id)
	return id, err
}

// SetPassword replaces an account's password hash.
func (s *Store) SetPassword(ctx context.Context, username, passwordHash string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE users SET password_hash = $2 WHERE username = $1`, username, passwordHash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// UserByUsername returns the account with the given username.
func (s *Store) UserByUsername(ctx context.Context, username string) (User, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+userColumns+` WHERE username = $1`, username)
	if err != nil {
		return User{}, err
	}
	u, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByPos[User])
	return u, notFound(err)
}

// UserByID returns the account with the given id.
func (s *Store) UserByID(ctx context.Context, id int64) (User, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+userColumns+` WHERE id = $1`, id)
	if err != nil {
		return User{}, err
	}
	u, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByPos[User])
	return u, notFound(err)
}

// Users returns every account, by username.
func (s *Store) Users(ctx context.Context) ([]User, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+userColumns+` ORDER BY username`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[User])
}

// FindingByID returns one finding.
func (s *Store) FindingByID(ctx context.Context, id int64) (FindingRow, error) {
	rows, err := s.pool.Query(ctx, findingsQuery+` WHERE f.id = $1`, id)
	if err != nil {
		return FindingRow{}, err
	}
	f, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByPos[FindingRow])
	return f, notFound(err)
}

// SubmissionRow is one manual evidence submission and its review.
type SubmissionRow struct {
	ID            int64
	ControlKey    string
	PeriodStart   time.Time
	PeriodEnd     time.Time
	PayloadSHA256 string
	Filename      string
	Note          string
	SubmittedByID int64
	SubmittedBy   string
	SubmittedAt   time.Time
	ReviewStatus  string
	ReviewedBy    *string
	ReviewedAt    *time.Time
	ReviewReason  string
	ValidUntil    *time.Time
}

const submissionsQuery = `
	SELECT e.id, e.control_key, e.period_start, e.period_end, e.payload_sha256, e.filename, e.note,
	       e.submitted_by, su.username, e.submitted_at, e.review_status, ru.username,
	       e.reviewed_at, e.review_reason, e.valid_until
	FROM evidence_submissions e
	JOIN users su ON su.id = e.submitted_by
	LEFT JOIN users ru ON ru.id = e.reviewed_by`

// NewSubmission is manual evidence being submitted.
type NewSubmission struct {
	ControlKey        string
	PeriodStart       time.Time
	PeriodEnd         time.Time
	Filename          string
	Note              string
	PayloadSHA256     string
	PayloadSize       int64
	PayloadMediaType  string
	PayloadStorageRef string
}

// CreateSubmission records manual evidence and logs the submission.
func (s *Store) CreateSubmission(ctx context.Context, actorID int64, n NewSubmission, at time.Time) (id int64, err error) {
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO evidence_payloads (sha256, size_bytes, media_type, storage_ref)
			VALUES ($1, $2, $3, $4) ON CONFLICT (sha256) DO NOTHING`,
			n.PayloadSHA256, n.PayloadSize, n.PayloadMediaType, n.PayloadStorageRef)
		if err != nil {
			return err
		}
		err = tx.QueryRow(ctx, `
			INSERT INTO evidence_submissions
				(control_key, period_start, period_end, payload_sha256, filename, note, submitted_by, submitted_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
			n.ControlKey, n.PeriodStart, n.PeriodEnd, n.PayloadSHA256, n.Filename, n.Note, actorID, at).Scan(&id)
		if err != nil {
			return err
		}
		return logTx(ctx, tx, actorID, "evidence.submitted", "evidence_submission", id, n.Note, at)
	})
	return id, err
}

// SubmissionByID returns one submission.
func (s *Store) SubmissionByID(ctx context.Context, id int64) (SubmissionRow, error) {
	rows, err := s.pool.Query(ctx, submissionsQuery+` WHERE e.id = $1`, id)
	if err != nil {
		return SubmissionRow{}, err
	}
	r, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByPos[SubmissionRow])
	return r, notFound(err)
}

// Submissions returns every submission, newest first.
func (s *Store) Submissions(ctx context.Context) ([]SubmissionRow, error) {
	rows, err := s.pool.Query(ctx, submissionsQuery+` ORDER BY e.id DESC`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[SubmissionRow])
}

// ReviewSubmission accepts or rejects a pending submission and logs it.
// validUntil is set when accepting.
func (s *Store) ReviewSubmission(ctx context.Context, id, reviewerID int64, accept bool, reason string, validUntil *time.Time, at time.Time) error {
	status, action := "rejected", "evidence.rejected"
	if accept {
		status, action = "accepted", "evidence.accepted"
	} else {
		validUntil = nil
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE evidence_submissions
			SET review_status = $2, reviewed_by = $3, reviewed_at = $4, review_reason = $5, valid_until = $6
			WHERE id = $1 AND review_status = 'pending'`,
			id, status, reviewerID, at, reason, validUntil)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrAlreadyDecided
		}
		return logTx(ctx, tx, reviewerID, action, "evidence_submission", id, reason, at)
	})
}

// ExceptionRow is one exception request and its decision.
type ExceptionRow struct {
	ID             int64
	FindingID      int64
	CheckKey       string
	Resource       string
	RequestedByID  int64
	RequestedBy    string
	Justification  string
	RequestedAt    time.Time
	ExpiresAt      time.Time
	Status         string
	DecidedBy      *string
	DecidedAt      *time.Time
	DecisionReason string
}

// Active reports whether the exception is approved and not yet expired.
func (e ExceptionRow) Active(now time.Time) bool {
	return e.Status == "approved" && e.ExpiresAt.After(now)
}

// Expired reports whether the exception was approved and has since expired.
func (e ExceptionRow) Expired(now time.Time) bool {
	return e.Status == "approved" && !e.ExpiresAt.After(now)
}

// DisplayStatus is the status to show at the given time: an approved
// exception past its expiry reads as expired. Nothing is rewritten to make
// that so; expiry is a comparison made on read.
func (e ExceptionRow) DisplayStatus(now time.Time) string {
	if e.Expired(now) {
		return "expired"
	}
	return e.Status
}

const exceptionsQuery = `
	SELECT x.id, x.finding_id, f.check_key, r.external_id, x.requested_by, qu.username,
	       x.justification, x.requested_at, x.expires_at, x.status, du.username,
	       x.decided_at, x.decision_reason
	FROM exceptions x
	JOIN findings f ON f.id = x.finding_id
	JOIN resources r ON r.id = f.resource_id
	JOIN users qu ON qu.id = x.requested_by
	LEFT JOIN users du ON du.id = x.decided_by`

// CreateException records an exception request and logs it.
func (s *Store) CreateException(ctx context.Context, findingID, requesterID int64, justification string, expiresAt, at time.Time) (id int64, err error) {
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			INSERT INTO exceptions (finding_id, requested_by, justification, requested_at, expires_at)
			VALUES ($1, $2, $3, $4, $5) RETURNING id`,
			findingID, requesterID, justification, at, expiresAt).Scan(&id)
		if err != nil {
			return err
		}
		return logTx(ctx, tx, requesterID, "exception.requested", "exception", id, justification, at)
	})
	return id, err
}

// ExceptionByID returns one exception.
func (s *Store) ExceptionByID(ctx context.Context, id int64) (ExceptionRow, error) {
	rows, err := s.pool.Query(ctx, exceptionsQuery+` WHERE x.id = $1`, id)
	if err != nil {
		return ExceptionRow{}, err
	}
	r, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByPos[ExceptionRow])
	return r, notFound(err)
}

// Exceptions returns every exception, newest first.
func (s *Store) Exceptions(ctx context.Context) ([]ExceptionRow, error) {
	rows, err := s.pool.Query(ctx, exceptionsQuery+` ORDER BY x.id DESC`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[ExceptionRow])
}

// DecideException approves or rejects a pending request and logs it.
func (s *Store) DecideException(ctx context.Context, id, deciderID int64, approve bool, reason string, at time.Time) error {
	status, action := "rejected", "exception.rejected"
	if approve {
		status, action = "approved", "exception.approved"
	}
	return s.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE exceptions
			SET status = $2, decided_by = $3, decided_at = $4, decision_reason = $5
			WHERE id = $1 AND status = 'requested'`,
			id, status, deciderID, at, reason)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrAlreadyDecided
		}
		return logTx(ctx, tx, deciderID, action, "exception", id, reason, at)
	})
}

// NoteRow is one remediation note.
type NoteRow struct {
	ID        int64
	FindingID int64
	Author    string
	Body      string
	CreatedAt time.Time
}

// AddNote records a remediation note on a finding and logs it.
func (s *Store) AddNote(ctx context.Context, findingID, authorID int64, body string, at time.Time) (id int64, err error) {
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			INSERT INTO remediation_notes (finding_id, author_id, body, created_at)
			VALUES ($1, $2, $3, $4) RETURNING id`,
			findingID, authorID, body, at).Scan(&id)
		if err != nil {
			return err
		}
		return logTx(ctx, tx, authorID, "remediation.noted", "finding", findingID, body, at)
	})
	return id, err
}

// Notes returns every remediation note, oldest first.
func (s *Store) Notes(ctx context.Context) ([]NoteRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT n.id, n.finding_id, u.username, n.body, n.created_at
		FROM remediation_notes n JOIN users u ON u.id = n.author_id
		ORDER BY n.id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[NoteRow])
}

// LogRow is one decision log entry.
type LogRow struct {
	ID         int64
	Actor      string
	ActorRole  string
	Action     string
	ObjectType string
	ObjectID   int64
	Reason     string
	At         time.Time
}

// DecisionLog returns the most recent log entries, newest first.
func (s *Store) DecisionLog(ctx context.Context, limit int) ([]LogRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT l.id, u.username, u.role, l.action, l.object_type, l.object_id, l.reason, l.at
		FROM decision_log l JOIN users u ON u.id = l.actor_id
		ORDER BY l.id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[LogRow])
}

// LogAction appends a decision log entry for an action that changes no
// decision row, such as starting a job.
func (s *Store) LogAction(ctx context.Context, actorID int64, action, objectType string, objectID int64, reason string, at time.Time) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		return logTx(ctx, tx, actorID, action, objectType, objectID, reason, at)
	})
}
