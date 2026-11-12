package assurance

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aelasmar01Lab/control-assurance/internal/authz"
	"github.com/aelasmar01Lab/control-assurance/internal/check"
	"github.com/aelasmar01Lab/control-assurance/internal/control"
	"github.com/aelasmar01Lab/control-assurance/internal/store"
)

// PackageFormat names the layout of a review package. A change to which
// files exist or what they hold means a new format.
const PackageFormat = "cca-review-package/1"

const packageNotice = "A review package for one past period. Every result describes one check version applied to one stored observation; " +
	"it is not a statement about any framework. Control states are as they stood at the end of the period."

// ManifestFile is one file of a package and the hash of its bytes.
type ManifestFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Manifest lists everything in a review package. It holds nothing about
// when or by whom the package was generated, so generating the package for
// the same period again yields the same manifest, byte for byte.
type Manifest struct {
	Format string `json:"format"`
	Notice string `json:"notice"`
	// The period is From inclusive to To exclusive, in UTC.
	PeriodFrom time.Time `json:"period_from"`
	PeriodTo   time.Time `json:"period_to"`
	// Scope is every resource registered before the end of the period,
	// including any with no evidence in it.
	Scope  []store.ScopeRow `json:"scope"`
	Counts map[string]int   `json:"counts"`
	Files  []ManifestFile   `json:"files"`
}

// Package is a review package held in memory.
type Package struct {
	Manifest Manifest
	// ManifestSHA256 is the hash of manifest.json, and so of the package.
	ManifestSHA256 string
	// Files holds every file by path, including manifest.json.
	Files map[string][]byte
}

// Paths returns the package's file paths in order.
func (p *Package) Paths() []string {
	paths := make([]string, 0, len(p.Files))
	for path := range p.Files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

// PackageControl is a control and its state at the end of the period.
type PackageControl struct {
	Key                 string            `json:"key"`
	Title               string            `json:"title"`
	Risk                string            `json:"risk"`
	Owner               string            `json:"owner"`
	EvidenceExpectation string            `json:"evidence_expectation"`
	Checks              []string          `json:"checks"`
	ManualCheck         string            `json:"manual_check,omitempty"`
	FreshnessHours      int               `json:"freshness_hours,omitempty"`
	Mappings            []control.Mapping `json:"mappings"`
	StateAtPeriodEnd    control.State     `json:"state_at_period_end"`
	Reasons             []string          `json:"reasons"`
}

// PackageCheck is a check version that produced an evaluation in the package.
type PackageCheck struct {
	Key              string `json:"key"`
	Version          string `json:"version"`
	Assertion        string `json:"assertion"`
	Source           string `json:"source"`
	Establishes      string `json:"establishes"`
	DoesNotEstablish string `json:"does_not_establish"`
	Mapping          string `json:"mapping"`
}

// PackageException is an exception as it stood at the end of the period.
type PackageException struct {
	store.ExceptionRow
	StatusAtPeriodEnd string `json:"status_at_period_end"`
}

// The as-of helpers below return history as it stood just before a moment.
// History is insert-only apart from a finding's closing, an exception's
// decision and a submission's review, each of which carries its own time.

func resultsBefore(evals []store.EvaluationRow, at time.Time) []store.EvaluationRow {
	type key struct{ resource, check string }
	newest := map[key]store.EvaluationRow{}
	for _, e := range evals {
		if !e.CollectedAt.Before(at) || !e.EvaluatedAt.Before(at) {
			continue
		}
		k := key{e.Resource, e.CheckKey}
		have, ok := newest[k]
		if !ok || e.ObservationID > have.ObservationID ||
			(e.ObservationID == have.ObservationID && e.EvaluationID > have.EvaluationID) {
			newest[k] = e
		}
	}
	out := make([]store.EvaluationRow, 0, len(newest))
	for _, e := range newest {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Resource != out[j].Resource {
			return out[i].Resource < out[j].Resource
		}
		return out[i].CheckKey < out[j].CheckKey
	})
	return out
}

func findingsBefore(findings []store.FindingRow, at time.Time) []store.FindingRow {
	var out []store.FindingRow
	for _, f := range findings {
		if !f.OpenedAt.Before(at) {
			continue
		}
		if f.ClosedAt != nil && !f.ClosedAt.Before(at) {
			f.ClosedAt, f.ClosingEvaluationID, f.ClosingExplanation = nil, nil, nil
		}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func exceptionsBefore(exceptions []store.ExceptionRow, at time.Time) []store.ExceptionRow {
	var out []store.ExceptionRow
	for _, x := range exceptions {
		if !x.RequestedAt.Before(at) {
			continue
		}
		if x.DecidedAt != nil && !x.DecidedAt.Before(at) {
			x.Status, x.DecidedBy, x.DecidedAt, x.DecisionReason = "requested", nil, nil, ""
		}
		out = append(out, x)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func submissionsBefore(submissions []store.SubmissionRow, at time.Time) []store.SubmissionRow {
	var out []store.SubmissionRow
	for _, sub := range submissions {
		if !sub.SubmittedAt.Before(at) {
			continue
		}
		if sub.ReviewedAt != nil && !sub.ReviewedAt.Before(at) {
			sub.ReviewStatus, sub.ReviewedBy, sub.ReviewedAt, sub.ReviewReason, sub.ValidUntil = "pending", nil, nil, "", nil
		}
		out = append(out, sub)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func inPeriod(t, from, to time.Time) bool { return !t.Before(from) && t.Before(to) }

// BuildPackage assembles the review package for the period from (inclusive)
// to (exclusive). The period must be over: a package is a statement about
// the past, and only the past is certain to read the same tomorrow.
func (s *Service) BuildPackage(ctx context.Context, actor authz.Actor, from, to time.Time) (*Package, error) {
	if err := authz.Can(actor, authz.Export, authz.Resource{}); err != nil {
		return nil, err
	}
	from, to = from.UTC(), to.UTC()
	now := s.now()
	switch {
	case !from.Before(to):
		return nil, invalid("the period must start before it ends")
	case to.After(now):
		return nil, invalid("the period ends at %s, which has not passed yet; a review package covers a past period", to.Format(time.RFC3339))
	}

	allEvals, err := s.Store.AllEvaluations(ctx)
	if err != nil {
		return nil, err
	}
	allFindings, err := s.Store.Findings(ctx)
	if err != nil {
		return nil, err
	}
	allExceptions, err := s.Store.Exceptions(ctx)
	if err != nil {
		return nil, err
	}
	allSubmissions, err := s.Store.Submissions(ctx)
	if err != nil {
		return nil, err
	}
	allNotes, err := s.Store.Notes(ctx)
	if err != nil {
		return nil, err
	}
	allRuns, err := s.Store.Runs(ctx, 1<<30)
	if err != nil {
		return nil, err
	}
	allLog, err := s.Store.DecisionLog(ctx, 1<<30)
	if err != nil {
		return nil, err
	}
	observations, err := s.Store.Observations(ctx, from, to)
	if err != nil {
		return nil, err
	}
	scope, err := s.Store.ResourcesBefore(ctx, to)
	if err != nil {
		return nil, err
	}

	// State at the end of the period.
	results := resultsBefore(allEvals, to)
	findingsAtEnd := findingsBefore(allFindings, to)
	exceptionsAtEnd := exceptionsBefore(allExceptions, to)
	submissions := submissionsBefore(allSubmissions, to)

	var controls []PackageControl
	for _, v := range deriveControls(to, results, findingsAtEnd, exceptionsAtEnd, submissions) {
		c := v.Control
		controls = append(controls, PackageControl{
			Key: c.Key, Title: c.Title, Risk: c.Risk, Owner: c.Owner, EvidenceExpectation: c.EvidenceExpectation,
			Checks: append([]string{}, c.Checks...), ManualCheck: c.ManualCheck, FreshnessHours: int(c.Freshness.Hours()),
			Mappings: append([]control.Mapping{}, c.Mappings...), StateAtPeriodEnd: v.State, Reasons: v.Reasons,
		})
	}

	// What happened during the period.
	inPackage := map[int64]bool{}
	for _, o := range observations {
		inPackage[o.ID] = true
	}
	evaluations := []store.EvaluationRow{}
	usedChecks := map[[2]string]bool{}
	for _, e := range allEvals {
		// An evaluation made after the period, for example under a later
		// check version, belongs to a later package.
		if inPackage[e.ObservationID] && e.EvaluatedAt.Before(to) {
			evaluations = append(evaluations, e)
			usedChecks[[2]string{e.CheckKey, e.CheckVersion}] = true
		}
	}
	// Findings that were open at some point in the period.
	findings := []store.FindingRow{}
	findingIn := map[int64]bool{}
	for _, f := range findingsAtEnd {
		if f.ClosedAt == nil || !f.ClosedAt.Before(from) {
			findings = append(findings, f)
			findingIn[f.ID] = true
		}
	}
	exceptions := []PackageException{}
	for _, x := range exceptionsAtEnd {
		if findingIn[x.FindingID] {
			exceptions = append(exceptions, PackageException{x, x.DisplayStatus(to)})
		}
	}
	notes := []store.NoteRow{}
	for _, n := range allNotes {
		if findingIn[n.FindingID] && n.CreatedAt.Before(to) {
			notes = append(notes, n)
		}
	}
	runs := []store.RunRow{}
	for _, r := range allRuns {
		if r.FinishedAt != nil && inPeriod(*r.FinishedAt, from, to) {
			runs = append(runs, r)
		}
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i].ID < runs[j].ID })
	log := []store.LogRow{}
	for _, l := range allLog {
		if inPeriod(l.At, from, to) {
			log = append(log, l)
		}
	}
	sort.Slice(log, func(i, j int) bool { return log[i].ID < log[j].ID })
	if submissions == nil {
		submissions = []store.SubmissionRow{}
	}

	checks := []PackageCheck{}
	for _, c := range check.All() {
		if usedChecks[[2]string{c.Key, c.Version}] || (c.Manual && len(submissions) > 0) {
			checks = append(checks, PackageCheck{c.Key, c.Version, c.Assertion, c.Source, c.Establishes, c.DoesNotEstablish, c.Mapping})
		}
	}

	p := &Package{Files: map[string][]byte{}}
	add := func(path string, v any) error {
		data, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return fmt.Errorf("encode %s: %w", path, err)
		}
		p.Files[path] = append(data, '\n')
		return nil
	}
	for path, v := range map[string]any{
		"controls.json": controls, "checks.json": checks, "runs.json": runs, "observations.json": observations,
		"evaluations.json": evaluations, "findings.json": findings, "exceptions.json": exceptions,
		"remediation_notes.json": notes, "evidence_submissions.json": submissions, "decision_log.json": log,
	} {
		if err := add(path, v); err != nil {
			return nil, err
		}
	}
	// The evidence itself, read back through the store so that each file
	// is verified against the hash it is filed under.
	evidence := map[string]bool{}
	for _, o := range observations {
		evidence[o.PayloadSHA256] = true
	}
	for _, sub := range submissions {
		evidence[sub.PayloadSHA256] = true
	}
	for sha := range evidence {
		data, err := s.Evidence.Get(ctx, sha)
		if err != nil {
			return nil, fmt.Errorf("evidence %s: %w", sha, err)
		}
		p.Files["evidence/"+sha] = data
	}
	p.Files["README.md"] = []byte(packageReadme(from, to))

	p.Manifest = Manifest{
		Format: PackageFormat, Notice: packageNotice, PeriodFrom: from, PeriodTo: to, Scope: scope,
		Counts: map[string]int{
			"controls": len(controls), "runs": len(runs), "observations": len(observations), "evaluations": len(evaluations),
			"findings": len(findings), "exceptions": len(exceptions), "remediation_notes": len(notes),
			"evidence_submissions": len(submissions), "decision_log_entries": len(log), "evidence_files": len(evidence),
		},
	}
	if p.Manifest.Scope == nil {
		p.Manifest.Scope = []store.ScopeRow{}
	}
	for _, path := range p.Paths() {
		sum := sha256.Sum256(p.Files[path])
		p.Manifest.Files = append(p.Manifest.Files, ManifestFile{Path: path, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(p.Files[path]))})
	}
	if err := add("manifest.json", p.Manifest); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(p.Files["manifest.json"])
	p.ManifestSHA256 = hex.EncodeToString(sum[:])

	if err := s.Store.LogAction(ctx, actor.UserID, "package.generated", "review_package", from.Unix(),
		fmt.Sprintf("period %s to %s, manifest %s", from.Format(time.RFC3339), to.Format(time.RFC3339), p.ManifestSHA256), now); err != nil {
		return nil, err
	}
	return p, nil
}

func packageReadme(from, to time.Time) string {
	return fmt.Sprintf(`# Review package

Period: %s (inclusive) to %s (exclusive), UTC.
Format: %s

%s

## Files

| File | Holds |
| --- | --- |
| manifest.json | The period, the resources in scope, and the SHA-256 and size of every other file. The SHA-256 of this file identifies the package. |
| controls.json | Each control, what it rests on, its framework mappings, and its state at the end of the period with the reasons. |
| checks.json | Each check version that produced a result here: its assertion, and what a pass does and does not establish. |
| runs.json | Every collection attempt that finished in the period, including failures and retries, with error classes. |
| observations.json | What each successful run saw: when, from which resource, and the hash of the evidence. |
| evaluations.json | Each check version applied to each of those observations, with its result and explanation. |
| findings.json | Every finding that was open at some point in the period, as it stood at the end. |
| exceptions.json | Exception requests and decisions on those findings, as they stood at the end. |
| remediation_notes.json | Notes recorded on those findings. |
| evidence_submissions.json | Manual evidence submitted before the end of the period, with its review as it stood then. |
| decision_log.json | Who did what, and why, during the period. |
| evidence/ | The evidence itself, each file named by the SHA-256 of its bytes. |

## How to check it

Run "cca package verify <this directory or zip>". It recomputes every hash in
the manifest, reports any file that is missing, changed or unlisted, and
re-applies each recorded check version to the stored evidence to confirm that
every evaluation in evaluations.json reproduces.

A collection failure appears in runs.json and nowhere else. It is not a
result, and it never changes one. Nothing in this package is a statement
that anything is compliant.
`, from.Format(time.RFC3339), to.Format(time.RFC3339), PackageFormat, packageNotice)
}

// WriteDir writes the package's files under dir, which must not already
// hold anything.
func (p *Package) WriteDir(dir string) error {
	if entries, err := os.ReadDir(dir); err == nil && len(entries) > 0 {
		return fmt.Errorf("%s is not empty", dir)
	}
	for _, path := range p.Paths() {
		target := filepath.Join(dir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			return err
		}
		if err := os.WriteFile(target, p.Files[path], 0o600); err != nil {
			return err
		}
	}
	return nil
}

// WriteZip writes the package as a zip archive. Entries are in path order
// and stamped with the end of the period, not the time of writing.
func (p *Package) WriteZip(w io.Writer) error {
	zw := zip.NewWriter(w)
	for _, path := range p.Paths() {
		f, err := zw.CreateHeader(&zip.FileHeader{Name: path, Method: zip.Deflate, Modified: p.Manifest.PeriodTo})
		if err != nil {
			return err
		}
		if _, err := f.Write(p.Files[path]); err != nil {
			return err
		}
	}
	return zw.Close()
}

// Verification is the outcome of checking a review package.
type Verification struct {
	ManifestSHA256 string
	PeriodFrom     time.Time
	PeriodTo       time.Time
	Files          int
	// Evaluations is how many evaluations were re-run, and Reproduced how
	// many gave the recorded result and explanation.
	Evaluations int
	Reproduced  int
	// Problems lists everything wrong with the package. Empty means sound.
	Problems []string
}

// OK reports whether the package is intact and every evaluation reproduced.
func (v *Verification) OK() bool { return len(v.Problems) == 0 }

// VerifyPackage checks a review package without a database: every file
// against the manifest, and every evaluation against the evidence in the
// package, re-applying the recorded check version.
func VerifyPackage(fsys fs.FS) (*Verification, error) {
	raw, err := fs.ReadFile(fsys, "manifest.json")
	if err != nil {
		return nil, fmt.Errorf("read manifest.json: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("manifest.json is not valid: %w", err)
	}
	if m.Format != PackageFormat {
		return nil, fmt.Errorf("package format %q is not %q", m.Format, PackageFormat)
	}
	sum := sha256.Sum256(raw)
	v := &Verification{ManifestSHA256: hex.EncodeToString(sum[:]), PeriodFrom: m.PeriodFrom, PeriodTo: m.PeriodTo, Files: len(m.Files)}
	problem := func(format string, args ...any) { v.Problems = append(v.Problems, fmt.Sprintf(format, args...)) }

	listed := map[string]bool{"manifest.json": true}
	content := map[string][]byte{}
	for _, f := range m.Files {
		listed[f.Path] = true
		if !fs.ValidPath(f.Path) {
			problem("%s: not a valid path", f.Path)
			continue
		}
		data, err := fs.ReadFile(fsys, f.Path)
		if err != nil {
			problem("%s: listed in the manifest but missing", f.Path)
			continue
		}
		got := sha256.Sum256(data)
		if hex.EncodeToString(got[:]) != f.SHA256 || int64(len(data)) != f.Size {
			problem("%s: content does not match the manifest", f.Path)
			continue
		}
		if name, ok := strings.CutPrefix(f.Path, "evidence/"); ok && name != f.SHA256 {
			problem("%s: evidence is not filed under the hash of its bytes", f.Path)
		}
		content[f.Path] = data
	}
	err = fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && !listed[path] {
			problem("%s: present but not listed in the manifest", path)
		}
		return err
	})
	if err != nil {
		return nil, err
	}

	var evaluations []store.EvaluationRow
	if data, ok := content["evaluations.json"]; ok {
		if err := json.Unmarshal(data, &evaluations); err != nil {
			problem("evaluations.json: not valid: %v", err)
		}
	}
	v.Evaluations = len(evaluations)
	for _, e := range evaluations {
		if mismatch := reproduce(e, func(sha string) ([]byte, error) {
			data, ok := content["evidence/"+sha]
			if !ok {
				return nil, errors.New("its evidence is not in the package")
			}
			return data, nil
		}); mismatch != "" {
			problem("evaluation %d (%s v%s): %s", e.EvaluationID, e.CheckKey, e.CheckVersion, mismatch)
			continue
		}
		v.Reproduced++
	}
	return v, nil
}

// reproduce re-applies the recorded check version to the stored evidence
// and returns "" when the result and explanation match what was recorded.
func reproduce(e store.EvaluationRow, evidence func(sha string) ([]byte, error)) string {
	c, ok := check.Lookup(e.CheckKey, e.CheckVersion)
	if !ok || c.Eval == nil {
		return "this build does not have that check version"
	}
	payload, err := evidence(e.PayloadSHA256)
	if err != nil {
		return err.Error()
	}
	result, explanation, err := c.Eval(check.Input{Payload: payload, AsOf: e.AsOf})
	switch {
	case err != nil:
		return "the check could not read the evidence: " + err.Error()
	case string(result) != e.Result:
		return fmt.Sprintf("recorded %s, reproduced %s", e.Result, result)
	case explanation != e.Explanation:
		return "the result matches but the explanation differs"
	}
	return ""
}

// Reproduction is the outcome of re-running every stored evaluation.
type Reproduction struct {
	Evaluations int
	Reproduced  int
	Mismatches  []string
}

// Reproduce re-applies each stored evaluation's recorded check version to
// its stored evidence and reports any that no longer gives the recorded
// result. It writes nothing.
func (s *Service) Reproduce(ctx context.Context, actor authz.Actor) (*Reproduction, error) {
	if err := authz.Can(actor, authz.View, authz.Resource{}); err != nil {
		return nil, err
	}
	evals, err := s.Store.AllEvaluations(ctx)
	if err != nil {
		return nil, err
	}
	out := &Reproduction{Evaluations: len(evals)}
	cache := map[string][]byte{}
	for _, e := range evals {
		mismatch := reproduce(e, func(sha string) ([]byte, error) {
			if data, ok := cache[sha]; ok {
				return data, nil
			}
			data, err := s.Evidence.Get(ctx, sha)
			if err == nil {
				cache[sha] = data
			}
			return data, err
		})
		if mismatch != "" {
			out.Mismatches = append(out.Mismatches, fmt.Sprintf("evaluation %d (%s v%s on observation %d): %s",
				e.EvaluationID, e.CheckKey, e.CheckVersion, e.ObservationID, mismatch))
			continue
		}
		out.Reproduced++
	}
	return out, nil
}

// zipFS opens a zip archive held in memory as a file system.
func zipFS(data []byte) (fs.FS, error) {
	return zip.NewReader(bytes.NewReader(data), int64(len(data)))
}

// OpenPackage opens a review package at path, which is a directory or a
// zip archive.
func OpenPackage(path string) (fs.FS, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return os.DirFS(path), nil
	}
	data, err := os.ReadFile(path) //nolint:gosec // the caller names the package to open
	if err != nil {
		return nil, err
	}
	return zipFS(data)
}
