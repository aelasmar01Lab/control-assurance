package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	const broken = "../../internal/pack/testdata/broken/duplicate-id.yaml"
	const valid = "../../internal/pack/testdata/valid.yaml"

	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout []string
		wantStderr string
	}{
		{"no args prints usage", nil, 2, nil, "Usage:"},
		{"version", []string{"version"}, 0, []string{"dev\n"}, ""},
		{"help", []string{"help"}, 0, []string{"Usage:"}, ""},
		{"users needs a subcommand", []string{"users"}, 2, nil, "users seed"},
		{"collect needs an integration", []string{"collect"}, 2, nil, "collect github"},
		{"collect rejects a bad repository name", []string{"collect", "github", "not-a-repo"}, 2, nil, "owner/name"},
		{"findings needs list", []string{"findings"}, 2, nil, "findings list"},
		{"checks guide", []string{"checks", "guide"}, 0, []string{"# Check guide", "## GH-01 (version 1)", "## GH-02 (version 1)", "## REC-01 (version 1)"}, ""},
		{"unknown command", []string{"bogus"}, 2, nil, "unknown command"},
		{
			"requirements list shows the catalog and its source hash",
			[]string{"requirements", "list"}, 0,
			[]string{
				"Minimum Viable Secure Product v3.0-20231109",
				"source sha256: ec4081ae8834ef61d8112c3af4bd184588c9d8d4e39fccd58a6dff2673154c04",
				"1.1", "4.4", "Backup and disaster recovery",
				"25 requirements",
			}, "",
		},
		{"requirements without list", []string{"requirements"}, 2, nil, "requirements list"},
		{"built-in packs validate", []string{"packs", "validate"}, 0, []string{"ok  mvsp v3.0-20231109 (25 requirements)"}, ""},
		{"valid pack file", []string{"packs", "validate", valid}, 0, []string{"ok  " + valid}, ""},
		{"broken pack file fails", []string{"packs", "validate", valid, broken}, 1, []string{"FAIL " + broken}, "1 of 2 pack files are invalid"},
		{"missing pack file fails", []string{"packs", "validate", "does-not-exist.yaml"}, 1, []string{"FAIL"}, "1 of 1"},
		{"migrate needs a subcommand", []string{"migrate"}, 2, nil, "migrate up"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run(context.Background(), tt.args, &stdout, &stderr); got != tt.wantCode {
				t.Errorf("exit code = %d, want %d (stderr: %s)", got, tt.wantCode, stderr.String())
			}
			for _, want := range tt.wantStdout {
				if !strings.Contains(stdout.String(), want) {
					t.Errorf("stdout = %q, want it to contain %q", stdout.String(), want)
				}
			}
			if !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tt.wantStderr)
			}
		})
	}
}

func TestMigrateRequiresDatabaseURL(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	var stdout, stderr bytes.Buffer
	if got := run(context.Background(), []string{"migrate", "up"}, &stdout, &stderr); got != 1 {
		t.Errorf("exit code = %d, want 1", got)
	}
	if !strings.Contains(stderr.String(), "DATABASE_URL is not set") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

const reviewPack = `
framework:
  key: fixture
  title: Fixture Framework
  version: v1
  text_rights: own_composition
  license: Synthetic test data
  source:
    kind: document
    retrieved: "2026-01-01"
requirements:
  - {id: "R1", group: "One", title: "First"}
  - {id: "R2", group: "One", title: "Second"}
`

const reviewControl = `key: logging-trail
title: Account activity trail
statement: A trail records management activity in the account.
risk: Actions in the account leave no record.
owner_role: control-owner
type: automated
checks: [AWS-03]
evidence_expectation: Trail descriptions, collected every 48 hours.
freshness_hours: 48
review:
  status: draft
  drafted_by: agent
  reviewed_by: ""
  reviewed_on: ""
  content_sha256: ""
`

const reviewMappings = `framework: fixture
version: v1
mappings:
  - control: logging-trail
    requirement: "R1"
    strength: partial
    rationale: A trail is one record R1 asks for.
    limitation: R1 also asks for application logs.
    basis: own_analysis
    review: {status: draft, drafted_by: agent, reviewed_by: "", reviewed_on: "", content_sha256: ""}
`

const reviewTracking = `framework: fixture
version: v1
entries:
  - requirement: "R2"
    status: not_implemented
    owner_role: control-owner
    applicability: Applicable.
    evidence_expectation: A record.
    rationale: Nothing addresses it.
    reviewer_note: Is this in scope?
    review: {status: draft, drafted_by: agent, reviewed_by: "", reviewed_on: "", content_sha256: ""}
`

// reviewRoot builds a small content root on disk: synthetic controls and a
// synthetic framework, with the real schemas.
func reviewRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write := func(name, data string) {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil { //nolint:gosec // under the test's temporary directory
			t.Fatal(err)
		}
	}
	for _, schema := range []string{"controls/control.schema.json", "mappings/mapping.schema.json", "tracking/tracking.schema.json"} {
		data, err := os.ReadFile("../../" + schema) //nolint:gosec // a fixed list of schema files
		if err != nil {
			t.Fatal(err)
		}
		write(schema, string(data))
	}
	write("packs/fixture/v1.yaml", reviewPack)
	write("controls/logging/logging-trail.yaml", reviewControl)
	write("mappings/fixture.yaml", reviewMappings)
	write("tracking/fixture.yaml", reviewTracking)
	write("docs/review-queue.md", "stale\n")
	write("docs/controls.md", "stale\n")
	return root
}

// The whole edit-and-sign contract from the command line: validate, sign,
// see it reviewed, edit it, and have verification fail until it is signed
// again or set back to draft.
func TestReviewCommands(t *testing.T) {
	root := reviewRoot(t)
	controlFile := filepath.Join(root, "controls", "logging", "logging-trail.yaml")
	cca := func(wantCode int, args ...string) string {
		t.Helper()
		var stdout, stderr bytes.Buffer
		if got := run(context.Background(), append(args, "--root", root), &stdout, &stderr); got != wantCode {
			t.Fatalf("cca %v = %d, want %d\nstdout: %s\nstderr: %s", args, got, wantCode, stdout.String(), stderr.String())
		}
		return stdout.String() + stderr.String()
	}
	contains := func(out string, wants ...string) {
		t.Helper()
		for _, want := range wants {
			if !strings.Contains(out, want) {
				t.Errorf("output lacks %q:\n%s", want, out)
			}
		}
	}

	contains(cca(0, "content", "validate"), "ok  1 controls, 1 mappings, 1 tracking entries")
	contains(cca(0, "review", "status"), "0 reviewed, 3 waiting", "(1 blocked by a reviewer note)")
	contains(cca(0, "review", "verify"), "0 reviewed, 3 draft")

	// Sign the control. The generated documents are rebuilt with it.
	contains(cca(0, "review", "sign", controlFile), "logging-trail: signed as ali", "rebuilt docs/review-queue.md", "rebuilt docs/controls.md")
	guide, err := os.ReadFile(filepath.Join(root, "docs", "controls.md")) //nolint:gosec // a file this test wrote
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(guide), "| Review | **reviewed by ali on ") {
		t.Errorf("the rebuilt guide does not show the control as reviewed:\n%s", guide)
	}
	contains(cca(0, "review", "status"), "1 reviewed, 2 waiting")
	contains(cca(0, "review", "verify"), "1 reviewed, 2 draft")

	// A mapping, by name and under another reviewer's name.
	contains(cca(0, "review", "sign", filepath.Join(root, "mappings", "fixture.yaml"), "--requirement", "R1", "--as", "sam"), "logging-trail -> R1: signed as sam")
	// Selecting nothing is refused, and so is an entry with an open note.
	contains(cca(1, "review", "sign", filepath.Join(root, "mappings", "fixture.yaml")), "say which mappings")
	contains(cca(1, "review", "sign", filepath.Join(root, "tracking", "fixture.yaml"), "--all"), "open reviewer_note")

	// Edit the signed control: verification fails, and says who signed what.
	data, err := os.ReadFile(controlFile) //nolint:gosec // a file this test wrote
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(data), "records management activity", "records all activity", 1)
	if err := os.WriteFile(controlFile, []byte(edited), 0o600); err != nil { //nolint:gosec // a file this test wrote
		t.Fatal(err)
	}
	contains(cca(1, "review", "verify"), "FAIL controls/logging/logging-trail.yaml: it was edited after ali reviewed it")
	contains(cca(1, "content", "validate"), "edited after ali reviewed it")

	// Setting it back to draft settles it.
	contains(cca(0, "review", "unsign", controlFile), "set back to draft")
	contains(cca(0, "review", "verify"), "1 reviewed, 2 draft")

	// A file that is not valid is not signed.
	if err := os.WriteFile(controlFile, []byte(strings.Replace(edited, "checks: [AWS-03]", "checks: [AWS-99]", 1)), 0o600); err != nil { //nolint:gosec // a file this test wrote
		t.Fatal(err)
	}
	contains(cca(1, "review", "sign", controlFile), "nothing in it was signed", `check "AWS-99" does not exist`)
}
