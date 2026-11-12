package main

import (
	"bytes"
	"context"
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
		{"unimplemented command fails", []string{"export"}, 1, nil, "not implemented"},
		{"collect needs an integration", []string{"collect"}, 2, nil, "collect github"},
		{"collect rejects a bad repository name", []string{"collect", "github", "not-a-repo"}, 2, nil, "owner/name"},
		{"findings needs list", []string{"findings"}, 2, nil, "findings list"},
		{"checks guide", []string{"checks", "guide"}, 0, []string{"# Check guide", "## GH-01 (version 1)", "## GH-02 (version 1)"}, ""},
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
