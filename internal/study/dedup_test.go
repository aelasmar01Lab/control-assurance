package study

import (
	"os"
	"strings"
	"testing"

	"github.com/aelasmar01Lab/control-assurance/internal/aws"
	"github.com/aelasmar01Lab/control-assurance/internal/github"
)

// small is a dataset small enough to run in every test run.
var small = Dataset{
	Seed: 7, Days: 30,
	Repositories: 6, RuleChangeChance: 0.05, ReorderChance: 0.30,
	BusyAccounts: 1, QuietAccounts: 2, UsersPerAcct: 6, QuietUseChance: 0.10,
}

func TestStudy(t *testing.T) {
	r, err := Run(small, t.TempDir())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, k := range Kinds {
		none, raw, norm := r.ByKind[NoDedup][k], r.ByKind[RawHash][k], r.ByKind[NormalizedHash][k]
		if none.Payloads != none.Observations {
			t.Errorf("%s: no deduplication stored %d payloads for %d observations", k, none.Payloads, none.Observations)
		}
		if raw.Payloads > none.Payloads || norm.Payloads > raw.Payloads {
			t.Errorf("%s: payloads none %d, raw %d, normalized %d; each should be no more than the last", k, none.Payloads, raw.Payloads, norm.Payloads)
		}
		// Done-when: the reproduction check holds for every strategy.
		for _, s := range Strategies {
			if m := r.ByKind[s][k]; m.Reproduced != m.Observations || m.Observations == 0 {
				t.Errorf("%s under %s: %d of %d evaluations reproduced", k, s, m.Reproduced, m.Observations)
			}
		}
	}
	// Normalizing removes reordering, so it stores fewer rule payloads
	// than hashing the raw bytes; it cannot remove real activity.
	rules := github.BranchRulesKind
	if r.ByKind[NormalizedHash][rules].Payloads >= r.ByKind[RawHash][rules].Payloads {
		t.Errorf("branch rules: normalized %d payloads, raw %d; want fewer", r.ByKind[NormalizedHash][rules].Payloads, r.ByKind[RawHash][rules].Payloads)
	}
	creds := aws.IAMCredentialsKind
	if r.ByKind[NormalizedHash][creds].Payloads != r.ByKind[RawHash][creds].Payloads {
		t.Errorf("IAM credentials: normalized %d payloads, raw %d; want the same", r.ByKind[NormalizedHash][creds].Payloads, r.ByKind[RawHash][creds].Payloads)
	}
	if r.ByKind[NormalizedHash][creds].Bytes >= r.ByKind[RawHash][creds].Bytes {
		t.Error("IAM credentials: dropping columns did not reduce bytes")
	}

	// The same dataset gives the same counts and bytes every time.
	again, err := Run(small, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if r.Fingerprint() != again.Fingerprint() {
		t.Errorf("two runs of one dataset differ: %s and %s", r.Fingerprint(), again.Fingerprint())
	}
	other := small
	other.Seed++
	if different, _ := Run(other, t.TempDir()); different != nil && different.Fingerprint() == r.Fingerprint() {
		t.Error("a different seed gave the same fingerprint")
	}

	report := r.Markdown("synthetic hardware")
	for _, want := range []string{"password_next_rotation", "access_key_1_last_used_region", "Drops no field", "synthetic hardware", r.Fingerprint()} {
		if !strings.Contains(report, want) {
			t.Errorf("the report does not mention %q", want)
		}
	}
}

// The committed case study must come from the dataset and harness in this
// commit. Only the machine-independent part is compared.
func TestPublishedStudyMatchesTheHarness(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the full dataset")
	}
	const path = "../../docs/dedup-study.md"
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (regenerate with `make study`)", path, err)
	}
	r, err := Run(Default, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(onDisk), "`"+r.Fingerprint()+"`") {
		t.Errorf("%s does not carry fingerprint %s; regenerate with `make study`", path, r.Fingerprint())
	}
}
