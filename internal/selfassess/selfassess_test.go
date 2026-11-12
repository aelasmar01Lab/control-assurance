package selfassess

import (
	"os"
	"strings"
	"testing"

	"github.com/aelasmar01Lab/control-assurance/internal/pack"
	"github.com/aelasmar01Lab/control-assurance/packs"
)

func mvsp(t *testing.T) *pack.Pack {
	t.Helper()
	all, err := pack.LoadFS(packs.FS)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range all {
		if p.Framework.Key == "mvsp" {
			return p
		}
	}
	t.Fatal("no mvsp pack")
	return nil
}

func TestEveryRequirementIsAssessedOnce(t *testing.T) {
	p := mvsp(t)
	seen := map[string]int{}
	for _, r := range Rows {
		seen[r.Requirement]++
		if strings.TrimSpace(r.Basis) == "" {
			t.Errorf("%s has no basis", r.Requirement)
		}
	}
	for _, r := range p.Requirements {
		if seen[r.ID] != 1 {
			t.Errorf("requirement %s is assessed %d times, want once", r.ID, seen[r.ID])
		}
		delete(seen, r.ID)
	}
	for id := range seen {
		t.Errorf("row for unknown requirement %s", id)
	}
	// The rows the plan expects to be honest about.
	for _, id := range []string{"2.1", "1.4"} {
		for _, r := range Rows {
			if r.Requirement == id && r.Status != NotMet {
				t.Errorf("%s is %s, want Not met", id, r.Status)
			}
		}
	}
}

func TestSelfAssessmentIsInSync(t *testing.T) {
	const path = "../../docs/self-assessment.md"
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (regenerate with `make guide`)", path, err)
	}
	if string(onDisk) != Markdown(mvsp(t)) {
		t.Errorf("%s is out of date; regenerate with `make guide`", path)
	}
}
