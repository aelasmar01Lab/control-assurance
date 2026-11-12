package check

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/aelasmar01Lab/control-assurance/internal/github"
)

func rule(typ, params string) github.Rule {
	return github.Rule{Type: typ, RulesetID: 7, RulesetSource: "lab-org/lab-repo", RulesetSourceType: "Repository", Parameters: json.RawMessage(params)}
}

func payload(t *testing.T, protected, complete bool, rules ...github.Rule) []byte {
	t.Helper()
	b := github.BranchRules{
		Repository: "lab-org/lab-repo", DefaultBranch: "main",
		BranchProtected: protected, RulesComplete: complete, Rules: rules,
	}
	out, err := b.Payload()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestGitHubChecks(t *testing.T) {
	review1 := rule("pull_request", `{"required_approving_review_count":1}`)
	review0 := rule("pull_request", `{"required_approving_review_count":0}`)
	status := rule("required_status_checks", `{"required_status_checks":[{"context":"ci"},{"context":"lint"}]}`)
	statusEmpty := rule("required_status_checks", `{"required_status_checks":[]}`)
	other := rule("deletion", ``)

	tests := []struct {
		name        string
		key         string
		payload     []byte
		want        Result
		wantExplain string
	}{
		{"GH-01 pass", "GH-01", payload(t, true, true, review1, status), Pass, "requires 1 approving review"},
		{"GH-01 pass states the bypass limit", "GH-01", payload(t, true, true, review1), Pass, "Bypass actors are not read"},
		{"GH-01 zero approvals is a fail", "GH-01", payload(t, true, true, review0), Fail, "No active rule"},
		{"GH-01 no rules, unprotected", "GH-01", payload(t, false, true), Fail, "No active rule"},
		{"GH-01 other rules only", "GH-01", payload(t, true, true, status, other), Fail, "No active rule"},
		{"GH-01 protected but nothing visible", "GH-01", payload(t, true, true), NotEvaluated, "no rule is visible"},
		{"GH-01 truncated listing without the rule", "GH-01", payload(t, true, false, other), NotEvaluated, "Incomplete coverage"},
		{"GH-01 truncated listing, nothing read", "GH-01", payload(t, false, false), NotEvaluated, "Incomplete coverage"},
		{"GH-01 truncated listing that includes the rule", "GH-01", payload(t, true, false, review1), Pass, "requires 1 approving review"},

		{"GH-02 pass names the checks", "GH-02", payload(t, true, true, review1, status), Pass, "ci, lint"},
		{"GH-02 rule with no checks is a fail", "GH-02", payload(t, true, true, statusEmpty), Fail, "No active rule"},
		{"GH-02 no rules, unprotected", "GH-02", payload(t, false, true), Fail, "No active rule"},
		{"GH-02 protected but nothing visible", "GH-02", payload(t, true, true), NotEvaluated, "no rule is visible"},
		{"GH-02 truncated listing without the rule", "GH-02", payload(t, true, false, review1), NotEvaluated, "Incomplete coverage"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, ok := Lookup(tt.key, "1")
			if !ok {
				t.Fatalf("check %s version 1 not registered", tt.key)
			}
			got, explanation, err := c.Eval(tt.payload)
			if err != nil {
				t.Fatalf("Eval: %v", err)
			}
			if got != tt.want {
				t.Errorf("result = %s, want %s (%s)", got, tt.want, explanation)
			}
			if !strings.Contains(explanation, tt.wantExplain) {
				t.Errorf("explanation = %q, want it to contain %q", explanation, tt.wantExplain)
			}
		})
	}
}

func TestUnreadablePayloadIsAnErrorNotAResult(t *testing.T) {
	for _, c := range Automated() {
		for _, bad := range []string{``, `not json`, `{}`} {
			if result, _, err := c.Eval([]byte(bad)); err == nil {
				t.Errorf("%s: Eval(%q) = %s, want an error", c.Key, bad, result)
			}
		}
	}
}

func TestRegistry(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range All() {
		id := c.Key + "@" + c.Version
		if seen[id] {
			t.Errorf("%s registered twice", id)
		}
		seen[id] = true
		for name, v := range map[string]string{
			"Assertion": c.Assertion, "Source": c.Source, "Permission": c.Permission,
			"Establishes": c.Establishes, "DoesNotEstablish": c.DoesNotEstablish,
			"Control": c.Control, "Mapping": c.Mapping, "ObservationKind": c.ObservationKind,
		} {
			if v == "" {
				t.Errorf("%s: %s is empty", id, name)
			}
		}
		if (c.Eval == nil) != c.Manual {
			t.Errorf("%s: an automated check needs Eval and a manual check must not have one", id)
		}
	}
}

// The committed guide must match the definitions the evaluator runs.
func TestGuideIsInSync(t *testing.T) {
	const path = "../../docs/checks.md"
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (regenerate with `make guide`)", path, err)
	}
	if string(onDisk) != Guide() {
		t.Errorf("%s is out of date; regenerate with `make guide`", path)
	}
}
