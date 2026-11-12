package check

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/aelasmar01Lab/control-assurance/internal/github"
)

const (
	rulesSource     = "GitHub REST: `GET /repos/{owner}/{repo}/rules/branches/{branch}` (active rules only), plus the repository and branch records"
	rulesPermission = "Repository metadata: read"
	bypassLimit     = "Bypass actors are not read, so who may skip this rule is unknown."
	classicLimit    = "Classic branch protection is not read."
)

var gh01 = Check{
	Key:              "GH-01",
	Version:          "1",
	ObservationKind:  github.BranchRulesKind,
	Assertion:        "An active rule on the default branch requires at least one approving review.",
	Source:           rulesSource,
	Permission:       rulesPermission,
	Establishes:      "The rule was active on that branch at collection time.",
	DoesNotEstablish: "That past changes were reviewed, who may bypass the rule, or anything about classic branch protection.",
	Control:          "Change management",
	Mapping:          "MVSP 3.5, supporting. Required review is not an MVSP requirement; it supports the internal control.",
	Eval:             evalGH01,
}

var gh02 = Check{
	Key:              "GH-02",
	Version:          "1",
	ObservationKind:  github.BranchRulesKind,
	Assertion:        "An active rule on the default branch requires named status checks.",
	Source:           rulesSource,
	Permission:       rulesPermission,
	Establishes:      "Named checks must pass before merge, as of collection time.",
	DoesNotEstablish: "That those checks test anything meaningful, or who may bypass the rule.",
	Control:          "Change management",
	Mapping:          "MVSP 3.5, supporting.",
	Eval:             evalGH02,
}

func decodeBranchRules(payload []byte) (*github.BranchRules, error) {
	var b github.BranchRules
	if err := json.Unmarshal(payload, &b); err != nil {
		return nil, fmt.Errorf("decode %s payload: %w", github.BranchRulesKind, err)
	}
	if b.Repository == "" || b.DefaultBranch == "" {
		return nil, fmt.Errorf("%s payload has no repository or default branch", github.BranchRulesKind)
	}
	return &b, nil
}

// noQualifyingRule decides between fail and not_evaluated when no rule
// satisfied the assertion. A missing rule is only a fail when the listing is
// known to be complete and nothing suggests protection this collector cannot see.
func noQualifyingRule(b *github.BranchRules, what string) (Result, string, error) {
	switch {
	case !b.RulesComplete:
		return NotEvaluated, fmt.Sprintf(
			"Incomplete coverage: the rule listing for %s was truncated after %d rules, and none of the rules read %s. "+
				"A qualifying rule may exist among those not read.",
			b.DefaultBranch, len(b.Rules), what), nil
	case b.BranchProtected && len(b.Rules) == 0:
		return NotEvaluated, fmt.Sprintf(
			"GitHub reports %s as protected, but no rule is visible to this credential. %s",
			b.DefaultBranch, classicLimit), nil
	default:
		return Fail, fmt.Sprintf(
			"No active rule on %s %s (%d active rules read, listing complete). %s",
			b.DefaultBranch, what, len(b.Rules), classicLimit), nil
	}
}

func evalGH01(in Input) (Result, string, error) {
	b, err := decodeBranchRules(in.Payload)
	if err != nil {
		return "", "", err
	}
	for _, r := range b.Rules {
		if r.Type != "pull_request" {
			continue
		}
		var p struct {
			Approvals int `json:"required_approving_review_count"`
		}
		if err := json.Unmarshal(r.Parameters, &p); err != nil {
			return "", "", fmt.Errorf("decode pull_request rule parameters: %w", err)
		}
		if p.Approvals >= 1 {
			return Pass, fmt.Sprintf(
				"Ruleset %d (%s) is active on %s and requires %d approving review(s). %s",
				r.RulesetID, r.RulesetSource, b.DefaultBranch, p.Approvals, bypassLimit), nil
		}
	}
	return noQualifyingRule(b, "requires an approving review")
}

func evalGH02(in Input) (Result, string, error) {
	b, err := decodeBranchRules(in.Payload)
	if err != nil {
		return "", "", err
	}
	for _, r := range b.Rules {
		if r.Type != "required_status_checks" {
			continue
		}
		var p struct {
			Checks []struct {
				Context string `json:"context"`
			} `json:"required_status_checks"`
		}
		if err := json.Unmarshal(r.Parameters, &p); err != nil {
			return "", "", fmt.Errorf("decode required_status_checks rule parameters: %w", err)
		}
		var names []string
		for _, c := range p.Checks {
			if c.Context != "" {
				names = append(names, c.Context)
			}
		}
		if len(names) > 0 {
			return Pass, fmt.Sprintf(
				"Ruleset %d (%s) is active on %s and requires these status checks: %s. %s",
				r.RulesetID, r.RulesetSource, b.DefaultBranch, strings.Join(names, ", "), bypassLimit), nil
		}
	}
	return noQualifyingRule(b, "requires a named status check")
}

// The patch deadlines GH-03 applies. They are this project's policy choice,
// not a framework figure, and changing either means a new check version.
const (
	deadlineHigh   = 30 * 24 * time.Hour // high and critical
	deadlineMedium = 90 * 24 * time.Hour // medium
)

var gh03 = Check{
	Key:              "GH-03",
	Version:          "1",
	ObservationKind:  github.AlertsKind,
	Assertion:        "No open Dependabot alert of medium severity or higher is older than its patch deadline: 30 days for high and critical, 90 days for medium.",
	Source:           "GitHub REST: `GET /repos/{owner}/{repo}/dependabot/alerts?state=open`",
	Permission:       "Dependabot alerts: read",
	Establishes:      "Every open alert visible to the credential was within its deadline at collection time.",
	DoesNotEstablish: "Anything about vulnerabilities Dependabot does not know about, dismissed alerts, or low severity alerts. When alerts are turned off the result is not evaluated, never a count of zero.",
	Control:          "Dependency remediation",
	Mapping:          "MVSP 2.6 and 3.4, partial. The deadlines are a policy choice; MVSP 3.4 sets 90 days for application vulnerabilities.",
	Eval:             evalGH03,
}

func evalGH03(in Input) (Result, string, error) {
	var a github.Alerts
	if err := json.Unmarshal(in.Payload, &a); err != nil {
		return "", "", fmt.Errorf("decode %s payload: %w", github.AlertsKind, err)
	}
	if a.Repository == "" {
		return "", "", fmt.Errorf("%s payload has no repository", github.AlertsKind)
	}
	if !a.AlertsEnabled {
		return NotEvaluated, fmt.Sprintf(
			"Dependabot alerts are turned off for %s, so there is no alert list to judge. This is not a count of zero.",
			a.Repository), nil
	}

	var overdue []string
	judged, low := 0, 0
	for _, alert := range a.Alerts {
		deadline, label := deadlineHigh, "30"
		switch alert.Severity {
		case "low":
			low++
			continue
		case "medium":
			deadline, label = deadlineMedium, "90"
		case "high", "critical":
		default:
			// A severity this version does not know gets the shortest deadline.
			label = "30, severity not recognised"
		}
		judged++
		if age := in.AsOf.Sub(alert.CreatedAt); age > deadline {
			overdue = append(overdue, fmt.Sprintf("#%d %s in %s, open %d days (deadline %s)",
				alert.Number, alert.Severity, alert.Package, int(age.Hours()/24), label))
		}
	}
	switch {
	case len(overdue) > 0:
		shown := overdue
		if len(shown) > 5 {
			shown = shown[:5]
		}
		return Fail, fmt.Sprintf("%d open alert(s) on %s are past their patch deadline: %s.",
			len(overdue), a.Repository, strings.Join(shown, "; ")), nil
	case !a.AlertsComplete:
		return NotEvaluated, fmt.Sprintf(
			"Incomplete coverage: the alert listing for %s was truncated after %d alerts, and none of those read is past its deadline. "+
				"An overdue alert may exist among those not read.", a.Repository, len(a.Alerts)), nil
	default:
		return Pass, fmt.Sprintf(
			"%d open alert(s) of medium severity or higher on %s, none past its deadline (30 days for high and critical, 90 for medium). "+
				"%d low severity alert(s) were not judged.", judged, a.Repository, low), nil
	}
}

var gh04 = Check{
	Key:              "GH-04",
	Version:          "1",
	ObservationKind:  github.SecurityPolicyKind,
	Assertion:        "The repository publishes a security policy file at a standard path on its default branch.",
	Source:           "GitHub REST: `GET /repos/{owner}/{repo}/contents/{path}` for `SECURITY.md`, `.github/SECURITY.md` and `docs/SECURITY.md`",
	Permission:       "Repository contents: read",
	Establishes:      "A non-empty policy file existed at a standard path at collection time.",
	DoesNotEstablish: "Anything about the file's content, any safe-harbour wording, or that reports are triaged. A default policy inherited from an organisation's `.github` repository is not read.",
	Control:          "Vulnerability disclosure",
	Mapping:          "MVSP 1.1, partial.",
	Eval:             evalGH04,
}

func evalGH04(in Input) (Result, string, error) {
	var p github.SecurityPolicy
	if err := json.Unmarshal(in.Payload, &p); err != nil {
		return "", "", fmt.Errorf("decode %s payload: %w", github.SecurityPolicyKind, err)
	}
	if p.Repository == "" || len(p.PathsChecked) == 0 {
		return "", "", fmt.Errorf("%s payload has no repository or no paths", github.SecurityPolicyKind)
	}
	for _, f := range p.Found {
		if f.Size > 0 {
			return Pass, fmt.Sprintf("%s exists on %s of %s (%d bytes). Its content was not read.",
				f.Path, p.DefaultBranch, p.Repository, f.Size), nil
		}
	}
	empty := ""
	if len(p.Found) > 0 {
		empty = fmt.Sprintf(" %s exists but is empty.", p.Found[0].Path)
	}
	return Fail, fmt.Sprintf("No non-empty security policy file on %s of %s at any of: %s.%s A policy inherited from an organisation's .github repository is not read.",
		p.DefaultBranch, p.Repository, strings.Join(p.PathsChecked, ", "), empty), nil
}
