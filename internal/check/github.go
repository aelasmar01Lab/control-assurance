package check

import (
	"encoding/json"
	"fmt"
	"strings"

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

func evalGH01(payload []byte) (Result, string, error) {
	b, err := decodeBranchRules(payload)
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

func evalGH02(payload []byte) (Result, string, error) {
	b, err := decodeBranchRules(payload)
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
