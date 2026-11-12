// Package selfassess holds this project's own MVSP self-assessment: what
// the application itself does and does not do against each requirement.
// It is about the software in this repository, not about the lab the
// software watches.
package selfassess

import (
	"fmt"
	"strings"

	"github.com/aelasmar01Lab/control-assurance/internal/pack"
)

// Status is how the application stands against one requirement.
type Status string

// The statuses. "Met" is used only where the basis can be checked in the
// repository.
const (
	Met           Status = "Met"
	Partly        Status = "Partly met"
	NotMet        Status = "Not met"
	NotApplicable Status = "Not applicable"
)

// Row is the assessment of one requirement.
type Row struct {
	Requirement string
	Status      Status
	// Basis says what the status rests on, and what is missing.
	Basis string
}

// AssessedOn is the date of this assessment.
const AssessedOn = "2026-11-12"

// Subject describes what was assessed.
const Subject = "The control-assurance application at the commit this file is in: a single binary and a PostgreSQL database, run locally by one person. It is not hosted, has no customers, and holds no production data."

// Rows is the assessment, one row per MVSP requirement.
var Rows = []Row{
	{"1.1", NotMet, "The repository publishes no vulnerability disclosure policy, safe harbour or contact, and has no triage procedure. The application's own GH-04 check would fail on this repository."},
	{"1.2", NotApplicable, "There are no customers and nothing is hosted for anyone to test. The source is public, so anyone may test a local copy."},
	{"1.3", Partly, "This document is the self-assessment, generated from `internal/selfassess`. It is the first one, so nothing yet shows it is repeated yearly."},
	{"1.4", NotMet, "No external penetration test has been performed."},
	{"1.5", NotMet, "There is no security training programme. The project has one maintainer."},
	{"1.6", NotMet, "No industry standard or legal obligation has been assessed against."},
	{"1.7", NotMet, "There is no incident handling process and no way to notify anyone of a breach."},
	{"1.8", NotApplicable, "The application holds no production data and controls no storage media."},
	{"2.1", NotMet, "Sign-in uses local accounts with argon2id password hashes. There is no single sign-on."},
	{"2.2", NotMet, "The site is served over plain HTTP on the loopback interface. There is no TLS, no redirect and no HSTS. It must not be exposed to a network as it is."},
	{"2.3", Partly, "Every response carries a restrictive Content-Security-Policy with `frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` and `Cache-Control: no-store`, and a test asserts them. Cookies are `HttpOnly` and `SameSite=Lax`; `Secure` is opt-in because there is no HTTPS."},
	{"2.4", NotMet, "Passwords are generated, not chosen, and hashed with argon2id. There is no self-service password change, no email verification, and no lockout or rate limit on sign-in, so brute-force protection is absent."},
	{"2.5", Met, "Pages are rendered with Go's `html/template`, which escapes output by context, and a test submits markup and asserts it is escaped. All SQL goes through `pgx` with bound parameters. Cross-origin form posts are refused by `net/http`'s cross-origin protection, with a test."},
	{"2.6", Partly, "Dependabot proposes dependency updates weekly, and `govulncheck` runs on every push and fails the build on a known vulnerability. There is no written patching schedule."},
	{"2.7", Partly, "Every write, export and package generation is recorded in an insert-only decision log with the user, the object, the reason and the time. Sign-in successes and failures are not logged, reads are not logged, and no IP address is recorded."},
	{"2.8", Partly, "In transit: calls to GitHub and AWS use TLS; the site itself and the local database connection do not. At rest: evidence in S3 is encrypted by the service's default; the local evidence directory and database rely on whatever the disk provides."},
	{"3.1", Met, "The data the application handles is listed in `docs/operations.md`, under \"Data handled\"."},
	{"3.2", NotMet, "There is no data flow diagram."},
	{"3.3", Partly, "Tests cover authorization bypass (every action against every role, and separation of duties), session handling, cross-site request forgery, output escaping, and rejection of evidence references that are not a SHA-256. There are no written development guidelines and no training."},
	{"3.4", NotMet, "There is no process for patching within 90 days and no security bulletins. Nothing has been reported to patch."},
	{"3.5", Partly, "Source is in git and every push is built and tested by CI. Credentials are kept out of the source: `.env` files are ignored and the collectors read tokens from the environment. No build provenance is generated, so SLSA Build Level 1 is not reached."},
	{"4.1", NotApplicable, "There are no facilities."},
	{"4.2", Partly, "Four roles are enforced below the HTTP layer, the auditor cannot write, and nobody can approve their own request. The AWS roles are read-only for collection and create-only for evidence. There is no access review and no deactivation of unused accounts."},
	{"4.3", NotApplicable, "The application holds no customer data. GitHub and AWS hold the repository and the lab account."},
	{"4.4", NotMet, "Nothing backs up the database or the local evidence directory, and no recovery has been tested."},
}

// Markdown renders the self-assessment against the given pack.
func Markdown(p *pack.Pack) string {
	rows := map[string]Row{}
	for _, r := range Rows {
		rows[r.Requirement] = r
	}
	count := map[Status]int{}
	var b strings.Builder
	b.WriteString("# MVSP self-assessment\n\n")
	b.WriteString("Generated by `cca self-assessment` from `internal/selfassess`. Do not edit by hand.\n\n")
	fmt.Fprintf(&b, "| | |\n| --- | --- |\n| Assessed | %s |\n| Framework | %s %s (%s) |\n| Source | %s at commit `%s` |\n| Assessed on | %s |\n| Assessed by | The maintainer. Nobody independent has reviewed it. |\n\n",
		Subject, p.Framework.Title, p.Framework.Version, p.Framework.License, p.Framework.Source.URL, p.Framework.Source.Commit, AssessedOn)
	b.WriteString("This is an assessment of the software, by its author. It is separate from what the software reports about the lab it watches. ")
	b.WriteString("\"Met\" is used only where the basis can be checked in this repository.\n\n")

	var table strings.Builder
	table.WriteString("| Requirement | Status | Basis |\n| --- | --- | --- |\n")
	for _, r := range p.Requirements {
		row, ok := rows[r.ID]
		if !ok {
			row = Row{r.ID, NotMet, "Not assessed."}
		}
		count[row.Status]++
		fmt.Fprintf(&table, "| %s %s | %s | %s |\n", r.ID, r.Title, row.Status, row.Basis)
	}
	fmt.Fprintf(&b, "Of %d requirements: %d met, %d partly met, %d not met, %d not applicable.\n\n",
		len(p.Requirements), count[Met], count[Partly], count[NotMet], count[NotApplicable])
	b.WriteString(table.String())
	b.WriteString("\n## Notes\n\n")
	b.WriteString("- MVSP 1.3 asks for the latest MVSP release. This assessment uses the pinned version above; whether a newer release exists has to be checked by hand.\n")
	b.WriteString("- The pinned upstream catalog file gives requirement 2.1 the statement text of requirement 1.1. Requirement 2.1 was assessed by its title, Single sign-on.\n")
	b.WriteString("- The largest gaps for anyone who wanted to host this: 2.1, 2.2 and 2.4 (sign-in and transport), 1.1 (no way to report a vulnerability), and 4.4 (no backup).\n")
	return b.String()
}
