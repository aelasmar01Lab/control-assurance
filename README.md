# control-assurance

A continuous control assurance application in Go: define controls, collect
observations from AWS and GitHub, evaluate versioned checks, track findings and
exceptions, and export a review package for a past period.

This README states only what is implemented.

**Who wrote what.** The framework packs, controls, mappings and tracking
entries in this repository are drafted by an AI agent and reviewed by the
maintainer. Each entry is a draft until the maintainer signs it, and the
product labels it either way wherever it appears.
[docs/review-queue.md](docs/review-queue.md) lists what has been reviewed
and what has not. None of it has been reviewed by an auditor.

## Try it

```sh
git clone https://github.com/aelasmar01Lab/control-assurance && cd control-assurance
make demo        # or: docker compose --profile demo up --build demo
```

That needs only Docker. It builds the binary, starts a throwaway database,
seeds twelve days of **synthetic** history and serves it at
<http://127.0.0.1:8080>. The terminal prints four sign-in names and their
demo passwords. Every page carries a banner saying the data is synthetic;
nothing is collected from a real system. If port 8080 is taken, set
`CCA_DEMO_PORT` and use that port instead of the one the terminal prints.
Stop it with Ctrl-C; `docker compose --profile demo down` removes it, and
the next start seeds the same history afresh.

The seeded history is the whole loop: checks fail and open findings, the
control owner requests exceptions, the reviewer approves them, a token is
rejected and a source has an outage (collection failures, not results), the
problems are fixed, the checks pass and the findings close. One exception
has lapsed and one check cannot be evaluated, so not everything is green.
[docs/walkthrough.md](docs/walkthrough.md) is a ten-minute tour, including
making a decision yourself and downloading a review package.

To run it against a real lab instead, see
[docs/operations.md](docs/operations.md).

## Status

| Area | Status |
| --- | --- |
| Repository layout, Go module, `cca` binary | Implemented |
| CI: tests with Postgres, lint, vulnerability scan, pack and content validation, review verification, migrations | Implemented |
| MVSP framework pack (25 requirements, pinned source), schema validation, database import | Implemented |
| Pack format that records text rights (full text, identifiers only, or written by this project), hierarchy, and profiles of another pack | Implemented; MVSP is the only pack |
| GitHub collector: branch rules, Dependabot alerts, security policy file; classified errors, pagination completeness | Implemented |
| AWS collector: IAM credential report, CloudTrail trails, Bedrock invocation logging; read-only assumed role | Implemented |
| Evidence store, content-addressed by SHA-256: local directory, or an S3 bucket with create-only writes under its own role | Implemented |
| Eight automated checks (GH-01 to GH-04, AWS-01 to AWS-04) and REC-01 (manual evidence), versioned, with stated limits | Implemented |
| Job queue in PostgreSQL, worker pool, daily schedule, retries per error class, recovery of abandoned runs | Implemented |
| Evaluations and findings, insert-only history | Implemented |
| Accounts, sessions and four roles; one permission function with matrix tests | Implemented |
| Manual evidence submission and review | Implemented |
| Exceptions with mandatory expiry, remediation notes, decision log | Implemented |
| Eight internal controls backed by checks or reviewed evidence, with derived state and a 48 hour evidence window | Implemented |
| Nineteen further controls in the access domain (the pilot), all drafts | Drafted. None has a check yet: the automated ones read *not evaluated*, the manual ones *needs attention* until evidence is submitted |
| NIST CSF 2.0 pack: 106 subcategories with NIST's text, imported from NIST's reference-data export by a script in `tools/import/nist-csf` | Implemented |
| NIST CSF 2.0 mappings | Pilot only: PR.AA (6 subcategories) is mapped or tracked. The other 100 subcategories are marked *not assessed*: nobody has looked at them, nothing is claimed about them, and they are not in the review queue |
| Controls, mappings and tracking entries as YAML files, validated against schemas and each other | Implemented |
| Two organizations, the real lab and a fictional demo company, each with a scope file listing the controls that do not apply to it | Implemented for the lab. The demo company has a scope file but no name yet, and the demo's seeded history is unchanged: two synthetic repositories and one account. Tracking entries are still about the lab only |
| Review contract: sign an entry, a signature covers its exact content, an edit after signing fails CI | Implemented |
| Content reviewed by the maintainer | See [docs/review-queue.md](docs/review-queue.md) for the current count |
| A record of every wording of every control that was loaded (control revisions), named in the review package | Implemented |
| Workspaces | Schema only: every organization table has a workspace, there is one, and nothing uses it yet |
| All 25 MVSP requirements, each covered in part by a control or tracked as manual, not implemented or out of scope with a reason | Implemented |
| Web interface: overview, frameworks and their requirements, findings, manual evidence, integration health, review package, decision log, review queue | Implemented |
| Fault table: every injected fault, its error class and retry behaviour, generated and tested | Implemented |
| Current-state JSON export | Implemented |
| Review package for a past period, with a manifest hash and an offline verifier | Implemented |
| Check versions: a new version adds evaluations beside the old; every stored evaluation can be re-run | Implemented |
| Deduplication case study on a documented synthetic dataset | Implemented |
| One-command seeded demo with labelled synthetic data | Implemented |
| This project's own MVSP self-assessment, generated | Implemented |
| Content reviewed by anyone other than the maintainer | Not started |
| Hosted demo, and a check of its own HTTPS and headers | Not started |
| SOC 2 pack | Blocked: see [BLOCKED.md](BLOCKED.md) |
| Every other framework | Not started |

## Documents

| Document | What it is |
| --- | --- |
| [docs/walkthrough.md](docs/walkthrough.md) | A ten-minute tour of the demo |
| [docs/controls.md](docs/controls.md) | Every control, its mappings and limits, and how each requirement is tracked, with what has been reviewed (generated) |
| [docs/review-queue.md](docs/review-queue.md) | What is waiting for the maintainer's review, and the command that signs each entry (generated) |
| [docs/authoring-rules.md](docs/authoring-rules.md) | The maintainer's rules for sourcing packs and writing controls and mappings, and which of them the tooling checks |
| [docs/drafting-log.md](docs/drafting-log.md) | What the agent drafted in each unit of work, from which sources, and what it is least sure of |
| [CLAUDE.md](CLAUDE.md) | The standing rules the agent works under |
| [BLOCKED.md](BLOCKED.md) | Frameworks the agent could not source, and what is needed for each |
| [docs/checks.md](docs/checks.md) | Each check: its assertion, source, and what a pass does and does not establish (generated) |
| [docs/permissions.md](docs/permissions.md) | Who may do what (generated) |
| [docs/faults.md](docs/faults.md) | Every injected fault, its error class and how it is retried (generated) |
| [docs/dedup-study.md](docs/dedup-study.md) | The deduplication case study (generated) |
| [docs/self-assessment.md](docs/self-assessment.md) | This project against MVSP, including what it does not meet (generated) |
| [docs/operations.md](docs/operations.md) | Running it against a real lab: processes, credentials, health, backup, data handled |
| [docs/decisions.md](docs/decisions.md) | Decision records: what was chosen and what was given up |

## The loop against a real lab

```sh
make db-up && make migrate && make build
export DATABASE_URL='postgres://cca:cca_local_only@127.0.0.1:5433/cca?sslmode=disable'

bin/cca users seed                      # four lab users; passwords are printed once
export CCA_USER=operator                # the user CLI commands act as

bin/cca packs load                      # import the MVSP catalog
bin/cca collect github owner/name       # collect from a repository now
AWS_PROFILE=cca-collector bin/cca collect aws   # collect from the account the credentials belong to
bin/cca evaluate                        # apply every check to the new evidence
bin/cca results                         # control states and current results
bin/cca findings list                   # findings, with exceptions and notes
bin/cca serve                           # the web interface at http://127.0.0.1:8080
```

To keep evidence current, run the worker beside the site:

```sh
AWS_PROFILE=cca-collector bin/cca worker   # collects each job daily, retries failures, evaluates
bin/cca worker --once                      # one pass, for cron
```

The first `collect` of a repository or account registers it as in scope.
After that the worker collects it on schedule, and the operator can queue
everything at once from the integration health page.

In the browser, with a failing check:

1. Sign in as `control-owner`: add a remediation note to the finding and
   request an exception with a justification and an expiry date. The control
   still reads *needs attention*; a request alone changes nothing.
2. Sign in as `reviewer`: approve the request. The control reads *accepted
   risk*, and the check still reads *fail*.
3. Fix the branch rule, then collect and evaluate. The check passes, the
   finding is closed by that evaluation, and the control reads *supported*.
4. Sign in as `auditor`: every page and the export are readable, and no form
   is offered. A hand-built write is refused with 403.

Every earlier step stays visible: both evaluations, the note, the request,
the approval, and a decision log entry for each.

What the results mean:

- `pass`, `fail` and `not_evaluated` each describe one check version applied
  to one stored observation. The [check guide](docs/checks.md) says what a
  pass does and does not establish.
- A collection failure is none of the three. It is recorded on the run with
  an error class and changes no result. The [fault table](docs/faults.md)
  lists every fault the tests inject, the class each ends in, and how each
  class is retried.
- A listing that was not read to the end is `incomplete`; a check that did
  not find what it looks for in it returns `not_evaluated`, not `fail`.
- Dependabot alerts turned off is `not_evaluated`, never zero alerts.
- A check that measures an age measures it to the moment the evidence
  describes, not to the clock, so a stored evaluation gives the same answer
  whenever it is repeated.

## Collection jobs

A job is one kind of evidence from one resource, such as
`github.dependabot_alerts` from one repository. Each attempt is a row in
`collection_runs`: queued, running, then succeeded or failed.

- Workers claim queued attempts with `FOR UPDATE SKIP LOCKED`, so two
  workers never take the same one, and a job has at most one unfinished
  attempt, so asking twice queues once.
- A failed attempt is retried according to its error class. A retry is a new
  row that names the attempt it follows. Classes that need a person (`auth`,
  `permission`, `not_found`) are not retried; the next scheduled collection
  tries again.
- A claimed attempt carries a five minute lease. If its worker is killed,
  the next worker pass marks it `interrupted` and queues the retry.
- A finished attempt cannot be changed or deleted; a database trigger
  refuses it.

The integration health page shows, for each job, the newest evidence and
its age, the last attempt and anything waiting. A job with no new evidence
for 48 hours is stale, whatever later failed attempts say, and the controls
that rest on it become stale with it.

A control's state is derived on read and never stored. The first match wins:

| State | When |
| --- | --- |
| Not evaluated | No check for the control has produced a result |
| Needs attention | A current failure with no approved, unexpired exception; or manual evidence missing, rejected or awaiting review |
| Stale | The newest evidence is older than the control's window, or accepted manual evidence is past its validity date |
| Accepted risk | Every current failure is covered by an approved, unexpired exception |
| Not evaluated | A check's current result could not be determined |
| Supported | Every check passes on current evidence and manual evidence is accepted and valid |

*Supported* is always shown beside the assertions it rests on. Nothing in
the product is called compliant.

## Requirements

`cca requirements status`, or the Frameworks page, lists every requirement
of every pack. For MVSP that is all 25. Seven are covered in part by a control and take the worst
state among their controls; the best a requirement can read is *partly
evidenced*, because no mapping in this release is stronger than partial.
The other eighteen show how they are tracked: manually, not implemented, or
out of scope, each with a reason. None of those is a positive state, and
nothing is shown as met.

NIST CSF 2.0 is partway in. Its 106 subcategories are all listed, with
NIST's text. Only the six under PR.AA (identity management, authentication
and access control) have been assessed: four are mapped by draft controls,
and two are tracked with a reason. The other 100 read *not assessed*:
nobody has looked at them yet, so nothing is said about the lab and there
is nothing to review.

One thing in the catalog is wrong at the source: the pinned upstream file
gives requirement 2.1 (Single sign-on) the statement text of requirement
1.1. The pack keeps upstream's text unmodified, and the product shows a
note beside 2.1 saying so.

## Editing and reviewing content

Controls, mappings and tracking entries are files, one control per file:

| Path | Holds |
| --- | --- |
| `controls/<domain>/<key>.yaml` | One control: its statement, risk, checks, evidence expectation |
| `mappings/<framework>.yaml` | Every tie between a control and a requirement of that framework, with its strength, rationale and limitation |
| `tracking/<framework>.yaml` | Each requirement no control covers, and how it is tracked |
| `scope/<organization>.yaml` | One organization (`lab` or `demo`) and the controls that do not apply to it, each with a reason. A control not listed applies. An exclusion changes a state only once it is reviewed |

Each entry ends in a `review` block. To review one:

```sh
$EDITOR controls/logging/audit-logging.yaml   # change anything that is wrong
make content                                  # validate, rebuild docs/review-queue.md and docs/controls.md
go run ./cmd/cca review sign controls/logging/audit-logging.yaml
go run ./cmd/cca review sign mappings/mvsp.yaml --requirement 2.7   # or --control <key>, or --all
go run ./cmd/cca review sign scope/lab.yaml --control access-role-change
git commit -am "Review audit logging"
```

Signing sets the entry to `reviewed`, with the reviewer's name (`--as`,
default `ali`), the date, and a hash of the entry's content without its
review block. It changes those four values and nothing else in the file,
and rebuilds the two generated documents. It refuses an entry that still
has a `reviewer_note`, which is a doubt the agent recorded for the
reviewer.

A signature is of specific content. `cca review verify`, which CI runs,
recomputes every reviewed entry's hash; an entry edited after signing fails
until it is signed again or set back to draft (`cca review unsign`). How
the YAML is laid out does not matter; what it says does.

What validation enforces, beyond the schemas: every requirement of every
pack is mapped by a control or tracked, never both; a mapping that is not
direct states its limitation; a mapping derived through another framework
is at most supporting; a draft control may not use "compliant", "ensures",
"guarantees", "robust", "appropriate" or "as needed"; a title has at most
eight words. A direct mapping that is still a draft counts as partial in
every derived state.

The content is built into the binary, so the server shows an edit after it
is rebuilt and restarted (`make serve`). `cca content load` records each
control's wording in the database as a revision; the review package names
the wording that was in force at the end of its period, and says when a
control has been reworded since.

## History and the review package

```sh
bin/cca reproduce                                            # re-run every stored evaluation
bin/cca package --from 2026-11-01 --to 2026-11-08 --out review.zip
bin/cca package verify review.zip                            # needs no database
```

- **Check versions.** Changing a check means registering a new version. The
  evaluator applies the newest version of each check to new evidence, and
  to stored evidence it has not yet seen, which adds evaluations and
  rewrites none. Older versions stay in the binary so their evaluations can
  be re-run. `cca reproduce` re-applies each evaluation's recorded version
  to its stored evidence and reports any that no longer gives the recorded
  result and explanation.
- **Review package.** For a period that is over, the package holds the
  control states as they stood at its end, every run, observation and
  evaluation in it, the findings that were open with their exceptions and
  notes, the decision log, and the evidence files. `manifest.json` lists the
  SHA-256 of every file; the SHA-256 of the manifest identifies the package.
  The manifest records nothing about when or by whom it was generated, so
  the same period gives the same manifest whenever it is asked for. Each
  generation is written to the decision log with that hash.
- **Verification.** `cca package verify` recomputes every hash, reports
  files that are missing, changed or unlisted, and re-runs every evaluation
  in the package from the evidence in the package. It reads no database.
  A manifest hash you recorded when the package was made is what makes a
  later edit of both a file and the manifest detectable.

The [deduplication case study](docs/dedup-study.md) compares storing every
collection, hashing raw responses and hashing normalized payloads, on a
synthetic dataset. `make study` regenerates it.

## Roles

Four lab roles: operator, control owner, reviewer and auditor. The
[permission matrix](docs/permissions.md) is generated from the rules in
force. The auditor can read and export and cannot write. Nobody can review
their own evidence or approve their own exception request; the service
refuses it and so does a database constraint.

Limits of sign-in, stated plainly: local accounts only, no single sign-on, no
second factor, no lockout or rate limit, no self-service password change.
The CLI does not authenticate anyone; `CCA_USER` names the user whose role
applies. See [decisions 9 and 13](docs/decisions.md).

## Credentials

Source credentials are held by `cca collect` and `cca worker` only. The web
process (`cca serve`) holds none: its "queue collection" button adds rows
for a worker to pick up.

GitHub: `GITHUB_TOKEN` when set, otherwise the GitHub CLI's current login
(`gh auth token`). The collector only issues `GET` requests and needs read
access to repository metadata, contents and Dependabot alerts. A CLI login
is much broader than that; see [decision 7](docs/decisions.md).

Evidence in S3: set `CCA_EVIDENCE_S3_BUCKET` and `CCA_EVIDENCE_AWS_PROFILE`.
The profile is named explicitly and must differ from `AWS_PROFILE`. The
evidence role ([`deploy/aws/evidence-policy.json`](deploy/aws/evidence-policy.json))
may read objects under one prefix and create new ones; it cannot overwrite
or delete, and it cannot read the sources. The collector role cannot touch
the bucket. `cca evidence copy-to-s3` copies payloads already stored locally.

AWS collection: the SDK's standard credential chain, so `AWS_PROFILE` selects the
role and `AWS_REGION` or the profile selects the Region. The collector is
meant to run as a role with the seven read-only actions in
[`deploy/aws/collector-policy.json`](deploy/aws/collector-policy.json), plus
`sts:GetCallerIdentity`, which needs no grant. It refuses to file evidence
when the credentials belong to a different account from the one being
collected.

## Layout

| Path | Purpose |
| --- | --- |
| `cmd/cca` | The single binary's entry point |
| `internal/assurance` | The service layer: every entry point goes through it, and it checks permission first |
| `internal/authz` | Roles, actions and the one permission function |
| `internal/auth` | Password hashing (argon2id) |
| `controls/`, `mappings/`, `tracking/`, `scope/` | The content the maintainer edits (YAML) and its JSON Schemas, embedded in the binary |
| `internal/content` | Reads and validates those files; review signing, verification and the review queue |
| `internal/control` | Internal controls, built from the content files, and the derivation of their state |
| `internal/collect` | What collectors share: the snapshot and the classified error |
| `internal/github` | The only code that talks to GitHub; read-only |
| `internal/aws` | The only code that talks to AWS; read-only |
| `internal/check` | Versioned checks and the generated check guide |
| `internal/evidence` | Content-addressed evidence store: local directory and S3 |
| `internal/study` | The deduplication case study harness |
| `internal/demo` | The seeded demo: a synthetic history played against synthetic sources |
| `internal/selfassess` | This project's own MVSP self-assessment |
| `internal/store` | PostgreSQL access |
| `internal/web` | The web interface: sign-in, pages and forms; one stylesheet, no script, fonts served from the binary |
| `internal/pack` | Pack parsing and validation |
| `internal/db` | Migrations runner |
| `migrations/` | SQL migrations (goose format), embedded in the binary |
| `packs/` | Framework packs (YAML) and their JSON Schema, embedded in the binary |
| `tools/import/` | One script per imported framework, so an import can be repeated |
| `docs/` | Check guide, permission matrix, fault table and case study (all generated), and decision records |
| `deploy/aws` | IAM policies for the read-only collector role and the evidence store role |

## Development

Requires Go 1.27+ and Docker.

```sh
make db-up     # start Postgres on 127.0.0.1:5433
make migrate   # apply migrations
make test      # run tests; database tests use throwaway schemas, so run db-up first
make build     # build bin/cca
make lint      # needs golangci-lint v2
make vuln      # govulncheck
make study     # regenerate docs/dedup-study.md; needs no database
make demo      # the seeded demo, in Docker
make content   # after editing controls/, mappings/ or tracking/: validate, and rebuild the review queue and control guide
make guide     # regenerate the generated documents in docs/ after changing a check, permission, fault or retry policy
```

Tests use a synthetic GitHub API (`internal/github/githubtest`) and a
synthetic AWS account (`internal/aws/awstest`); no test calls GitHub or AWS. Without `CCA_TEST_DATABASE_URL` the database tests are skipped
locally and fail in CI.

## Framework content

`packs/mvsp/v3.0-20231109.yaml` holds the Minimum Viable Secure Product
requirement text, unmodified, from
[vendorsec/mvsp](https://github.com/vendorsec/mvsp) (CC0-1.0). The pack header
records the source commit, path, retrieval date and SHA-256 of the source file.

Every pack must satisfy `packs/pack.schema.json`. A pack states its rights
over the framework's text. `full` carries the publisher's titles and text
under a licence recorded in the header. `identifiers_only` carries
identifiers, hierarchy and a short label in this project's own words, and
the loader refuses one that has a title or text. `own_composition` is a
requirement list this project wrote. A baseline that selects from another
catalog is a profile: it lists identifiers and takes everything else from
its parent. An invalid pack fails the test suite and the pack validation
step in CI. Framework rows are immutable in the database once written.

## License

Apache-2.0. See [LICENSE](LICENSE).
