# control-assurance

A continuous control assurance application in Go: define controls, collect
observations from AWS and GitHub, evaluate versioned checks, track findings and
exceptions, and export a review package for a past period.

This README states only what is implemented.

## Status

| Area | Status |
| --- | --- |
| Repository layout, Go module, `cca` binary | Implemented |
| CI: tests with Postgres, lint, vulnerability scan, pack validation, migrations | Implemented |
| MVSP framework pack (25 requirements, pinned source), schema validation, database import | Implemented |
| GitHub collector: branch rules, Dependabot alerts, security policy file; classified errors, pagination completeness | Implemented |
| AWS collector: IAM credential report, CloudTrail trails, Bedrock invocation logging; read-only assumed role | Implemented |
| Evidence store, content-addressed by SHA-256: local directory, or an S3 bucket with create-only writes under its own role | Implemented |
| Eight automated checks (GH-01 to GH-04, AWS-01 to AWS-04) and REC-01 (manual evidence), versioned, with stated limits | Implemented |
| Job queue in PostgreSQL, worker pool, daily schedule, retries per error class, recovery of abandoned runs | Implemented |
| Evaluations and findings, insert-only history | Implemented |
| Accounts, sessions and four roles; one permission function with matrix tests | Implemented |
| Manual evidence submission and review | Implemented |
| Exceptions with mandatory expiry, remediation notes, decision log | Implemented |
| Eight internal controls with derived state and a 48 hour evidence window | Implemented |
| Web interface: overview, findings, manual evidence, integration health, decision log | Implemented |
| Fault table: every injected fault, its error class and retry behaviour, generated and tested | Implemented |
| Current-state JSON export | Implemented |
| Review package for a past period, with a manifest hash and an offline verifier | Implemented |
| Check versions: a new version adds evaluations beside the old; every stored evaluation can be re-run | Implemented |
| Deduplication case study on a documented synthetic dataset | Implemented |
| A state for each of the 25 MVSP requirements; reviewed mappings | Not started |
| Hosted demo, seeded demo data | Not started |

## The loop

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
| `internal/control` | Internal controls and the derivation of their state |
| `internal/collect` | What collectors share: the snapshot and the classified error |
| `internal/github` | The only code that talks to GitHub; read-only |
| `internal/aws` | The only code that talks to AWS; read-only |
| `internal/check` | Versioned checks and the generated check guide |
| `internal/evidence` | Content-addressed evidence store: local directory and S3 |
| `internal/study` | The deduplication case study harness |
| `internal/store` | PostgreSQL access |
| `internal/web` | The web interface: sign-in, pages and forms |
| `internal/pack` | Pack parsing and validation |
| `internal/db` | Migrations runner |
| `migrations/` | SQL migrations (goose format), embedded in the binary |
| `packs/` | Framework packs (YAML) and their JSON Schema, embedded in the binary |
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
make guide     # regenerate docs/checks.md, docs/permissions.md and docs/faults.md after changing a check, a permission, a fault or a retry policy
```

Tests use a synthetic GitHub API (`internal/github/githubtest`) and a
synthetic AWS account (`internal/aws/awstest`); no test calls GitHub or AWS. Without `CCA_TEST_DATABASE_URL` the database tests are skipped
locally and fail in CI.

## Framework content

`packs/mvsp/v3.0-20231109.yaml` holds the Minimum Viable Secure Product
requirement text, unmodified, from
[vendorsec/mvsp](https://github.com/vendorsec/mvsp) (CC0-1.0). The pack header
records the source commit, path, retrieval date and SHA-256 of the source file.

Every pack must satisfy `packs/pack.schema.json`. An invalid pack fails the
test suite and the pack validation step in CI. Framework rows are immutable in
the database once written.

## License

Apache-2.0. See [LICENSE](LICENSE).
