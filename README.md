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
| GitHub collector: branch rules, classified errors, pagination completeness | Implemented |
| Evidence store: filesystem, content-addressed by SHA-256 | Implemented |
| Checks GH-01 and GH-02 (automated) and REC-01 (manual evidence), versioned, with stated limits | Implemented |
| Evaluations and findings, insert-only history | Implemented |
| Accounts, sessions and four roles; one permission function with matrix tests | Implemented |
| Manual evidence submission and review | Implemented |
| Exceptions with mandatory expiry, remediation notes, decision log | Implemented |
| Two internal controls with derived state (change management, backup and recovery) | Implemented |
| Web interface: overview, findings, manual evidence, decision log | Implemented |
| Current-state JSON export | Implemented |
| The other six internal controls; state for all 25 MVSP requirements | Not started |
| AWS collector, GH-03, GH-04, scheduler, retries | Not started |
| Review package for a past period, S3 evidence store, deduplication study | Not started |

## The loop

```sh
make db-up && make migrate && make build
export DATABASE_URL='postgres://cca:cca_local_only@127.0.0.1:5433/cca?sslmode=disable'

bin/cca users seed                      # four lab users; passwords are printed once
export CCA_USER=operator                # the user CLI commands act as

bin/cca packs load                      # import the MVSP catalog
bin/cca collect github owner/name       # read the active rules on the default branch
bin/cca evaluate                        # apply GH-01 and GH-02 to the new evidence
bin/cca results                         # control states and current results
bin/cca findings list                   # findings, with exceptions and notes
bin/cca serve                           # the web interface at http://127.0.0.1:8080
```

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
  an error class (`auth`, `permission`, `rate_limited`, `not_found`,
  `network`, `server`, `malformed_response`) and changes no result.
- A rule listing that was not read to the end is `incomplete`; a check that
  did not find its rule in it returns `not_evaluated`, not `fail`.

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

`cca collect` uses `GITHUB_TOKEN` when set, and otherwise the GitHub CLI's
current login (`gh auth token`). The collector only issues `GET` requests and
needs read access to repository metadata. A CLI login is much broader than
that; see [decision 7](docs/decisions.md).

## Layout

| Path | Purpose |
| --- | --- |
| `cmd/cca` | The single binary's entry point |
| `internal/assurance` | The service layer: every entry point goes through it, and it checks permission first |
| `internal/authz` | Roles, actions and the one permission function |
| `internal/auth` | Password hashing (argon2id) |
| `internal/control` | Internal controls and the derivation of their state |
| `internal/github` | The only code that talks to GitHub; read-only |
| `internal/check` | Versioned checks and the generated check guide |
| `internal/evidence` | Content-addressed evidence store |
| `internal/store` | PostgreSQL access |
| `internal/web` | The web interface: sign-in, pages and forms |
| `internal/pack` | Pack parsing and validation |
| `internal/db` | Migrations runner |
| `migrations/` | SQL migrations (goose format), embedded in the binary |
| `packs/` | Framework packs (YAML) and their JSON Schema, embedded in the binary |
| `docs/` | Check guide and permission matrix (both generated), and decision records |
| `deploy/aws` | IAM policy for the read-only collector role |

## Development

Requires Go 1.27+ and Docker.

```sh
make db-up     # start Postgres on 127.0.0.1:5433
make migrate   # apply migrations
make test      # run tests; database tests use throwaway schemas, so run db-up first
make build     # build bin/cca
make lint      # needs golangci-lint v2
make vuln      # govulncheck
make guide     # regenerate docs/checks.md and docs/permissions.md after changing a check or a permission
```

Tests use a synthetic GitHub API (`internal/github/githubtest`); no test
calls GitHub. Without `CCA_TEST_DATABASE_URL` the database tests are skipped
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
