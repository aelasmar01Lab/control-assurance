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
| Checks GH-01 and GH-02, versioned, with stated limits | Implemented |
| Evaluations and findings, insert-only history | Implemented |
| One read-only page (`cca serve`) | Implemented |
| Internal controls and mappings to requirements | Not started |
| Accounts, roles, permissions | Not started |
| Manual evidence, exceptions, decision log | Not started |
| AWS collector, GH-03, GH-04, scheduler, freshness | Not started |
| Review package export | Not started |

## The loop

```sh
make db-up && make migrate && make build
export DATABASE_URL='postgres://cca:cca_local_only@127.0.0.1:5433/cca?sslmode=disable'

bin/cca packs load                      # import the MVSP catalog
bin/cca collect github owner/name       # read the active rules on the default branch
bin/cca evaluate                        # apply GH-01 and GH-02 to the new evidence
bin/cca results                         # current result per repository and check
bin/cca findings list                   # findings, with the evaluations that opened and closed them
bin/cca serve                           # the same, read-only, at http://127.0.0.1:8080
```

Disable the branch ruleset, collect and evaluate: both checks fail and each
opens one finding. Re-enable it, collect and evaluate: both pass, and each
finding is closed by the passing evaluation. Every earlier evaluation is
still listed.

What the results mean:

- `pass`, `fail` and `not_evaluated` each describe one check version applied
  to one stored observation. The [check guide](docs/checks.md) says what a
  pass does and does not establish.
- A collection failure is none of the three. It is recorded on the run with
  an error class (`auth`, `permission`, `rate_limited`, `not_found`,
  `network`, `server`, `malformed_response`) and changes no result.
- A rule listing that was not read to the end is `incomplete`; a check that
  did not find its rule in it returns `not_evaluated`, not `fail`.

## Credentials

`cca collect` uses `GITHUB_TOKEN` when set, and otherwise the GitHub CLI's
current login (`gh auth token`). The collector only issues `GET` requests and
needs read access to repository metadata. A CLI login is much broader than
that; see [decision 7](docs/decisions.md).

## Layout

| Path | Purpose |
| --- | --- |
| `cmd/cca` | The single binary's entry point |
| `internal/assurance` | The collect and evaluate steps; every entry point goes through it |
| `internal/github` | The only code that talks to GitHub; read-only |
| `internal/check` | Versioned checks and the generated check guide |
| `internal/evidence` | Content-addressed evidence store |
| `internal/store` | PostgreSQL access |
| `internal/web` | The read-only page |
| `internal/pack` | Pack parsing and validation |
| `internal/db` | Migrations runner |
| `migrations/` | SQL migrations (goose format), embedded in the binary |
| `packs/` | Framework packs (YAML) and their JSON Schema, embedded in the binary |
| `docs/` | Check guide (generated) and decision records |
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
make guide     # regenerate docs/checks.md after changing a check
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
