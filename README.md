# control-assurance

A continuous control assurance application in Go: define controls, collect
observations from AWS and GitHub, evaluate versioned checks, track findings and
exceptions, and export a review package for a past period.

This README states only what is implemented.

## Status

| Area | Status |
| --- | --- |
| Repository layout, Go module, `cca` binary skeleton | Implemented |
| CI: tests, lint, vulnerability scan | Implemented |
| Postgres in Compose | Implemented |
| Database migrations | Not started |
| MVSP framework pack and schema validation | Not started |
| Collectors (GitHub, AWS) | Not started |
| Checks, evaluations, findings | Not started |
| Accounts, roles, permissions | Not started |
| Manual evidence, exceptions, decision log | Not started |
| Review package export | Not started |

## Layout

| Path | Purpose |
| --- | --- |
| `cmd/cca` | The single binary's entry point |
| `internal/` | Application packages |
| `migrations/` | SQL migrations |
| `packs/` | Framework packs (YAML) |

## Development

Requires Go 1.27+ and Docker.

```sh
cp .env.example .env
make db-up     # start Postgres
make test      # run tests
make build     # build bin/cca
make lint      # needs golangci-lint v2
make vuln      # govulncheck
```
