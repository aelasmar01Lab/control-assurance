# control-assurance

A continuous control assurance application in Go: define controls, collect
observations from AWS and GitHub, evaluate versioned checks, track findings and
exceptions, and export a review package for a past period.

This README states only what is implemented.

## Status

| Area | Status |
| --- | --- |
| Repository layout, Go module, `cca` binary | Implemented |
| CI: tests, lint, vulnerability scan, pack validation, migrations | Implemented |
| Postgres in Compose | Implemented |
| MVSP framework pack (25 requirements, pinned source) | Implemented |
| Pack schema and validation (`cca packs validate`) | Implemented |
| Catalog listing from pack files (`cca requirements list`) | Implemented |
| Database migrations (`cca migrate`), framework catalog tables | Implemented |
| Importing packs into the database | Not started |
| Collectors (GitHub, AWS) | Not started |
| Checks, evaluations, findings | Not started |
| Accounts, roles, permissions | Not started |
| Manual evidence, exceptions, decision log | Not started |
| Review package export | Not started |

## Layout

| Path | Purpose |
| --- | --- |
| `cmd/cca` | The single binary's entry point |
| `internal/pack` | Pack parsing and validation |
| `internal/db` | Database access and migrations runner |
| `migrations/` | SQL migrations (goose format), embedded in the binary |
| `packs/` | Framework packs (YAML) and their JSON Schema, embedded in the binary |
| `deploy/aws` | IAM policy for the read-only collector role |

## Development

Requires Go 1.27+ and Docker.

```sh
make db-up     # start Postgres on 127.0.0.1:5433
make migrate   # apply migrations
make test      # run tests
make build     # build bin/cca
make lint      # needs golangci-lint v2
make vuln      # govulncheck
```

```sh
bin/cca requirements list     # the catalog, with its pinned source and hashes
bin/cca packs validate        # validate the built-in packs
bin/cca packs validate f.yaml # validate a pack file
```

## Framework content

`packs/mvsp/v3.0-20231109.yaml` holds the Minimum Viable Secure Product
requirement text, unmodified, from
[vendorsec/mvsp](https://github.com/vendorsec/mvsp) (CC0-1.0). The pack header
records the source commit, path, retrieval date and SHA-256 of the source file.

Every pack must satisfy `packs/pack.schema.json`. An invalid pack fails the
test suite and the pack validation step in CI. Framework rows are immutable in
the database once written: a trigger rejects updates and deletes.

## License

Apache-2.0. See [LICENSE](LICENSE).
