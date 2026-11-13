.PHONY: demo build test lint vuln db-up db-down migrate packs content guide study serve

# Local development database; matches compose.yaml and .env.example.
DATABASE_URL ?= postgres://cca:cca_local_only@127.0.0.1:5433/cca?sslmode=disable
export DATABASE_URL

# Database tests run in their own throwaway schemas of the same database.
CCA_TEST_DATABASE_URL ?= $(DATABASE_URL)
export CCA_TEST_DATABASE_URL

# One command: a seeded demo with synthetic data at http://127.0.0.1:8080.
# Needs only Docker.
demo:
	docker compose --profile demo up --build demo

build:
	go build -o bin/cca ./cmd/cca

test:
	go test -race ./...

lint:
	golangci-lint run

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

db-up:
	docker compose up -d --wait postgres

db-down:
	docker compose down

migrate:
	go run ./cmd/cca migrate up

packs:
	go run ./cmd/cca packs validate

# After editing anything under controls/, mappings/, tracking/ or scope/: check it,
# then regenerate the two documents made from it. Sign what you reviewed
# with "go run ./cmd/cca review sign <file>".
content:
	go run ./cmd/cca content validate
	go run ./cmd/cca review queue > docs/review-queue.md
	go run ./cmd/cca controls guide > docs/controls.md
	go run ./cmd/cca review status

# Regenerate the documents that are generated from code.
guide:
	go run ./cmd/cca checks guide > docs/checks.md
	go run ./cmd/cca permissions > docs/permissions.md
	go run ./cmd/cca faults > docs/faults.md
	go run ./cmd/cca controls guide > docs/controls.md
	go run ./cmd/cca review queue > docs/review-queue.md
	go run ./cmd/cca self-assessment > docs/self-assessment.md

# Regenerate the deduplication case study. Needs no database and no network.
study:
	go run ./cmd/cca study dedup > docs/dedup-study.md

serve: build
	bin/cca serve
