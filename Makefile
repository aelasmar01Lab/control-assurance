.PHONY: build test lint vuln db-up db-down migrate packs

# Local development database; matches compose.yaml and .env.example.
DATABASE_URL ?= postgres://cca:cca_local_only@127.0.0.1:5433/cca?sslmode=disable
export DATABASE_URL

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
