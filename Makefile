.PHONY: build test lint vuln db-up db-down

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
