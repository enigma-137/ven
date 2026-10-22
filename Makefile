# VEN build tasks. On Windows without make, use scripts/build.ps1.

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.1.0-dev)
LDFLAGS := -s -w -X github.com/enigma-137/ven/internal/app.Version=$(VERSION)
BIN     := bin/ven$(if $(filter Windows_NT,$(OS)),.exe,)

.PHONY: all web build dev-build test vet check fuzz clean

all: build

## web: install frontend dependencies and build web/dist (embedded by go:embed)
web:
	npm --prefix web ci
	npm --prefix web run build
	touch web/dist/.gitkeep

## build: release binary with the embedded dashboard
build: web
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/ven

## dev-build: Go-only build (uses whatever is in web/dist)
dev-build:
	go build -o $(BIN) ./cmd/ven

## test: Go tests
test:
	go test ./...

## vet: go vet
vet:
	go vet ./...

## check: everything CI should run
check: vet test
	npm --prefix web run typecheck
	npm --prefix web run build
	touch web/dist/.gitkeep

## fuzz: run the dotenv fuzzers briefly
fuzz:
	go test ./internal/envfile -run '^$$' -fuzz FuzzParse -fuzztime 30s
	go test ./internal/envfile -run '^$$' -fuzz FuzzQuoteValue -fuzztime 30s

clean:
	rm -rf bin web/dist/assets web/dist/index.html web/dist/favicon.svg
