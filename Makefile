SHELL := /bin/bash
export DATABASE_URL ?= postgres://postgres:postgres@localhost:5432/authz?sslmode=disable
export OPA_BASE_URL ?= http://127.0.0.1:8181
export BUNDLE_OUT_DIR ?= $(CURDIR)/.bundle/out
export BASE_REGO_PATH ?= $(CURDIR)/rego/authz/main.rego

.PHONY: tidy build test run bundle-init docker-up docker-down smoke k6

tidy:
	go mod tidy

build:
	go build -o ./authz-server ./cmd/server

test:
	go test ./...

run: build
	DATABASE_URL=$(DATABASE_URL) OPA_BASE_URL=$(OPA_BASE_URL) BUNDLE_OUT_DIR=$(BUNDLE_OUT_DIR) BASE_REGO_PATH=$(BASE_REGO_PATH) ./authz-server

bundle-init:
	mkdir -p "$(BUNDLE_OUT_DIR)/authz"
	cp "$(BASE_REGO_PATH)" "$(BUNDLE_OUT_DIR)/authz/main.rego"
	printf '%s\n' 'package authz' '' '# placeholder until first publish' > "$(BUNDLE_OUT_DIR)/authz/generated.rego"
	printf '%s\n' '{}' > "$(BUNDLE_OUT_DIR)/role_grants.json"

docker-up: bundle-init
	docker compose up -d postgres opa

docker-down:
	docker compose down

# Requires server (:8080), OPA (:8181), Postgres per docker-compose.
smoke:
	curl -sf "$(OPA_BASE_URL)/health" >/dev/null || curl -sf "$(OPA_BASE_URL)/" >/dev/null
	curl -sf http://127.0.0.1:8080/v1/releases/current
	curl -sf http://127.0.0.1:8080/displayground/ | head -1 | grep -q '<!DOCTYPE html>'
	curl -sf -X POST http://127.0.0.1:8080/v1/authorize \
	  -H 'Content-Type: application/json' \
	  -d '{"user":{"sub":"smoke","roles":["admin"]},"request":{"action":"read","resource":{"type":"any"}}}'

k6:
	@command -v k6 >/dev/null || (echo "install k6: https://k6.io/docs/get-started/installation/" && exit 1)
	k6 run scripts/k6-authorize.js
