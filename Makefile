# SKM — SSH Key Manager

SHELL         := /bin/bash
BACKEND       := backend
FRONTEND      := frontend
DEPLOY        := deploy
COMPOSE       := docker compose -f $(DEPLOY)/docker-compose.yml
COMPOSE_TEST  := docker compose -f $(DEPLOY)/docker-compose.test.yml -p skm_test

# Integration tests need real dependencies; these match docker-compose.test.yml.
TEST_DB       := postgres://skm:skm@localhost:55440/skm?sslmode=disable
# Two separate hosts: Go runs test packages in parallel, and the connector and
# end-to-end suites both manage the same account's authorized_keys. Sharing one
# host lets them silently overwrite each other.
TEST_SSH      := localhost:52201
TEST_SSH_E2E  := localhost:52202
TEST_SSH_ROT  := localhost:52203,localhost:52204

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# ------------------------------------------------------------------ build ---

.PHONY: build
build: frontend ## Build both binaries with the web interface embedded
	cd $(BACKEND) && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o ../bin/skm-server ./cmd/skm-server
	cd $(BACKEND) && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o ../bin/skmctl    ./cmd/skmctl
	@echo "built bin/skm-server and bin/skmctl"

.PHONY: build-backend
build-backend: ## Build the binaries without rebuilding the web interface
	cd $(BACKEND) && go build -o ../bin/skm-server ./cmd/skm-server
	cd $(BACKEND) && go build -o ../bin/skmctl    ./cmd/skmctl

.PHONY: frontend
frontend: ## Build the Angular app into the Go embed directory
	@if [ ! -d "$(FRONTEND)/node_modules" ]; then cd $(FRONTEND) && npm install --no-audit --no-fund; fi
	cd $(FRONTEND) && npm run build -- --configuration production
	rm -rf $(BACKEND)/internal/web/dist
	mkdir -p $(BACKEND)/internal/web/dist
	cp -r $(FRONTEND)/dist/skm/browser/* $(BACKEND)/internal/web/dist/
	touch $(BACKEND)/internal/web/dist/.gitkeep
	@echo "embedded the web interface into $(BACKEND)/internal/web/dist"

# ------------------------------------------------------------------- test ---

.PHONY: test
test: ## Run unit tests only (no Docker required)
	cd $(BACKEND) && go test -race -short ./...

.PHONY: test-integration
test-integration: test-up ## Run every test against real Postgres and sshd
	cd $(BACKEND) && SKM_TEST_DATABASE_URL="$(TEST_DB)" \
		SKM_TEST_SSH_ADDR="$(TEST_SSH)" SKM_TEST_SSH_ADDR_E2E="$(TEST_SSH_E2E)" \
		SKM_TEST_SSH_FLEET="$(TEST_SSH_ROT)" \
		go test -count=1 ./...

.PHONY: test-all
test-all: test-up ## Run every test with the race detector
	cd $(BACKEND) && SKM_TEST_DATABASE_URL="$(TEST_DB)" \
		SKM_TEST_SSH_ADDR="$(TEST_SSH)" SKM_TEST_SSH_ADDR_E2E="$(TEST_SSH_E2E)" \
		SKM_TEST_SSH_FLEET="$(TEST_SSH_ROT)" \
		go test -race -count=1 ./...

.PHONY: test-up
test-up: ## Start the integration test fleet
	$(COMPOSE_TEST) up -d --build
	@echo -n "waiting for the test fleet"
	@for i in $$(seq 1 60); do \
		if docker exec skm_test_postgres pg_isready -U skm -q 2>/dev/null; then echo " ready"; exit 0; fi; \
		echo -n "."; sleep 1; \
	done; echo " timed out"; exit 1

.PHONY: test-down
test-down: ## Stop and remove the integration test fleet
	$(COMPOSE_TEST) down -v --remove-orphans

.PHONY: cover
cover: test-up ## Produce a coverage report
	cd $(BACKEND) && SKM_TEST_DATABASE_URL="$(TEST_DB)" \
		SKM_TEST_SSH_ADDR="$(TEST_SSH)" SKM_TEST_SSH_ADDR_E2E="$(TEST_SSH_E2E)" \
		SKM_TEST_SSH_FLEET="$(TEST_SSH_ROT)" \
		go test -coverprofile=../coverage.out -covermode=atomic ./...
	cd $(BACKEND) && go tool cover -html=../coverage.out -o ../coverage.html
	@echo "wrote coverage.html"

# ------------------------------------------------------------------ checks ---

.PHONY: lint
lint: ## Format check and vet
	@test -z "$$(cd $(BACKEND) && gofmt -l . | tee /dev/stderr)" || { echo "run 'make fmt'"; exit 1; }
	cd $(BACKEND) && go vet ./...

.PHONY: fmt
fmt: ## Format the Go source
	cd $(BACKEND) && gofmt -w .

# Comment lines are stripped before matching, so documenting a forbidden
# construct does not trip the check that forbids it.
NOCOMMENT := grep -vE '^[^:]+:[0-9]+:[[:space:]]*(//|\*|/\*)'

.PHONY: audit-source
audit-source: ## Assert the security invariants that must never regress
	@echo "checking that host key verification is never disabled..."
	@if grep -rn "InsecureIgnoreHostKey" $(BACKEND) --include="*.go" | $(NOCOMMENT) | grep . ; then \
		echo "FAIL: host key verification is bypassed somewhere"; exit 1; fi
	@echo "checking that private key material never reaches a log..."
	@if grep -rnE '(slog|log)\.[A-Za-z]+[a-z]?\([^)]*(PrivatePEM|privatePEM|PrivateKey|privateKey)' \
		$(BACKEND) --include="*.go" | $(NOCOMMENT) | grep -v '_test.go' | grep . ; then \
		echo "FAIL: private key material reaches a log call"; exit 1; fi
	@echo "checking that the server never prints private key material..."
	@if grep -rnE 'fmt\.(Print|Fprint|Sprint)[a-z]*\([^)]*(PrivatePEM|privatePEM|PrivateKey|privateKey)' \
		$(BACKEND)/internal --include="*.go" | $(NOCOMMENT) | grep -v '_test.go' | grep . ; then \
		echo "FAIL: private key material reaches a print call in the server"; exit 1; fi
	@echo "checking that the reveal path is permission-gated..."
	@grep -q "PermKeyRevealBreakGlass" $(BACKEND)/internal/service/keys.go \
		|| { echo "FAIL: break-glass reveal is not separately gated"; exit 1; }
	@echo "checking that bulk export is gated like a reveal..."
	@grep -q "RequireFresh(authz.PermKeyReveal" $(BACKEND)/internal/service/backup.go \
		|| { echo "FAIL: exporting every private key is not gated like a reveal"; exit 1; }
	@echo "checking that consumer delivery is gated and audited..."
	@grep -q "ActionConsumerSend" $(BACKEND)/internal/service/consumers.go \
		|| { echo "FAIL: consumer delivery is not audited"; exit 1; }
	@echo "checking that backup archives are never written unencrypted..."
	@grep -q 'passphrase == ""' $(BACKEND)/internal/backup/archive.go \
		|| { echo "FAIL: an archive can be written without a passphrase"; exit 1; }
	@echo "checking that the rotation gate cannot be skipped..."
	@grep -q "store.RTVerified" $(BACKEND)/internal/service/rotation.go \
		|| { echo "FAIL: retirement does not require a verified target"; exit 1; }
	@echo "checking that the exec connector is off by default..."
	@grep -q "not enabled on this install" $(BACKEND)/internal/connectors/execc/exec.go \
		|| { echo "FAIL: the exec connector does not refuse to run without an allow-list"; exit 1; }
	@echo "all source invariants hold"

.PHONY: check
check: lint audit-source test ## Everything CI runs before integration tests

# ------------------------------------------------------------------- run ---

.PHONY: secrets
secrets: ## Generate the local secrets docker-compose expects
	@mkdir -p $(DEPLOY)/secrets
	@test -s $(DEPLOY)/secrets/master_key         || openssl rand -hex 32 > $(DEPLOY)/secrets/master_key
	@test -s $(DEPLOY)/secrets/db_password        || openssl rand -hex 32 > $(DEPLOY)/secrets/db_password
	@test -s $(DEPLOY)/secrets/bootstrap_password || openssl rand -hex 16 > $(DEPLOY)/secrets/bootstrap_password
	@printf 'postgres://skm:%s@skm_postgres:5432/skm?sslmode=disable' \
		"$$(cat $(DEPLOY)/secrets/db_password)" > $(DEPLOY)/secrets/database_url
	@# The container runs as a different, unprivileged user than the host owner,
	@# so mode 600 on the files would make them unreadable inside the container.
	@# The directory is 700 instead: other local users cannot traverse it, while
	@# the Docker daemon (root) can still mount the files in.
	@chmod 700 $(DEPLOY)/secrets
	@chmod 644 $(DEPLOY)/secrets/master_key $(DEPLOY)/secrets/db_password \
		$(DEPLOY)/secrets/bootstrap_password $(DEPLOY)/secrets/database_url
	@echo "secrets written to $(DEPLOY)/secrets/ (git-ignored, directory mode 700)"
	@echo "  admin password: $$(cat $(DEPLOY)/secrets/bootstrap_password)"

# Override when 8090 is taken: `SKM_HTTP_PORT=8081 make up`
SKM_HTTP_PORT ?= 8090
export SKM_HTTP_PORT

.PHONY: up
up: secrets ## Build and start the full stack (SKM_HTTP_PORT to change the port)
	$(COMPOSE) up -d --build
	@echo "SKM is starting on http://localhost:$(SKM_HTTP_PORT)"
	@echo "  sign in as 'admin' with the password shown by 'make secrets'"

.PHONY: down
down: ## Stop the stack, keeping data
	$(COMPOSE) down

.PHONY: clean-all
clean-all: ## Stop the stack and DELETE the database volume
	$(COMPOSE) down -v

.PHONY: logs
logs: ## Follow the server logs
	$(COMPOSE) logs -f skm_server

.PHONY: dev
dev: test-up build-backend ## Run the server locally against the test database
	@SKM_DATABASE_URL="$(TEST_DB)" \
	 SKM_MASTER_KEY="$$(openssl rand -hex 32)" \
	 SKM_BOOTSTRAP_USER=admin \
	 SKM_BOOTSTRAP_PASSWORD=admin-dev-password \
	 SKM_LOG_FORMAT=text \
	 SKM_LOG_LEVEL=debug \
	 SKM_DEV_MODE=true \
	 ./bin/skm-server

.PHONY: dev-frontend
dev-frontend: ## Run the Angular dev server with API proxying
	cd $(FRONTEND) && npm start

.PHONY: clean
clean: ## Remove build artefacts
	rm -rf bin coverage.out coverage.html
	rm -rf $(BACKEND)/internal/web/dist/*
	rm -rf $(FRONTEND)/dist $(FRONTEND)/.angular
