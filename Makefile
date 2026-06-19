.PHONY: build run test lint proto tidy docker-up docker-down

# ── Build ─────────────────────────────────────────────────────────────────────
build:
	go build -o bin/auth-service ./cmd/server

run: build
	JWT_SECRET=$$(openssl rand -hex 32) \
	DGRAPH_TARGET="localhost:9080" \
	ENV=development \
	./bin/auth-service

# ── Test ──────────────────────────────────────────────────────────────────────
test:
	go test -race -count=1 ./...

test/cover:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out

# ── Lint ──────────────────────────────────────────────────────────────────────
lint:
	golangci-lint run ./...

# ── Proto ─────────────────────────────────────────────────────────────────────
# Requires: protoc, protoc-gen-go, protoc-gen-go-grpc
proto:
	protoc \
		--go_out=internal/handler/grpc/pb \
		--go_opt=paths=source_relative \
		--go-grpc_out=internal/handler/grpc/pb \
		--go-grpc_opt=paths=source_relative \
		proto/auth.proto

# ── Dependencies ──────────────────────────────────────────────────────────────
tidy:
	go mod tidy

# ── Dgraph (local dev) ────────────────────────────────────────────────────────
docker-up:
	docker compose up -d

docker-down:
	docker compose down

# Apply Dgraph schema manually (alternative to the auto-apply at startup)
schema:
	curl -X POST http://localhost:8080/admin/schema \
		--data-binary @scripts/schema.dql \
		-H "Content-Type: application/dql"
