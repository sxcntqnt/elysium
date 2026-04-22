#!/usr/bin/env bash
# scripts/vault-bootstrap.sh
#
# Idempotent Vault setup for the auth service.
# Run once per Vault cluster (dev or prod). Requires VAULT_ADDR and VAULT_TOKEN
# to be set (root or bootstrap token with sufficient permissions).
#
# What this script creates:
#   - KV v2 mount at "secret"
#   - Transit mount + HMAC-SHA256 key "auth-service-jwt"
#   - AppRole auth mount + role "auth-service"
#   - Policy "auth-service-policy"
#   - Placeholder secrets (overwrite with real values before deploying)

set -euo pipefail

: "${VAULT_ADDR:?VAULT_ADDR must be set}"
: "${VAULT_TOKEN:?VAULT_TOKEN must be set}"

ROLE_NAME="auth-service"
TRANSIT_KEY="auth-service-jwt"
KV_MOUNT="secret"
KV_PREFIX="auth-service"

echo "→ Enabling KV v2 secrets engine (idempotent)..."
vault secrets enable -path="${KV_MOUNT}" kv-v2 2>/dev/null || echo "  (already enabled)"

echo "→ Enabling Transit secrets engine (idempotent)..."
vault secrets enable transit 2>/dev/null || echo "  (already enabled)"

echo "→ Creating Transit HMAC-SHA256 key '${TRANSIT_KEY}'..."
vault write -f "transit/keys/${TRANSIT_KEY}" type=hmac-sha256 2>/dev/null || \
  echo "  (key already exists — not rotating)"

echo "→ Enabling AppRole auth (idempotent)..."
vault auth enable approle 2>/dev/null || echo "  (already enabled)"

echo "→ Writing auth-service policy..."
vault policy write "${ROLE_NAME}-policy" - <<'POLICY'
# KV v2 — read-only access to auth-service namespace
path "secret/data/auth-service/*" {
  capabilities = ["read"]
}

path "secret/metadata/auth-service/*" {
  capabilities = ["read", "list"]
}

# Transit — HMAC sign and verify only (no key export, no encrypt/decrypt)
path "transit/hmac/auth-service-jwt" {
  capabilities = ["update"]
}

path "transit/verify/auth-service-jwt" {
  capabilities = ["update"]
}

# Token self-renewal
path "auth/token/renew-self" {
  capabilities = ["update"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}
POLICY

echo "→ Creating AppRole '${ROLE_NAME}'..."
vault write "auth/approle/role/${ROLE_NAME}" \
  token_policies="${ROLE_NAME}-policy" \
  token_ttl="1h" \
  token_max_ttl="24h" \
  token_type="service" \
  secret_id_ttl="720h"    # 30 days; use response-wrapping in prod

echo "→ Writing placeholder KV secrets (OVERWRITE BEFORE DEPLOY)..."

vault kv put "${KV_MOUNT}/${KV_PREFIX}/jwt" \
  signing_key="CHANGE_ME_minimum_32_bytes_long_key_here" \
  access_ttl="15m" \
  refresh_ttl="168h"

vault kv put "${KV_MOUNT}/${KV_PREFIX}/bcrypt" \
  cost="12"

vault kv put "${KV_MOUNT}/${KV_PREFIX}/database" \
  dgraph_target="localhost:9080" \
  tls_enabled="false"

echo ""
echo "✓ Bootstrap complete."
echo ""
echo "Fetch credentials for your service:"
echo "  ROLE_ID:    $(vault read -field=role_id auth/approle/role/${ROLE_NAME}/role-id)"
echo "  SECRET_ID:  $(vault write -f -field=secret_id auth/approle/role/${ROLE_NAME}/secret-id)"
echo ""
echo "In production, use response-wrapping for SECRET_ID:"
echo "  vault write -wrap-ttl=5m -f auth/approle/role/${ROLE_NAME}/secret-id"
