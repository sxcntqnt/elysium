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
#
# Usage:
#   ./vault-bootstrap.sh
#   ENV_FILE=prod.env ./vault-bootstrap.sh
#   ENV_FILE=/dev/null ./vault-bootstrap.sh   # skip credential file entirely
#
# Environment variables:
#   VAULT_ADDR        required  Vault server address
#   VAULT_TOKEN       required  Root or bootstrap token
#   ROLE_NAME         optional  AppRole name (default: auth-service)
#   TRANSIT_KEY       optional  Transit key name (default: auth-service-jwt)
#   KV_MOUNT          optional  KV v2 mount path (default: secret)
#   KV_PREFIX         optional  KV path prefix (default: auth-service)
#   ENV_FILE          optional  Output file for credentials (default: .env.vault)
#                               Set to /dev/null to suppress credential file creation.
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration (all overridable via environment)
# ---------------------------------------------------------------------------
: "${VAULT_ADDR:?VAULT_ADDR must be set}"
: "${VAULT_TOKEN:?VAULT_TOKEN must be set}"

ROLE_NAME="${ROLE_NAME:-auth-service}"
TRANSIT_KEY="${TRANSIT_KEY:-auth-service-jwt}"
KV_MOUNT="${KV_MOUNT:-secret}"
KV_PREFIX="${KV_PREFIX:-auth-service}"
ENV_FILE="${ENV_FILE:-.env.vault}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# vault_enable_secrets_engine <type> <path>
# Enables a secrets engine if not already enabled; silently skips if it is.
vault_enable_secrets_engine() {
  local type="$1" path="$2"
  if vault secrets list -format=json | grep -q "\"${path}/\""; then
    echo "  (${path} already enabled — skipping)"
  else
    vault secrets enable -path="${path}" "${type}"
    echo "  Enabled ${type} at ${path}/"
  fi
}

# vault_enable_auth_method <type>
# Enables an auth method if not already enabled; silently skips if it is.
vault_enable_auth_method() {
  local type="$1"
  if vault auth list -format=json | grep -q "\"${type}/\""; then
    echo "  (${type} auth already enabled — skipping)"
  else
    vault auth enable "${type}"
    echo "  Enabled ${type} auth"
  fi
}

# vault_ensure_transit_key <mount> <key> <type>
# Creates a transit key if it doesn't already exist. Never rotates an existing key.
vault_ensure_transit_key() {
  local mount="$1" key="$2" key_type="$3"
  if vault read "${mount}/keys/${key}" > /dev/null 2>&1; then
    echo "  (key '${key}' already exists — not rotating)"
  else
    vault write -f "${mount}/keys/${key}" type="${key_type}"
    echo "  Created transit key '${key}' (${key_type})"
  fi
}

# vault_kv_put_if_missing <mount> <path> [key=value ...]
# Writes KV secrets only if the path does not already have a current version.
# Existing secrets are left untouched so real production values are never
# silently overwritten by placeholder data.
vault_kv_put_if_missing() {
  local mount="$1" kv_path="$2"; shift 2
  if vault kv get -mount="${mount}" "${kv_path}" > /dev/null 2>&1; then
    echo "  (${kv_path} already exists — skipping placeholder write)"
  else
    vault kv put -mount="${mount}" "${kv_path}" "$@"
    echo "  Wrote placeholder at ${kv_path} (OVERWRITE BEFORE DEPLOY)"
  fi
}

# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------

echo "→ Enabling KV v2 secrets engine..."
vault_enable_secrets_engine kv-v2 "${KV_MOUNT}"

echo "→ Enabling Transit secrets engine..."
vault_enable_secrets_engine transit transit

echo "→ Ensuring Transit HMAC-SHA256 key '${TRANSIT_KEY}'..."
vault_ensure_transit_key transit "${TRANSIT_KEY}" aes256-gcm96

echo "→ Enabling AppRole auth..."
vault_enable_auth_method approle

echo "→ Writing auth-service policy..."
vault policy write "${ROLE_NAME}-policy" - <<POLICY
# KV v2 — read-only access to auth-service namespace
path "${KV_MOUNT}/data/${KV_PREFIX}/*" {
  capabilities = ["read"]
}
path "${KV_MOUNT}/metadata/${KV_PREFIX}/*" {
  capabilities = ["read", "list"]
}
# Transit — HMAC sign and verify only (no key export, no encrypt/decrypt)
path "transit/hmac/${TRANSIT_KEY}" {
  capabilities = ["update"]
}
path "transit/verify/${TRANSIT_KEY}" {
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
echo "  Policy '${ROLE_NAME}-policy' written"

echo "→ Configuring AppRole '${ROLE_NAME}'..."
# write is idempotent — it updates role config on every run, which is what
# you want so that TTL / policy changes are applied without manual cleanup.
vault write "auth/approle/role/${ROLE_NAME}" \
  token_policies="${ROLE_NAME}-policy" \
  token_period="24h" \
  token_max_ttl="24h" \
  token_type="service" \
  secret_id_ttl="720h" 

echo "  AppRole '${ROLE_NAME}' configured"

echo "→ Writing placeholder KV secrets (skipped if already present)..."
vault_kv_put_if_missing "${KV_MOUNT}" "${KV_PREFIX}/jwt" \
  signing_key="CHANGE_ME_minimum_32_bytes_long_key_here" \
  access_ttl="15m" \
  refresh_ttl="168h"

vault_kv_put_if_missing "${KV_MOUNT}" "${KV_PREFIX}/bcrypt" \
  cost="12"

vault_kv_put_if_missing "${KV_MOUNT}" "${KV_PREFIX}/database" \
  dgraph_target="localhost:9080" \
  tls_enabled="false"

# ---------------------------------------------------------------------------
# Emit credentials
# ---------------------------------------------------------------------------
echo "→ Fetching AppRole credentials..."
ROLE_ID="$(vault read -field=role_id "auth/approle/role/${ROLE_NAME}/role-id")"
SECRET_ID="$(vault write -f -field=secret_id "auth/approle/role/${ROLE_NAME}/secret-id")"

if [[ "${ENV_FILE}" == "/dev/null" ]]; then
  echo "  ENV_FILE=/dev/null — credential file skipped"
  echo ""
  echo "  ROLE_ID:   ${ROLE_ID}"
  echo "  SECRET_ID: ${SECRET_ID}"
elif [[ -f "${ENV_FILE}" ]]; then
  echo ""
  echo "ERROR: ${ENV_FILE} already exists."
  echo "  Remove it first, or set ENV_FILE to a different path:"
  echo "    ENV_FILE=new.env ./vault-bootstrap.sh"
  echo ""
  echo "  To view credentials without writing a file:"
  echo "    ENV_FILE=/dev/null ./vault-bootstrap.sh"
  exit 1
else
  cat > "${ENV_FILE}" <<EOF
VAULT_ROLE_ID=${ROLE_ID}
VAULT_SECRET_ID=${SECRET_ID}
EOF
  chmod 600 "${ENV_FILE}"
  echo "  Credentials written to ${ENV_FILE} (mode 600)"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "✓ Bootstrap complete."
echo ""
echo "In production, use response-wrapping for SECRET_ID:"
echo "  vault write -wrap-ttl=5m -f auth/approle/role/${ROLE_NAME}/secret-id"
