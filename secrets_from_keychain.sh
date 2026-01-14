#!/usr/bin/env bash
# Print export statements for secrets stored in macOS Keychain
# Usage:
#   eval "$(./secrets_from_keychain.sh username)"
#   # now $APPLE_ID etc are set in your current shell (zsh/bash)

set -euo pipefail

KEYCHAIN_PREFIX="${KEYCHAIN_PREFIX:-gh-actions:}"
KEYCHAIN_USER="${1:-${KEYCHAIN_USER:-$USER}}"

kc_get() {
  local name="$1"
  local service="${KEYCHAIN_PREFIX}${name}"

  security find-generic-password -a "$KEYCHAIN_USER" -s "$service" -w 2>/dev/null || {
    echo "echo '❌ Missing Keychain secret: service=$service account=$KEYCHAIN_USER' 1>&2" 
    exit 1
  }
}

# Escape values so they’re safe in export statements (handles quotes/newlines)
emit_export() {
  local var="$1"
  local val="$2"
  printf 'export %s=%q\n' "$var" "$val"
}

emit_export APPLE_ID              "$(kc_get APPLE_ID)"
emit_export APP_SPECIFIC_PASSWORD "$(kc_get APP_SPECIFIC_PASSWORD)"
emit_export TEAM_ID               "$(kc_get TEAM_ID)"
emit_export CERTIFICATE_NAME      "$(kc_get CERTIFICATE_NAME)"
