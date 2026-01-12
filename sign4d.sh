#!/usr/bin/env bash
set -euo pipefail

APP="${1:?Usage: sign4d.sh /path/to/YourApp.app}"
IDENTITY="${2:?Usage: sign4d.sh /path/to/YourApp.app 'Developer ID Application: ... (TEAMID)'}"

echo "Signing 4D bundle: $APP"
echo "Identity: $IDENTITY"
echo

SIGN_OPTS=(--sign "$IDENTITY" --options runtime --timestamp)

is_macho() {
  /usr/bin/file "$1" 2>/dev/null | /usr/bin/grep -q "Mach-O"
}

# Returns one of: unsigned | adhoc | real
sig_kind() {
  local target="$1"
  local out rc=0

  out="$(/usr/bin/codesign -dv --verbose=4 "$target" 2>&1)" || rc=$?

  if [[ $rc -ne 0 ]]; then
    echo "unsigned"
    return 0
  fi

  if echo "$out" | /usr/bin/grep -qE '^Signature=adhoc$'; then
    echo "adhoc"
    return 0
  fi

  echo "real"
}

sign_file_if_needed() {
  local target="$1"

  # Only files that are Mach-O are signable (scripts/text are skipped here)
  if ! is_macho "$target"; then
    echo "== not Mach-O, skip: $target"
    return 0
  fi

  local kind
  kind="$(sig_kind "$target")"

  case "$kind" in
    unsigned|adhoc)
      echo "-> signing file ($kind): $target"
      /usr/bin/codesign --force "${SIGN_OPTS[@]}" --verbose=1 "$target"
      ;;
    real)
      echo "== signed (real), skip: $target"
      ;;
  esac
}

sign_container_if_needed() {
  local target="$1"
  local kind
  kind="$(sig_kind "$target")"

  case "$kind" in
    unsigned|adhoc)
      echo "-> signing container deep ($kind): $target"
      /usr/bin/codesign --force "${SIGN_OPTS[@]}" --deep --verbose=1 "$target" || true
      ;;
    real)
      echo "== signed (real), skip: $target"
      ;;
  esac
}

# 1) Nested helper apps first (if any)
find "$APP" -type d -name "*.app" ! -path "$APP" -print0 \
| while IFS= read -r -d '' subapp; do
    sign_container_if_needed "$subapp"
  done

# 2) Frameworks (directory is signable)
find "$APP" -type d -name "*.framework" -print0 \
| while IFS= read -r -d '' fw; do
    sign_container_if_needed "$fw"
  done

# 3) Mach-O files anywhere under Contents (includes extension-less 4D tools)
find "$APP/Contents" -type f -print0 \
| while IFS= read -r -d '' f; do
    sign_file_if_needed "$f" || true
  done

# 4) Bundle containers (directories; may contain nested Mach-O)
find "$APP/Contents" -type d \( -name "*.bundle" -o -name "*.plugin" -o -name "*.xpc" -o -name "*.appex" \) -print0 \
| while IFS= read -r -d '' d; do
    sign_container_if_needed "$d"
  done

# 5) Re-sign the main app LAST (always)
echo "-> signing main app (always): $APP"
/usr/bin/codesign --force "${SIGN_OPTS[@]}" --deep --strict --verbose=2 "$APP"

echo
echo "Verifying…"
/usr/bin/codesign --verify --deep --strict --verbose=4 "$APP"
/usr/sbin/spctl -a -vv "$APP" || true
echo "Done."
