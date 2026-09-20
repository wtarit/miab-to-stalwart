#!/usr/bin/env bash
set -euo pipefail

required_env_vars=(
  MAILBOX_ROOT
  ARCHIVE_ROOT
  STALWART_URL
)

missing=()

for var in "${required_env_vars[@]}"; do
  if [[ -z "${!var:-}" ]]; then
    missing+=("$var")
  fi
done

if (( ${#missing[@]} > 0 )); then
  echo "ERROR: Missing required environment variable(s):" >&2

  for var in "${missing[@]}"; do
    echo "  - $var" >&2
  done

  echo >&2
  echo "Example:" >&2
  echo "  export MAILBOX_ROOT=/srv/miab-migration/mail/mailboxes" >&2
  echo "  export ARCHIVE_ROOT=/srv/miab-migration/vandelay" >&2
  echo "  export STALWART_URL=http://127.0.0.1:8080" >&2
  echo "  export VANDELAY_TOKEN='your-api-token'" >&2

  exit 1
fi

if [[ ! -d "$MAILBOX_ROOT" ]]; then
  echo "ERROR: MAILBOX_ROOT does not exist or is not a directory:" >&2
  echo "  $MAILBOX_ROOT" >&2
  exit 1
fi

mkdir -p "$ARCHIVE_ROOT"

for domain_dir in "$MAILBOX_ROOT"/*; do
  [[ -d "$domain_dir" ]] || continue

  domain="$(basename "$domain_dir")"

  for mailbox_dir in "$domain_dir"/*; do
    [[ -d "$mailbox_dir" ]] || continue

    user="$(basename "$mailbox_dir")"
    email="${user}@${domain}"
    archive="${ARCHIVE_ROOT}/${email}.sqlite"

    echo
    echo "========================================"
    echo "Migrating: $email"
    echo "========================================"

    echo "Importing Maildir..."
    vandelay import maildir \
      "$mailbox_dir" \
      "$archive"

    echo "Exporting to Stalwart..."
    vandelay export \
      --url "$STALWART_URL" \
      --auth-bearer \
      --account-name "$email" \
      "$archive"

    echo "Done: $email"
  done
done
