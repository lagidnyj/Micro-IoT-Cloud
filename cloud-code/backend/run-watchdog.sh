#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PHP_BIN=${PHP_BIN:-php}

if ! command -v "$PHP_BIN" >/dev/null 2>&1; then
    printf 'Error: PHP CLI not found: %s\n' "$PHP_BIN" >&2
    exit 127
fi

exec "$PHP_BIN" "$SCRIPT_DIR/watchdog.php"
