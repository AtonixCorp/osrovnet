#!/usr/bin/env bash
set -euo pipefail

# Simple entrypoint for root image: run migrations then exec given CMD
: ${DJANGO_SETTINGS_MODULE:=osrovnet.settings}
export DJANGO_SETTINGS_MODULE

# Wait for DB (simple retry loop)
wait_for_db() {
  local max=30
  local i=0
  until python manage.py migrate --check >/dev/null 2>&1 || [ "$i" -ge "$max" ]; do
    echo "Waiting for DB... ($i/$max)"
    i=$((i+1))
    sleep 1
  done
}

# Run migrations then start process
if [ "$1" = "gunicorn" ]; then
  echo "Running migrations..."
  python manage.py migrate --noinput || true
  echo "Migrations done."
fi

exec "$@"
