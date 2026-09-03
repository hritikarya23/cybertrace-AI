#!/bin/sh
set -eu

echo "Applying database migrations..."
attempt=1
max_attempts=30
until alembic upgrade head; do
  if [ "$attempt" -ge "$max_attempts" ]; then
    echo "Database migrations failed after $max_attempts attempts." >&2
    exit 1
  fi
  echo "Database is not ready; retrying in 2 seconds ($attempt/$max_attempts)..."
  attempt=$((attempt + 1))
  sleep 2
done

exec "$@"
