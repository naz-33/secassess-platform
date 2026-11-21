#!/usr/bin/env sh
set -e

# Wait for MySQL to be reachable
host="${DB_HOST:-mysql}"
port="${DB_PORT:-3306}"
max_tries=30
tries=0

check_mysql() {
  if command -v mysqladmin >/dev/null 2>&1; then
    mysqladmin ping -h "$host" -P "$port" --silent
  else
    php -r "try { new PDO('mysql:host=${host};port=${port}', '${DB_USERNAME:-root}', '${DB_PASSWORD:-}'); exit(0); } catch (Throwable \$e) { exit(1); }" >/dev/null 2>&1
  fi
}

until check_mysql; do
  tries=$((tries+1))
  if [ $tries -ge $max_tries ]; then
    echo "MySQL not reachable after $max_tries attempts, exiting."
    exit 1
  fi
  echo "Waiting for MySQL at $host:$port... ($tries/$max_tries)"
  sleep 2
done

# Run migrations (force for non‑interactive containers)
php artisan migrate --force || true

# Create the storage symlink if it doesn't exist
php artisan storage:link || true

# Finally exec the passed CMD (usually `php artisan serve`)
exec "$@"
