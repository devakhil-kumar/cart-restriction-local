#!/bin/bash

# Copy .env if not already present
[ -f .env ] || cp .env.example .env

# Create SQLite file if it doesn't exist
# if [ "$DB_CONNECTION" = "sqlite" ]; then
#     DB_PATH=${DB_DATABASE:-"/app/database/database.sqlite"}
#     if [ ! -f "$DB_PATH" ]; then
#         echo "Creating SQLite file at $DB_PATH"
#         mkdir -p "$(dirname "$DB_PATH")"
#         touch "$DB_PATH"
#     fi
# fi

# Generate app key if not present
php artisan key:generate --force
# php artisan migrate --force

# Laravel setup
php artisan config:cache
php artisan route:cache
php artisan view:cache

# Start queue in background
php artisan queue:work --daemon &

# Set secure permissions on JSON file if it exists
# [ -f storage/app/private/shops.json ] && chmod 600 storage/app/private/shops.json
[ -f /app/storage/shops.json ] && chmod 600 /app/storage/shops.json

# Create storage directory if it doesn't exist (Railway volume mount point)
mkdir -p /app/storage

# Start server
php -S 0.0.0.0:${PORT:-8000} -t public
