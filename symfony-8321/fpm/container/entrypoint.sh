#!/bin/sh
set -eu

mkdir -p /tmp/php2shell-sessions /var/run/php /var/www/html/public/proof
chmod 0777 /tmp/php2shell-sessions
chmod 0777 /var/www/html/public/proof

if [ "${1:-}" = php-fpm ]; then
    APP_ENV=prod APP_DEBUG=0 php -d memory_limit=256M \
        /var/www/html/bin/console cache:warmup --no-interaction
    chown -R www-data:www-data /var/www/html/var/cache /var/www/html/var/log
fi

exec docker-php-entrypoint "$@"
