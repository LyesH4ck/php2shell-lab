# syntax=docker/dockerfile:1
FROM --platform=linux/amd64 composer:2.9.2 AS vendor

WORKDIR /app
COPY app/composer.json ./composer.json
COPY app/composer.lock ./composer.lock
RUN composer install --no-dev --no-interaction --no-progress --prefer-dist --classmap-authoritative
COPY app/ /app/
RUN composer dump-autoload --no-dev --no-interaction --classmap-authoritative && \
    APP_ENV=prod APP_DEBUG=0 php -d memory_limit=256M bin/console cache:warmup

FROM --platform=linux/amd64 php:8.3.21-fpm-bookworm@sha256:6c4391a739ec0a07c57f4f3af374c3262797f281207363bcf44c289bb4d7caa0

LABEL org.opencontainers.image.title="PHP2Shell Symfony nginx-FPM topology lab" \
      org.opencontainers.image.description="Loopback-only nginx/PHP-FPM reproduction based on the exposed staging phpinfo" \
      io.php2shell.profile="fpm-staging-php-8.3.21-fpm-amd64"

ENV APP_ENV=prod APP_DEBUG=0

COPY --from=vendor /app/ /var/www/html/
COPY fpm/public/plain.php /var/www/html/public/plain.php
COPY fpm/public/fpm-index.php /var/www/html/public/fpm-index.php
COPY fpm/public/body-leak.php /var/www/html/public/body-leak.php
COPY fpm/php/zz-fpm-phpinfo-profile.ini /usr/local/etc/php/conf.d/zz-fpm-phpinfo-profile.ini
COPY fpm/php/zzz-display-errors-off.ini /usr/local/etc/php/conf.d/zzz-display-errors-off.ini
COPY fpm/php/www.conf /usr/local/etc/php-fpm.d/www.conf
COPY fpm/container/entrypoint.sh /usr/local/bin/php2shell-fpm-entrypoint

RUN chown -R root:root /var/www/html && \
    find /var/www/html -type d -exec chmod 0755 '{}' + && \
    find /var/www/html -type f -exec chmod 0644 '{}' + && \
    chmod 0755 /var/www/html/bin/console /usr/local/bin/php2shell-fpm-entrypoint

EXPOSE 9000
ENTRYPOINT ["/usr/local/bin/php2shell-fpm-entrypoint"]
CMD ["php-fpm"]
