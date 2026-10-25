# syntax=docker/dockerfile:1
FROM --platform=linux/amd64 composer:2.9.2 AS vendor

WORKDIR /app
COPY app/composer.json ./composer.json
COPY app/composer.lock ./composer.lock
RUN set -eux; \
    composer install \
      --no-dev \
      --no-interaction \
      --no-progress \
      --prefer-dist \
      --classmap-authoritative

COPY app/ /app/
RUN set -eux; \
    composer dump-autoload --no-dev --no-interaction --classmap-authoritative; \
    chmod 0755 bin/console; \
    APP_ENV=prod APP_DEBUG=0 php -d memory_limit=128M bin/console cache:warmup; \
    APP_ENV=prod APP_DEBUG=0 php -d memory_limit=128M bin/console about

FROM --platform=linux/amd64 php:8.3.21-apache-bookworm@sha256:21d7cc2cd70c79ae043b01448f6952f9681b18784472ec5a29769f83c1305831

LABEL org.opencontainers.image.title="PHP2Shell isolated Symfony 7.4.19/PHP 8.3.21 lab" \
      org.opencontainers.image.description="Real Symfony 7.4.19 app on deliberately vulnerable PHP 8.3.21 Apache amd64" \
      org.opencontainers.image.base.digest="sha256:21d7cc2cd70c79ae043b01448f6952f9681b18784472ec5a29769f83c1305831" \
      org.opencontainers.image.version="7.4.19-php8.3.21-amd64" \
      io.php2shell.profile="symfony-7.4.19-php-8.3.21-amd64"

ENV APP_ENV=prod \
    APP_DEBUG=0 \
    PHP2SHELL_APACHE_WORKERS=4

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends socat; \
    rm -rf /var/lib/apt/lists/*

COPY --from=vendor /app/ /var/www/html/
COPY config/zz-php2shell.ini /usr/local/etc/php/conf.d/zz-php2shell.ini
COPY config/zzz-display-errors-off.ini /usr/local/etc/php/conf.d/zzz-display-errors-off.ini
COPY config/ports.conf /etc/apache2/ports.conf
COPY config/php2shell-symfony.conf /etc/apache2/conf-available/php2shell.conf
COPY config/disabled-site.conf /etc/apache2/sites-available/000-default.conf
COPY container/entrypoint.sh /usr/local/bin/php2shell-entrypoint

RUN set -eux; \
    chown -R root:root /var/www/html; \
    find /var/www/html -type d -exec chmod 0755 '{}' +; \
    find /var/www/html -type f -exec chmod 0644 '{}' +; \
    chmod 0755 /var/www/html/bin/console /usr/local/bin/php2shell-entrypoint; \
    a2enconf php2shell; \
    APP_ENV=prod APP_DEBUG=0 php -d memory_limit=128M /var/www/html/bin/console about

EXPOSE 80
ENTRYPOINT ["/usr/local/bin/php2shell-entrypoint"]
