# syntax=docker/dockerfile:1
FROM --platform=linux/amd64 composer:2.9.2 AS vendor

WORKDIR /app
COPY symfony/app/composer.json symfony/app/composer.lock ./
RUN set -eux; \
    composer install \
      --no-dev \
      --no-interaction \
      --no-progress \
      --prefer-dist \
      --classmap-authoritative

COPY symfony/app/ /app/
RUN set -eux; \
    composer dump-autoload \
      --no-dev \
      --no-interaction \
      --classmap-authoritative; \
    chmod 0755 bin/console; \
    APP_ENV=prod APP_DEBUG=0 php -d memory_limit=128M bin/console cache:warmup; \
    APP_ENV=prod APP_DEBUG=0 php -d memory_limit=128M bin/console about

FROM --platform=linux/amd64 php:8.4.26-apache-bookworm@sha256:745ef8b8e5291613b7f3e78d470c1497941e2ab548c869a7b0b506889ce6a1b3

LABEL org.opencontainers.image.title="php2shell isolated Symfony vulnerable lab" \
      org.opencontainers.image.description="Symfony 7.4.21 LTS on deliberately vulnerable PHP 8.4.26 amd64" \
      org.opencontainers.image.base.digest="sha256:745ef8b8e5291613b7f3e78d470c1497941e2ab548c869a7b0b506889ce6a1b3" \
      org.opencontainers.image.version="7.4.21-php8.4.26-amd64" \
      io.php2shell.profile="symfony-7.4.21-php-8.4.26-amd64"

ENV APP_ENV=prod \
    APP_DEBUG=0 \
    PHP2SHELL_APACHE_WORKERS=1

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends socat; \
    rm -rf /var/lib/apt/lists/*

COPY --from=vendor /app/ /var/www/html/

COPY config/zz-php2shell.ini /usr/local/etc/php/conf.d/zz-php2shell.ini
COPY config/zzz-display-errors-off.ini /usr/local/etc/php/conf.d/zzz-display-errors-off.ini
COPY config/ports.conf /etc/apache2/ports.conf
COPY symfony/php2shell-symfony.conf /etc/apache2/conf-available/php2shell.conf
COPY config/disabled-site.conf /etc/apache2/sites-available/000-default.conf
COPY container/entrypoint.sh /usr/local/bin/php2shell-entrypoint

RUN set -eux; \
    chown -R root:root /var/www/html; \
    find /var/www/html -type d -exec chmod 0755 '{}' +; \
    find /var/www/html -type f -exec chmod 0644 '{}' +; \
    chmod 0755 /var/www/html/bin/console /usr/local/bin/php2shell-entrypoint; \
    a2enconf php2shell; \
    APP_ENV=prod APP_DEBUG=0 php -d memory_limit=128M /var/www/html/bin/console about; \
    php -m | sha256sum | grep -q \
      '^0ced2e32cd135bf75be5b4793bd1ef05cdedbe15a6b3aadf02cbe3ac0979de68 '; \
    printf '%s  %s\n' \
      ff3ea77fb119541f6d10ddf0fa7e9e3fd6a3043e049a536b530dbbec35db68d6 \
      /usr/lib/apache2/modules/libphp.so | sha256sum -c -

EXPOSE 80
ENTRYPOINT ["/usr/local/bin/php2shell-entrypoint"]
