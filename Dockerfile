# syntax=docker/dockerfile:1
FROM --platform=linux/amd64 php:8.4.26-apache-bookworm@sha256:745ef8b8e5291613b7f3e78d470c1497941e2ab548c869a7b0b506889ce6a1b3

LABEL org.opencontainers.image.title="php2shell isolated vulnerable lab" \
      org.opencontainers.image.description="Deliberately vulnerable PHP 8.4.26 amd64 research target" \
      org.opencontainers.image.base.digest="sha256:745ef8b8e5291613b7f3e78d470c1497941e2ab548c869a7b0b506889ce6a1b3" \
      io.php2shell.profile="php-8.4.26-amd64-clean-terminal"

# socat only bridges published port 80 to Apache's calibrated loopback-only
# listener on 127.0.0.1:8088. It does not alter the PHP binary.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends socat; \
    rm -rf /var/lib/apt/lists/*

COPY config/zz-php2shell.ini /usr/local/etc/php/conf.d/zz-php2shell.ini
COPY config/zzz-display-errors-off.ini /usr/local/etc/php/conf.d/zzz-display-errors-off.ini
COPY config/ports.conf /etc/apache2/ports.conf
COPY config/php2shell.conf /etc/apache2/conf-available/php2shell.conf
COPY config/disabled-site.conf /etc/apache2/sites-available/000-default.conf
COPY config/index.php /var/www/html/index.php
COPY container/entrypoint.sh /usr/local/bin/php2shell-entrypoint

RUN set -eux; \
    chmod 0755 /usr/local/bin/php2shell-entrypoint; \
    a2enconf php2shell; \
    printf '%s  %s\n' \
      ff3ea77fb119541f6d10ddf0fa7e9e3fd6a3043e049a536b530dbbec35db68d6 \
      /usr/lib/apache2/modules/libphp.so | sha256sum -c -

EXPOSE 80
ENTRYPOINT ["/usr/local/bin/php2shell-entrypoint"]

