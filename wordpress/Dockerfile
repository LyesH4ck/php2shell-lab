# syntax=docker/dockerfile:1
FROM --platform=linux/amd64 php:8.4.26-apache-bookworm@sha256:745ef8b8e5291613b7f3e78d470c1497941e2ab548c869a7b0b506889ce6a1b3 AS assets

ARG WORDPRESS_VERSION=7.1.3
ARG WORDPRESS_SHA256=d2a09acb6a15e3b9c471d72557753c266d6f41a79ed19bfe04cbfe49e283b2a5
ARG SQLITE_PLUGIN_VERSION=3.1.1
ARG SQLITE_PLUGIN_SHA256=5681502868907644ecc472739a75c72453b662c44bcc5dd7c1b1410f988bad44

# Network/download tooling exists only in this throw-away asset stage.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl unzip; \
    rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    curl --fail --location --silent --show-error --retry 5 \
      "https://wordpress.org/wordpress-${WORDPRESS_VERSION}.tar.gz" \
      --output /tmp/wordpress.tar.gz; \
    printf '%s  %s\n' "${WORDPRESS_SHA256}" /tmp/wordpress.tar.gz \
      | sha256sum -c -; \
    mkdir -p /out/wordpress; \
    tar -xzf /tmp/wordpress.tar.gz --strip-components=1 \
      -C /out/wordpress

RUN set -eux; \
    curl --fail --location --silent --show-error --retry 5 \
      "https://downloads.wordpress.org/plugin/sqlite-database-integration.${SQLITE_PLUGIN_VERSION}.zip" \
      --output /tmp/sqlite-database-integration.zip; \
    printf '%s  %s\n' "${SQLITE_PLUGIN_SHA256}" \
      /tmp/sqlite-database-integration.zip | sha256sum -c -; \
    unzip -q /tmp/sqlite-database-integration.zip \
      -d /out/wordpress/wp-content/plugins; \
    sed \
      -e 's|{SQLITE_IMPLEMENTATION_FOLDER_PATH}|/var/www/html/wp-content/plugins/sqlite-database-integration|g' \
      -e 's|{SQLITE_PLUGIN}|sqlite-database-integration/load.php|g' \
      /out/wordpress/wp-content/plugins/sqlite-database-integration/db.copy \
      > /out/wordpress/wp-content/db.php; \
    ! grep -q '{SQLITE_' /out/wordpress/wp-content/db.php

FROM --platform=linux/amd64 php:8.4.26-apache-bookworm@sha256:745ef8b8e5291613b7f3e78d470c1497941e2ab548c869a7b0b506889ce6a1b3

LABEL org.opencontainers.image.title="php2shell isolated WordPress vulnerable lab" \
      org.opencontainers.image.description="WordPress 7.1.3 with SQLite Integration 3.1.1 on deliberately vulnerable PHP 8.4.26 amd64" \
      org.opencontainers.image.base.digest="sha256:745ef8b8e5291613b7f3e78d470c1497941e2ab548c869a7b0b506889ce6a1b3" \
      org.opencontainers.image.version="7.1.3-sqlite3.1.1-php8.4.26-amd64" \
      io.php2shell.profile="wordpress-7.1.3-sqlite-3.1.1-php-8.4.26-amd64"

ENV PHP2SHELL_APACHE_WORKERS=1

# This is deliberately identical to the minimal lab's only runtime package.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends socat; \
    php -r 'exit(extension_loaded("pdo_sqlite") && extension_loaded("sqlite3") ? 0 : 1);'; \
    php -r 'exit(version_compare(SQLite3::version()["versionString"], "3.37.0", ">=") ? 0 : 1);'; \
    rm -rf /var/lib/apt/lists/*

COPY --from=assets /out/wordpress/ /var/www/html/

COPY config/zz-php2shell.ini /usr/local/etc/php/conf.d/zz-php2shell.ini
COPY config/zzz-display-errors-off.ini /usr/local/etc/php/conf.d/zzz-display-errors-off.ini
COPY config/ports.conf /etc/apache2/ports.conf
COPY config/php2shell.conf /etc/apache2/conf-available/php2shell.conf
COPY config/disabled-site.conf /etc/apache2/sites-available/000-default.conf
COPY container/entrypoint.sh /usr/local/bin/php2shell-entrypoint

COPY wordpress/wp-config.php /var/www/html/wp-config.php
COPY wordpress/index.php /var/www/html/index.php
COPY wordpress/install.php /opt/php2shell/wordpress/install.php
COPY wordpress/theme/php2shell-proof /var/www/html/wp-content/themes/php2shell-proof

RUN set -eux; \
    mkdir -p /var/lib/php2shell-wordpress; \
    chown -R root:root /var/www/html /var/lib/php2shell-wordpress; \
    find /var/www/html -type d -exec chmod 0755 '{}' +; \
    find /var/www/html -type f -exec chmod 0644 '{}' +; \
    chmod 0755 /usr/local/bin/php2shell-entrypoint; \
    chmod 0555 /opt/php2shell/wordpress/install.php; \
    chmod 0444 /var/www/html/wp-config.php; \
    a2enconf php2shell; \
    php -m | sha256sum | grep -q \
      '^0ced2e32cd135bf75be5b4793bd1ef05cdedbe15a6b3aadf02cbe3ac0979de68 '; \
    printf '%s  %s\n' \
      ff3ea77fb119541f6d10ddf0fa7e9e3fd6a3043e049a536b530dbbec35db68d6 \
      /usr/lib/apache2/modules/libphp.so | sha256sum -c -

EXPOSE 80
ENTRYPOINT ["/usr/local/bin/php2shell-entrypoint"]
