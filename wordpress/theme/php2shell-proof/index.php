<?php

global $wpdb, $wp_version;

$database_ok = $wpdb->get_var('SELECT 1') === '1';
$sqlite_ok = extension_loaded('pdo_sqlite')
    && defined('SQLITE_DRIVER_VERSION')
    && SQLITE_DRIVER_VERSION === '3.1.1';

if (!$database_ok || !$sqlite_ok) {
    status_header(503);
}

header('Content-Type: text/plain; charset=UTF-8');
echo "php2shell wordpress lab\n";
printf("wordpress=%s\n", $wp_version);
printf("database=%d\n", $database_ok ? 1 : 0);
printf("sqlite=%d\n", $sqlite_ok ? 1 : 0);
