#!/usr/local/bin/php
<?php

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "This installer is CLI-only.\n");
    exit(64);
}

define('WP_INSTALLING', true);
require_once '/var/www/html/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/upgrade.php';

if (
    !extension_loaded('pdo_sqlite')
    || !defined('SQLITE_DRIVER_VERSION')
    || SQLITE_DRIVER_VERSION !== '3.1.1'
) {
    fwrite(STDERR, "Pinned SQLite integration is not active.\n");
    exit(1);
}

add_filter('pre_wp_mail', static function () {
    return true;
});

if (!is_blog_installed()) {
    $result = wp_install(
        'PHP2Shell WordPress Lab',
        'php2shell',
        'php2shell@example.invalid',
        false,
        '',
        'php2shell-lab-only'
    );

    if (is_wp_error($result)) {
        fwrite(STDERR, $result->get_error_message() . "\n");
        exit(1);
    }
}

update_option('template', 'php2shell-proof');
update_option('stylesheet', 'php2shell-proof');
update_option('blog_public', '0');
update_option('permalink_structure', '');

require_once ABSPATH . 'wp-admin/includes/plugin.php';
$sqlite_plugin = 'sqlite-database-integration/load.php';
if (!is_plugin_active($sqlite_plugin)) {
    $activation = activate_plugin($sqlite_plugin, '', false, true);
    if (is_wp_error($activation)) {
        fwrite(STDERR, $activation->get_error_message() . "\n");
        exit(1);
    }
}

if (!is_plugin_active($sqlite_plugin)) {
    fwrite(STDERR, "SQLite Database Integration activation did not persist.\n");
    exit(1);
}

$required_tables = array(
    $GLOBALS['wpdb']->options,
    $GLOBALS['wpdb']->posts,
    $GLOBALS['wpdb']->users,
);

foreach ($required_tables as $table) {
    $found = $GLOBALS['wpdb']->get_var(
        $GLOBALS['wpdb']->prepare('SHOW TABLES LIKE %s', $table)
    );

    if ($found !== $table) {
        fwrite(STDERR, "WordPress table missing after installation: {$table}\n");
        exit(1);
    }
}

if (!is_file(DB_PATH) || filesize(DB_PATH) < 4096) {
    fwrite(STDERR, "WordPress SQLite database file is missing or empty.\n");
    exit(1);
}

fwrite(STDOUT, "WordPress 7.1.3 SQLite database is ready.\n");
