<?php

define('DB_NAME', 'wordpress');
define('DB_USER', 'unused');
define('DB_PASSWORD', 'unused');
define('DB_HOST', 'unused');
define('DB_CHARSET', 'utf8mb4');
define('DB_COLLATE', '');
define('DB_ENGINE', 'sqlite');
define('DB_PATH', '/var/lib/php2shell-wordpress/wordpress.sqlite');

define('AUTH_KEY',         'php2shell-wordpress-auth-key-lab-only');
define('SECURE_AUTH_KEY',  'php2shell-wordpress-secure-auth-key-lab-only');
define('LOGGED_IN_KEY',    'php2shell-wordpress-logged-in-key-lab-only');
define('NONCE_KEY',        'php2shell-wordpress-nonce-key-lab-only');
define('AUTH_SALT',        'php2shell-wordpress-auth-salt-lab-only');
define('SECURE_AUTH_SALT', 'php2shell-wordpress-secure-auth-salt-lab-only');
define('LOGGED_IN_SALT',   'php2shell-wordpress-logged-in-salt-lab-only');
define('NONCE_SALT',       'php2shell-wordpress-nonce-salt-lab-only');

$table_prefix = 'wp_';

define('WP_DEBUG', false);
define('WP_DEBUG_DISPLAY', false);
define('WP_ENVIRONMENT_TYPE', 'local');
define('WP_MEMORY_LIMIT', '40M');
define('WP_MAX_MEMORY_LIMIT', '128M');
define('DISABLE_WP_CRON', true);
define('DISALLOW_FILE_EDIT', true);
define('DISALLOW_FILE_MODS', true);
define('AUTOMATIC_UPDATER_DISABLED', true);
define('WP_AUTO_UPDATE_CORE', false);
define('WP_HTTP_BLOCK_EXTERNAL', true);
define('WP_DEFAULT_THEME', 'php2shell-proof');

$lab_url = getenv('PHP2SHELL_WORDPRESS_URL') ?: 'http://127.0.0.1:9091';

if (
    PHP_SAPI !== 'cli'
    && isset($_SERVER['HTTP_HOST'])
    && preg_match(
        '/\A(?:127\.0\.0\.1|localhost)(?::[0-9]{1,5})?\z/D',
        $_SERVER['HTTP_HOST']
    ) === 1
) {
    $lab_url = 'http://' . $_SERVER['HTTP_HOST'];
}

define('WP_HOME', $lab_url);
define('WP_SITEURL', $lab_url);

if (!defined('ABSPATH')) {
    define('ABSPATH', __DIR__ . '/');
}

require_once ABSPATH . 'wp-settings.php';
