<?php
// PHP has already parsed multipart/form-data and run upload-progress handling
// before userland reaches this branch.  Keep exploit POSTs minimal so the
// forged request state is not disturbed by the full WordPress bootstrap.
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    header('Content-Type: text/plain; charset=UTF-8');
    echo "php2shell wordpress parser\n";
    exit;
}

ini_set('memory_limit', '40M');
define('WP_USE_THEMES', true);
require __DIR__ . '/wp-blog-header.php';
