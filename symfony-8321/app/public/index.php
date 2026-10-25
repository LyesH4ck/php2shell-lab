<?php

// Multipart parsing and upload-progress handling happen before userland.
// The POST branch intentionally avoids booting Symfony so the parser geometry
// can be compared with the existing calibrated laboratory profile.
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    // Keep the parser endpoint allocation-neutral. A userland header() call
    // allocates a SAPI header node after the multipart UAF and changes the
    // calibrated heap geometry on PHP 8.3.x.
    echo "php2shell symfony 8.3.21 parser\n";
    flush();
    exit;
}

ini_set('memory_limit', '128M');

use App\Kernel;
use Symfony\Component\HttpFoundation\Request;

require dirname(__DIR__).'/vendor/autoload.php';

$kernel = new Kernel('prod', false);
$request = Request::createFromGlobals();
$response = $kernel->handle($request);
$response->send();
$kernel->terminate($request, $response);
