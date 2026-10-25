<?php

// PHP has already parsed multipart/form-data and run session upload-progress
// handling before userland reaches this branch. Keep the calibrated exploit
// POST path allocation-free; normal GETs below boot the complete Symfony app.
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    header('Content-Type: text/plain; charset=UTF-8');
    echo "php2shell symfony parser\n";
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
