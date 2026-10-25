<?php

namespace App\Controller;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Kernel as HttpKernel;

final class LabController
{
    public function index(): Response
    {
        return new Response(
            "php2shell symfony php-8.3.21 lab\n"
            ."symfony=".HttpKernel::VERSION."\n"
            ."php=".PHP_VERSION."\n"
            ."sapi=".PHP_SAPI."\n"
            ."kernel=booted\n",
            Response::HTTP_OK,
            ['Content-Type' => 'text/plain; charset=UTF-8'],
        );
    }
}
