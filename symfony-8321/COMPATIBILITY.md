# PHP 8.3.21 compatibility result

## Validated result

The original PHP 8.4.26 heap profile was not portable to PHP 8.3.21. A
dedicated calibration is now complete for the pinned official
`php:8.3.21-apache-bookworm` amd64 image.

The complete chain was validated first with one Apache prefork worker and then
with a fixed pool of four workers. The four-worker run parked three workers on
verified keep-alive connections and kept every stateful A/B pair on the fourth.
It returned an HTTP 200 response containing:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

After the run, all parking connections were closed, the Symfony GET endpoint
returned normally, and Apache again had four live worker children.

## Build boundary

The profile matches this exact `libphp.so`:

```text
build id          f2815d5ceefe3cfcb40bf2bbbe2b6357fecc4461
libphp.so SHA256  b359ebd17f6db814f85721a6c1c0245888413f42254638910207a4eb273a62c0
zif_system        0x3a20d0
zif_passthru      0x3a20e0
zval_ptr_dtor     0x4915f0
_zend_bailout     0x14e48a
```

The result does not imply portability to vendor rebuilds, patched PHP 8.3.21
packages, PHP-FPM, another architecture, or another allocator configuration.

## Validated deployment

```text
host architecture: x86_64
container image architecture: linux/amd64
PHP: 8.3.21 apache2handler
Symfony kernel: 7.4.19
display_errors: Off
memory_limit: 8M
workers: 4 (3 parked during the exploit)
published: 127.0.0.1:9094 only
```

Run `./scripts/verify.sh` for environment checks and
`./scripts/test-multiworker.sh id` for a fresh receipt.
