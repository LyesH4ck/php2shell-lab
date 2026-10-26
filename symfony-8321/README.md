# Symfony 7.4.19 / PHP 8.3.21 amd64 lab

The requested `Symfony 7.14.19` release does not exist. Symfony publishes a
minor release every six months; this lab uses the existing `7.4.19` release as
the explicit interpretation of that version string. The lock file pins the
FrameworkBundle, HttpKernel, HttpFoundation, and Console components to 7.4.19.

This deliberately vulnerable laboratory runs the official PHP 8.3.21 Apache
image on native Linux amd64. A real Symfony kernel boots for GET requests. A
minimal POST branch leaves the pre-userland multipart/session parser observable
without adding framework allocations to the exploit path. The default Apache
prefork pool contains four workers.

The target has no published port and no default route. A separate relay exposes
only `127.0.0.1:9094` by default.

```sh
./scripts/up.sh
curl http://127.0.0.1:9094/index.php
./scripts/test-multiworker.sh id
./scripts/down.sh
```

Choose another loopback port with:

```sh
export PHP2SHELL_SYMFONY_8321_PORT=19094
./scripts/up.sh
```

Choose another fixed prefork-pool size with:

```sh
export PHP2SHELL_APACHE_WORKERS=6
./scripts/up.sh
./scripts/test-multiworker.sh id
```

`test-multiworker.sh` reads the exact worker count from the running container,
parks `N-1` workers on verified Apache keep-alive connections, and sends every
stateful exploit phase to the one remaining worker. It rejects empty output,
an incomplete terminal HTTP body, missing parking heartbeats, or a pool that
does not recover after the run. Raw responses and a JSON verification receipt
are retained under `artifacts/multiworker-*`.

The calibrated profile is specific to the pinned official PHP 8.3.21 amd64
image. It is not portable to arbitrary PHP builds. Four-worker RCE was
reproduced on the native Contabo host with three parked workers and direct
command output:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

See `CALIBRATION-PHP-8.3.21.md` for the calibration and `COMPATIBILITY.md` for
the exact portability boundary.

## nginx / PHP-FPM replica

The bundle also contains a separate nginx + PHP-FPM profile based on the
passively observed staging configuration: PHP 8.3.21, Symfony 7.4.19,
`memory_limit=128M`, `post_max_size=8M`, upload progress enabled, and errors
hidden from HTTP responses.

Start the four-worker topology replica and compare the blocked edge with the
open local origin:

```sh
./scripts/up-fpm.sh
./scripts/verify-fpm.sh
curl -i http://127.0.0.1:9195/fpm-index.php
curl -i http://127.0.0.1:9196/fpm-index.php
```

The calibrated RCE proof uses a separate one-worker pool while retaining the
same PHP image, Symfony application, nginx routing, ini values, and 128 MiB
limit:

```sh
./scripts/up-fpm-rce.sh
./scripts/test-fpm-rce.sh id
```

The command output is returned in the terminal and saved under
`artifacts/fpm-rce/command-output.txt`. Run `up-fpm.sh` again to
restore the ordinary four-worker topology. See `FPM-LAB.md` for the
observed configuration, calibrated offsets, 413 interpretation, and the
multiworker boundary.

The lab also contains a same-request HTTP body disclosure. It returns raw
ZendMM bytes through nginx rather than relying on an invalid FastCGI header:

```sh
./scripts/test-fpm-body-leak.sh
```

Successful responses and the JSON pointer check are written under
`artifacts/fpm-body-leak/`. This is a lab-calibrated proof: the runner
uses local `/proc` access to select a usable worker layout, and
`/body-leak.php` is an explicit lab-only sink. It must not be used as a generic
remote scanner.

To run the stricter single-file PoC, where exploitation uses only HTTP and
success is inferred only from returned bytes:

```sh
./scripts/test-fpm-body-leak-http.sh
```

The client has no Docker, `/proc`, or debugger dependency. It sprays the heap
profiles measured for this pinned PHP 8.3.21 amd64 image and saves the binary
receipt plus a JSON report under `artifacts/http-only-leak/`. The route remains
a lab-only body sink, so this command is not a generic remote scanner.

The preferred leak proof uses Symfony's real WebProfiler controller and does
not call `/body-leak.php`:

```sh
./scripts/test-fpm-phpinfo-leak-http.sh
```

It replaces the integer value in `$_FILES['pre']['error'][0]` with a heap
pointer. `phpinfo()` formats that value as decimal ASCII, and the client derives
the 2 MiB ZendMM base from the response. Exploitation remains HTTP-only and the
worker stays available. This profile requires the exposed
`/_profiler/phpinfo` route from WebProfilerBundle 7.4.19.

The lab-only worker-fencing profile now discovers the live pool size over HTTP
and leaves exactly one FPM child available. Both four- and six-child pools were
validated on Contabo:

```sh
./scripts/up-fpm-4worker-rce.sh
./scripts/test-fpm-4worker-rce.sh id

./scripts/up-fpm-6worker-rce.sh
./scripts/test-fpm-multiworker-rce.sh id
```

Set `PHP2SHELL_FPM_POOL_ATTEMPTS` to change the default three clean attempts.
The fence relies on the lab's `/calibration-hold.php` endpoint and is not a
generic technique for an arbitrary remote FPM deployment. See
`FPM-LEAK-RESEARCH.md` for the validated HTTP body disclosure and its current
portability boundary.
