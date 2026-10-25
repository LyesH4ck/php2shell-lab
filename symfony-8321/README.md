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
