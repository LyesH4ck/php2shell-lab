# Real WordPress reproduction profile

This profile installs a real WordPress site and database around the pinned
PHP2Shell target. It is deliberately vulnerable and is intended only for a
disposable local research host. The only published listener is host loopback,
`127.0.0.1:9091` by default.

## What is installed

- WordPress 7.1.3 from the official tarball, verified before extraction with
  SHA-256 `d2a09acb6a15e3b9c471d72557753c266d6f41a79ed19bfe04cbfe49e283b2a5`;
- PHP 8.4.26 Apache amd64 from the same pinned base and exact `libphp.so` as
  the minimal lab;
- the official WordPress SQLite Database Integration 3.1.1 plugin, whose
  archive is verified with SHA-256
  `5681502868907644ecc472739a75c72453b662c44bcc5dd7c1b1410f988bad44`;
- a minimal theme that performs a real `SELECT 1` through WordPress `$wpdb`
  and emits a deterministic health response.

The pinned PHP image already provides `PDO`, `pdo_sqlite`, and `sqlite3`.
No additional PHP extension is built or loaded, which preserves the calibrated
PHP/Apache module profile. This profile contains no MariaDB service and does
not use `mysqli`. The SQLite file is
`/var/lib/php2shell-wordpress/wordpress.sqlite`, in a container tmpfs outside
the web root; consequently there is no database TCP listener or port to
publish.

The database is initialized by WordPress's own installer. The lab admin is
`php2shell` with password `php2shell-lab-only`. These are intentionally public
lab-only credentials and must never be reused elsewhere.

## What the POST and GET paths prove

This reproduces a PHP request-parser vulnerability on a real WordPress site;
it is not a WordPress core, theme, or plugin vulnerability. PHP parses a
multipart request before it invokes any user PHP code. Therefore, on every POST
to this lab front controller, the vulnerable multipart parser has already run
when the controller immediately returns. WordPress is deliberately not
bootstrapped for those POSTs because its allocations and shutdown work would
perturb the calibrated heap geometry. This means the lab neutralizes normal
WordPress application POST actions by design.

Ordinary GET requests take the complete application path: they load the real
WordPress 7.1.3 installation, use the official SQLite integration, execute
`SELECT 1` through `$wpdb`, and render the installed proof theme. The exploit
harness performs this GET again after the terminal request. Thus the receipt
separately demonstrates the parser/RCE path and the healthy real WordPress
application path without claiming that WordPress itself causes the bug.

## Start on native Linux x86_64

From the repository root:

```sh
./scripts/wordpress-up.sh
./scripts/wordpress-status.sh
curl --noproxy '*' -fsS http://127.0.0.1:9091/index.php
```

The final command must return exactly:

```text
php2shell wordpress lab
wordpress=7.1.3
database=1
sqlite=1
```

Run one RCE attempt:

```sh
./scripts/wordpress-test.sh id
```

The calibrated command carrier is limited to 14 bytes. To request cold Apache
master retries for ASLR-dependent phase 2:

```sh
MAX_ATTEMPTS=8 ./scripts/wordpress-retry-test.sh id
```

Receipts are written below `results/wordpress/`. A passing receipt requires
command output in the complete terminal HTTP response, the same Apache worker
before and after the terminal request, an unchanged Apache error log, and the
exact WordPress/DB health response from the follow-up GET.

The repository includes one successful native x86_64 reference receipt in
[`artifacts/contabo-native-x86-wordpress-20261022/`](artifacts/contabo-native-x86-wordpress-20261022/).

## Multiworker prefork reproduction

WordPress uses one Apache prefork worker by default. To reproduce the chain
with several workers, export `PHP2SHELL_APACHE_WORKERS` before recreating the
stack. The accepted range is `1` through `16`; `1` is the default.

This four-worker example keeps the publication on loopback at
`127.0.0.1:9091`:

```sh
export PHP2SHELL_APACHE_WORKERS=4
./scripts/wordpress-down.sh
./scripts/wordpress-up.sh
MAX_ATTEMPTS=8 ./scripts/wordpress-retry-test.sh id
```

For `N` workers, the exploit harness parks `N-1` prefork children on retained
HTTP/1.1 connections. Each connection receives a complete benign `OPTIONS *`
request and its response is read before the connection is held with
keep-alive. Heartbeats verify and refresh every parked connection before the
exploit requests. This leaves exactly one free child for the parser/RCE chain;
if a parking connection closes, the attempt fails instead of silently losing
worker affinity.

Run this mode with zero concurrent traffic. Close browser tabs and do not run
health checks, crawlers, parallel curl commands, or a second exploit client
against the port during an attempt. Loopback-only publication prevents remote
access, but another local process could still consume the sole free worker and
invalidate the experiment.

The multiworker test path writes a dedicated receipt that records the total
worker count, the `N-1` parked workers, the prefork keep-alive fencing mode,
the terminal command output, and the follow-up WordPress response. This receipt
is deliberately different from the single-worker clean-terminal proof, which
can snapshot one sole worker PID before and after the terminal request. To
inspect a successful native four-worker run, see
[`artifacts/contabo-native-x86-wordpress-multiworker-20261022/`](artifacts/contabo-native-x86-wordpress-multiworker-20261022/). To
return to that proof protocol, unset the variable (or set it to `1`), then run
`wordpress-down.sh` and `wordpress-up.sh` again.

## Contabo native x86_64 host

The deployed reference checkout on `root@contabo` is
`/root/php2shell-wordpress-lab`. From an SSH session on that host:

```sh
cd /root/php2shell-wordpress-lab
uname -m
docker info --format '{{.OSType}} {{.Architecture}} {{.ServerVersion}}'
./scripts/wordpress-up.sh
./scripts/wordpress-status.sh
curl --noproxy '*' -fsS http://127.0.0.1:9091/index.php
./scripts/wordpress-test.sh id
```

The listener remains accessible only from Contabo's own loopback interface.
For the calibrated reference proof, both the host and Docker server must report
native `x86_64`/`amd64`; an emulated amd64 container is only a smoke test.

## macOS Apple Silicon or Linux ARM64

The amd64 containers can be used for installation and HTTP smoke testing when
the Docker backend supports emulation:

```sh
export ALLOW_EMULATION=1
./scripts/wordpress-up.sh
./scripts/wordpress-status.sh
curl --noproxy '*' -fsS http://127.0.0.1:9091/index.php
```

An RCE result under Rosetta or QEMU is not the reference proof. Run
`wordpress-test.sh` on native Linux x86_64 for the calibrated ASLR result.

## macOS Intel and Windows WSL2

On an Intel Mac, use the native commands above. On Windows, run the scripts
inside a WSL2 Linux shell with Linux-container integration. If the Windows
host is ARM64, export `ALLOW_EMULATION=1` and treat the result as a smoke test.

Confirm both host and Docker server architecture with:

```sh
uname -m
docker info --format '{{.OSType}} {{.Architecture}} {{.ServerVersion}}'
```

The reference platform reports `x86_64` or `amd64` and Docker Engine 28 or
newer.

## Change the loopback port

Export one value in the terminal and use it for every helper:

```sh
export PHP2SHELL_WORDPRESS_HOST_PORT=9191
./scripts/wordpress-up.sh
./scripts/wordpress-status.sh
curl --noproxy '*' -fsS http://127.0.0.1:9191/index.php
./scripts/wordpress-test.sh id
```

The host publication remains loopback-only. The internal target addresses,
Apache port, exploit URL path, and `Host: 127.0.0.1:8088` calibration are not
changed by this variable.

## Isolation and lifecycle

The target has no default route, host gateway, or host mount, and its root
filesystem is read-only. A restricted relay is the only service attached to
the ingress bridge. The SQLite database state lives in the target's dedicated
tmpfs outside `/var/www/html` and is recreated by `wordpress-up.sh` after
teardown. There is no separate database container and no database port.
Stopping or restarting the target discards that tmpfs; run `wordpress-up.sh`
to recreate a normal site. The retry helper performs that installation itself
after each deliberate cold-master restart.

The minimal and WordPress profiles intentionally reuse the calibrated private
addresses. Stop one profile before starting the other:

```sh
./scripts/down.sh
./scripts/wordpress-up.sh
```

Stop and remove the WordPress containers and private networks with:

```sh
./scripts/wordpress-down.sh
```

Evidence under `results/wordpress/` is preserved. The helper does not prune
images, volumes, or unrelated Docker resources.
