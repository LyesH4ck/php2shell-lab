# PHP2Shell isolated Docker lab

This directory installs the exact vulnerable PHP 8.4.26 amd64 profile used by
the calibrated PoC. It is deliberately vulnerable and, by default, publishes
the target on host loopback only: `127.0.0.1:9090`.

## Prerequisites

- Docker Engine 28 or newer (the isolated bridge gateway mode is required);
- either legacy `docker-compose` 1.29+ or current `docker compose`;
- Python 3 and curl on the host;
- a free unprivileged host loopback TCP port (`127.0.0.1:9090` by default).

The helper scripts automatically accept both Compose command styles. The
Compose file itself uses the legacy 2.4 format.

The legacy path has been verified with `docker-compose` 1.29.2 against Docker
Engine 29.1.3. A current Compose plugin remains preferred because Compose 1.29
is end-of-life.

The target image is always `linux/amd64`. Native Linux x86_64 is the reference
platform for the calibrated ASLR/RCE proof. Other platforms can run the target
for smoke testing as described below.

Check both the host shell and Docker server before starting:

```sh
uname -m
docker info --format '{{.OSType}} {{.Architecture}} {{.ServerVersion}}'
```

The Docker operating system must be `linux`. Docker Engine must report version
28 or newer.

For the reference proof, `uname -m` must report `x86_64` and Docker must report
`x86_64` or `amd64`. If the Docker server reports ARM64, the `linux/amd64`
image is emulated even when the shell itself reports `x86_64`.

Clone the repository once, then run the remaining commands from its root:

```sh
git clone https://github.com/LyesH4ck/php2shell-lab.git
cd php2shell-lab
```

## Real WordPress profile

A second Compose profile installs a complete WordPress 7.1.3 site with the
official SQLite Database Integration 3.1.1 plugin while retaining the exact
vulnerable PHP 8.4.26 runtime. The pinned PHP image already contains
`pdo_sqlite`, so this profile installs no additional PHP extension and uses
neither MariaDB nor `mysqli`. Its SQLite database lives in a tmpfs outside the
web root and no database port exists or is published:

```sh
./scripts/wordpress-up.sh
./scripts/wordpress-status.sh
curl --noproxy '*' -fsS http://127.0.0.1:9091/index.php
./scripts/wordpress-test.sh id
```

PHP parses each multipart POST before entering the front controller. After
that parser stage, all POST requests to this deliberately constrained lab exit
immediately without bootstrapping WordPress so the calibrated heap geometry is
preserved. Ordinary GET requests load the real WordPress installation and
theme and perform a real `SELECT 1` through `$wpdb`; the deterministic response
ends with `sqlite=1`.

A successful native x86_64 receipt, including the direct `id` output and the
clean-terminal verification, is stored under
[`artifacts/contabo-native-x86-wordpress-20261022/`](artifacts/contabo-native-x86-wordpress-20261022/).

On ARM64, prefix the start command with `ALLOW_EMULATION=1`; this validates the
site but is not a native-ASLR RCE proof. The minimal and WordPress profiles use
the same calibrated private addresses and must not run at the same time. See
[`WORDPRESS.md`](WORDPRESS.md) for architecture-specific commands, port
configuration, installation details, evidence requirements, and teardown.

## Instructions by operating system

| Test host | Start command | Supported use |
| --- | --- | --- |
| Linux x86_64/amd64 | `./scripts/up.sh` | Reference platform for the full RCE proof |
| macOS Apple Silicon (`arm64`) | `ALLOW_EMULATION=1 ./scripts/up.sh` | Target smoke tests; RCE/ASLR proof is not reliable |
| macOS Intel (`x86_64`) | `./scripts/up.sh` | Target and PoC testing; native Linux remains the reference proof platform |
| Windows x86_64 with WSL2 | Run `./scripts/up.sh` inside WSL2 | Target and PoC testing; native Linux remains the reference proof platform |
| Linux ARM64 | `ALLOW_EMULATION=1 ./scripts/up.sh` in a Linux shell | Target smoke tests only |
| Windows ARM64 with WSL2 | Run `ALLOW_EMULATION=1 ./scripts/up.sh` inside WSL2 | Target smoke tests only |

### Native Linux x86_64

No emulation flag is required:

```sh
./scripts/up.sh
./scripts/status.sh
curl --noproxy '*' -fsS http://127.0.0.1:9090/
./scripts/test.sh id
```

For multiple cold-master attempts:

```sh
MAX_ATTEMPTS=8 ./scripts/retry-test.sh id
```

### macOS Apple Silicon

Docker Desktop or OrbStack must be able to run `linux/amd64` images. Export the
emulation flag in the terminal used for the lab:

```sh
export ALLOW_EMULATION=1
./scripts/up.sh
./scripts/status.sh
curl --noproxy '*' -fsS http://127.0.0.1:9090/
```

The target can be built and exercised this way. A failure of `test.sh` under
Rosetta or QEMU does not disprove the vulnerability, and a result under
emulation is not the calibrated native-ASLR proof.

### macOS Intel

An Intel Mac should report `x86_64` from `uname -m`; no emulation override is
needed:

```sh
./scripts/up.sh
./scripts/status.sh
curl --noproxy '*' -fsS http://127.0.0.1:9090/
./scripts/test.sh id
```

### Windows with WSL2

Use a WSL2 Linux shell with Docker Desktop Linux-container integration. Do not
run the POSIX helper scripts directly from PowerShell or `cmd.exe`:

```sh
uname -m
./scripts/up.sh
./scripts/status.sh
curl --noproxy '*' -fsS http://127.0.0.1:9090/
./scripts/test.sh id
```

On a Windows ARM64 system, export `ALLOW_EMULATION=1` before `up.sh` and treat
the run as a smoke test only.

### Linux ARM64

The Docker server must have amd64 emulation available:

```sh
export ALLOW_EMULATION=1
./scripts/up.sh
./scripts/status.sh
curl --noproxy '*' -fsS http://127.0.0.1:9090/
```

This mode is for target smoke tests, not the calibrated RCE proof.

## Host port

The default is the unprivileged loopback port `127.0.0.1:9090`. It avoids the
privileged-port checks that can affect ports such as 80 and 443. It does not
require elevated privileges for the host port binding itself, although the
current user must still be allowed to access Docker. The target is never
published on a non-loopback address.

Port precedence is: `PHP2SHELL_HOST_PORT` from the current environment, then
`.env`, then the built-in default `9090`. Run `unset PHP2SHELL_HOST_PORT` before
relying on `.env` again.

To change the port for the current terminal session, export it before running
any helper script:

```sh
export PHP2SHELL_HOST_PORT=9191
./scripts/up.sh
./scripts/status.sh
curl --noproxy '*' -fsS http://127.0.0.1:9191/
./scripts/test.sh id
```

For a single command, prefix every helper invocation with the same value:

```sh
PHP2SHELL_HOST_PORT=9191 ./scripts/up.sh
PHP2SHELL_HOST_PORT=9191 ./scripts/status.sh
PHP2SHELL_HOST_PORT=9191 ./scripts/test.sh id
```

For a persistent local setting, edit `.env`:

```dotenv
COMPOSE_PROJECT_NAME=php2shell_lab
PHP2SHELL_HOST_PORT=9191
```

After changing `.env`, run `./scripts/down.sh` followed by `./scripts/up.sh` so
the relay is recreated with the new host-port mapping. Existing result files
are preserved.

Choose a free TCP port from 1024 through 65535. If `9090` is already in use,
`9091` or `19090` are reasonable alternatives. The port controls only the host
side of the loopback publication; the calibrated internal ports must not be
changed.

## Start and verify

```sh
./scripts/up.sh
./scripts/status.sh
```

The image is built from the pinned amd64 manifest of
`php:8.4.26-apache-bookworm`. The build refuses a `libphp.so` other than:

```text
ff3ea77fb119541f6d10ddf0fa7e9e3fd6a3043e049a536b530dbbec35db68d6
```

Apache remains on the calibrated in-container address `127.0.0.1:8088`. A
relay in the target forwards its internal port 80 to Apache, while a separate,
restricted Compose relay is attached to both the target network and a separate
ingress bridge. Docker publishes only the configured loopback host port
(`127.0.0.1:9090` by default) to port 80 of that relay, which forwards to the
target's fixed address.

The target network is both `internal` and configured with bridge gateway mode
`isolated`. Unlike a plain internal network, Docker assigns no address such as
`172.31.254.1` to the host bridge. The target therefore has neither a default
route nor a reachable host gateway. The relay does not share the host network
namespace; it runs only `socat` and has no privilege beyond
`NET_BIND_SERVICE`. Both root filesystems are read-only, capabilities are
reduced, and there are no host mounts or Docker socket access.

The scripts add no persistent firewall rule. Docker manages its ordinary
bridge publication and filtering rules for the lifetime of the Compose
networks. Before starting the vulnerable process, `up.sh` creates the stack in
stopped state and rejects a reused bridge without isolated gateway mode or a
relay publication other than loopback. `verify.sh` additionally checks the
live routes, absence of a gateway, inability to connect to
`172.31.254.1:22`, and the exact published address. Periodic HTTP health checks
remain disabled because unrelated requests would disturb the exploit's
calibrated worker state; `up.sh`, `status.sh`, and `test.sh` perform explicit
checks instead.

## Run the exploit

For the request-by-request root cause, address provenance, exact success
criteria and an agent-ready reproduction prompt, read
[`VULNERABILITY_CHAIN.md`](VULNERABILITY_CHAIN.md).

One attempt:

```sh
./scripts/test.sh id
```

Because the currently calibrated phase 2 depends on a favorable native ASLR
layout, a cold-master retry helper is included:

```sh
MAX_ATTEMPTS=8 ./scripts/retry-test.sh id
```

Each attempt uses a new directory under `results/`. For the terminal request,
the exploit publishes tokenized `before-rce-b` and `after-rce-b` marker
files and waits for `test.sh` to acknowledge each one. The harness snapshots
the sole Apache worker PID reported by `docker top`, then reads that worker's
PID-namespace PID and `/proc/PID/stat` field 22 from inside the container. It
also records container identity and the size, inode, and SHA-256 of
`/tmp/php2shell-apache-error.log` inside those two barriers. It then performs
one HTTP 200 follow-up GET and takes the same snapshot immediately afterwards.

A success requires command output in the complete terminal HTTP response, the
same worker process at all three snapshots, an unchanged Apache error log, and
the exact follow-up body. Any missing/late acknowledgement, snapshot error,
worker respawn, container restart, or log change fails closed. The receipt
keeps `terminal-sync.json`, the three `clean-terminal-*.json` snapshots,
`clean-terminal-evidence.json`, `clean-terminal-transcript.txt`, and the raw
follow-up headers/body. Cross-process ordering is verified with the recorded
Unix nanosecond timestamps; monotonic timestamps are retained as local
diagnostic metadata only.

The command carrier is limited to 14 bytes. The exploit is intentionally
restricted to loopback and private targets and is calibrated only for this
exact PHP build; it is not a generic all-version PHP exploit.

## Stop

```sh
./scripts/down.sh
```

This removes the lab containers and both Compose networks, but preserves all
receipts. It never runs `docker system prune` and never deletes images or
results.

If another host service already owns the configured host port, stop it or
choose another value with `PHP2SHELL_HOST_PORT` or in `.env`. Stopping this lab
does not restart unrelated host services.

## Troubleshooting

`This calibrated exploit requires native x86_64` on an ARM system means the
architecture guard is working. Use `ALLOW_EMULATION=1` only for the smoke-test
paths documented above.

`127.0.0.1:PORT is unavailable: [Errno 13] Permission denied` means the chosen
host port is privileged for the current user. Do not use `sudo`; reset the
session to the default unprivileged port:

```sh
export PHP2SHELL_HOST_PORT=9090
```

If port 9090 is busy, select another unprivileged port and use the same value
for `up.sh`, `status.sh`, and `test.sh`. An exported value overrides `.env`; use
`unset PHP2SHELL_HOST_PORT` to return to the value stored in `.env`.

Current Docker Compose releases may warn that the top-level `version` field is
obsolete. It is retained for legacy `docker-compose` 1.29 compatibility. The
warning is informational. On macOS, `DOCKER_INSECURE_NO_IPTABLES_RAW is set`
may also be printed by the Docker backend. Continue only when `up.sh` finishes
with `VERIFY_OK`; the verification result, rather than the warning alone,
determines whether the lab started with its expected isolation.

## Direct Compose commands

Legacy:

```sh
docker-compose up -d --build
docker-compose down
```

Direct `up` is supported, but `./scripts/up.sh` is recommended because it
performs the stopped-state network and publication checks before starting the
target.

Current:

```sh
docker compose -f docker-compose.yml up -d --build
docker compose -f docker-compose.yml down
```

## Sharing the lab

The clean modern distribution is a Git repository plus a prebuilt OCI image
published to a registry such as GHCR, pinned by digest and accompanied by an
SBOM and signature. This source-built bundle remains preferable while the PoC
is changing because every critical input and hash is locally auditable.

Loopback is an exposure boundary, not authentication: any process on the host,
or a host service with an SSRF primitive, may still reach the target. Run this
only on a disposable research VM.
