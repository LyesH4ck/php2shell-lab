# PHP2Shell isolated Docker lab

This directory installs the exact vulnerable PHP 8.4.26 amd64 profile used by
the calibrated PoC. It is deliberately vulnerable and publishes the target on
host loopback only: `127.0.0.1:80`.

## Prerequisites

- native Linux x86_64;
- Docker Engine 28 or newer (the isolated bridge gateway mode is required);
- either legacy `docker-compose` 1.29+ or current `docker compose`;
- Python 3 and curl on the host;
- free host TCP port `127.0.0.1:80`.

The helper scripts automatically accept both Compose command styles. The
Compose file itself uses the legacy 2.4 format.

The legacy path has been verified with `docker-compose` 1.29.2 against Docker
Engine 29.1.3. A current Compose plugin remains preferred because Compose 1.29
is end-of-life.

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
ingress bridge. Docker publishes only `127.0.0.1:80` to port 80 of that relay,
which forwards to the target's fixed address.

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

If another host service already owns port 80, stop it first or choose another
port in `.env`. Stopping this lab does not restart unrelated host services.

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
