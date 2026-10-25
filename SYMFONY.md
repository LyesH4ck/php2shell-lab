# Real Symfony reproduction profile

This profile runs a real Symfony 7.4.21 LTS application on the exact pinned
PHP 8.4.26 Apache amd64 runtime used by the calibrated PHP2Shell proof. It is
deliberately vulnerable and publishes only on host loopback,
`127.0.0.1:9093` by default.

The target is intended for an authorized, disposable lab only.

## What the two paths prove

Normal GET requests boot Symfony's kernel, resolve the configured route through
FrameworkBundle, invoke `App\Controller\LabController`, and return:

```text
php2shell symfony lab
symfony=7.4.21
php=8.4.26
kernel=booted
```

For POST requests, PHP parses multipart form data and session upload progress
before invoking `public/index.php`. The front controller exits immediately
after that parser stage, so Composer and Symfony allocations do not perturb the
calibrated exploit geometry. The PHP bug is not a Symfony vulnerability.

## Contabo: start and run the proof

From the deployed repository on `root@contabo`:

```sh
cd /root/php2shell-symfony-lab
uname -m
docker info --format '{{.OSType}} {{.Architecture}} {{.ServerVersion}}'
./scripts/symfony-up.sh
./scripts/symfony-status.sh
curl --noproxy '*' -fsS http://127.0.0.1:9093/index.php
./scripts/symfony-test.sh id
```

If the native ASLR layout is not favorable on the first cold Apache master,
use:

```sh
MAX_ATTEMPTS=8 ./scripts/symfony-retry-test.sh id
```

The command carrier is limited to 14 bytes. Receipts are stored under
`results/symfony/`.

## Multi-worker prefork proof

```sh
export PHP2SHELL_APACHE_WORKERS=4
./scripts/symfony-down.sh
./scripts/symfony-up.sh
MAX_ATTEMPTS=8 ./scripts/symfony-retry-test.sh id
```

The harness parks `N-1` workers on verified keep-alive connections and uses
the remaining worker for the stateful chain. Do not send concurrent traffic
during the proof.

## Change the loopback port

```sh
export PHP2SHELL_SYMFONY_HOST_PORT=9193
./scripts/symfony-up.sh
./scripts/symfony-status.sh
./scripts/symfony-test.sh id
```

The host publication remains loopback-only. Do not change the internal Apache
port or `Host: 127.0.0.1:8088`, because those values are part of the calibrated
profile.

## Other architectures

On Apple Silicon or Linux ARM64, use:

```sh
ALLOW_EMULATION=1 ./scripts/symfony-up.sh
```

This supports installation and HTTP smoke tests only. The reference leak and
RCE proof requires native Linux x86_64/amd64.

## Stop the lab

```sh
./scripts/symfony-down.sh
```

This removes only the Symfony containers and their private networks. Existing
receipts are preserved.
