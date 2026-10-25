# Symfony validation receipts — 2026-10-25

Two Symfony labs were validated by a second agent and are published in this
repository:

- `symfony/` — Symfony 7.4.21 on the pinned `php:8.4.26-apache-bookworm`
  runtime (compose profile `docker-compose.symfony.yml`, loopback
  `127.0.0.1:9093`); the complete chain reuses this repository's
  `exploit/exploit_off.py` unchanged.
- `symfony-8321/` — Symfony 7.4.19 on `php:8.3.21-apache-bookworm`, a
  self-contained bundle with its own calibration (`CALIBRATION-PHP-8.3.21.md`,
  `COMPATIBILITY.md`): the PHP 8.3.21 heap profile required dedicated
  allocator adjustments (phase 2 `PS(mod_data)` shifted by one bin-40
  field, phase 3 bin-192 reference carrier) and a calibrated
  `exploit_generic.py` variant under `calibration/agent_psfiles/`.

Both labs keep the same topology rules as the WordPress profile: GET
requests boot the real Symfony kernel; multipart POST requests exit right
after the pre-userland parser stage so framework allocations do not perturb
the calibrated geometry.

## Fresh captures (this date)

Both labs were re-run from their published scripts immediately before this
commit; console captures are rendered as screenshots:

- `screenshots/rce-symfony-php-8.3.21.png` — four prefork workers, three
  parked by keep-alive fencing, `uid=33(www-data)` in the terminal HTTP
  response (`./scripts/test-multiworker.sh id` from `symfony-8321/`);
- `screenshots/rce-symfony-php-8.4.26.png` — single prefork worker,
  `uid=33(www-data)` (`./scripts/symfony-test.sh id` from the repository
  root).

Machine-checkable receipts of the same runs are kept inside each lab:
`symfony-8321/artifacts/multiworker-4-*` and `results/symfony/` for the
8.4.26 lab, including `result.json`, raw phase responses, parking
transcripts and verification JSON.

## Host-header constraint

Both calibrations send the HTTP `Host` header `127.0.0.1:8088`
(`--host-header`), pinned by their test scripts. The `Host` value
participates in the calibrated request allocation geometry: launching with
an arbitrary host can shift phase-1/2/3 landings and break the chain.
Keep the documented host exactly, or recalibrate.
