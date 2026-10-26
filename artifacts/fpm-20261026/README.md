# PHP-FPM chain receipts — 2026-10-26

Second-agent research published with this commit, sanitized of any external
host reference: the nginx + PHP-FPM profile under `symfony-8321/fpm/`
reproduces the properties of an observed
staging deployment (PHP 8.3.21 FPM, Symfony 7.4.19, 128M/8M/2M ini,
nginx in front). No exploit request was ever sent to that deployment; only
a passive `phpinfo()` read was used to build the replica.

## What was validated (fresh runs, this date, loopback lab only)

1. **Heap-base disclosure through the real Symfony WebProfiler route**
   (`./scripts/test-fpm-phpinfo-leak-http.sh`, HTTP-only client,
   no local process inspection): a same-request `BG(unserialize)`
   reclaim lands its eighteenth pointer write on the `IS_LONG` zval of
   `$_FILES['pre']['error'][0]`; `phpinfo()` formats it as decimal ASCII;
   the client reconstructs the 2 MiB ZendMM base from the response body.
   Fresh receipt: `symfony-8321/artifacts/http-only-leak/phpinfo.json`
   (`success: true`, pointer `0x7373590b2280`, base `0x737359000000`).
2. **Full FPM RCE** (`./scripts/test-fpm-rce.sh id`): the calibrated
   stale-decoder chain ends in a file-write terminal served from the
   webroot; `uid=33(www-data)` in the response (receipt
   `symfony-8321/artifacts/fpm-rce/command-output.txt`).

Screenshots: `screenshots/leak-fpm-phpinfo.png` and
`screenshots/rce-fpm-php8321.png`.

Full research log, failed `Set-Cookie`/FastCGI-header paths, and the
multiworker fencing results: `symfony-8321/FPM-LEAK-RESEARCH.md` and
`symfony-8321/FPM-LAB.md`.

## Scope honesty

- All results are lab-only (loopback, pinned `php:8.3.21-fpm-bookworm`
  image). They demonstrate the FPM branch of the PHP2Shell chain on this
  profile; they do not by themselves prove that any external deployment is
  exploitable (pool affinity, build identity and writable webroot remain
  deployment-dependent).
- The remote-host hostname that motivated this profile was removed from
  every file, script, container name and receipt before publication.
