# PHP 8.3.21 / Symfony 7.4.19 nginx-FPM replica

## Scope

This profile is an isolated, loopback-only reproduction. No OOM, crash, leak,
file-write, or RCE request was sent to the staging host. The remote host was
used only for a passive `phpinfo()` read and for interpreting the already
observed nginx 413 response.

The local profile reproduces these observed properties:

- PHP 8.3.21, NTS, `fpm-fcgi`, Linux amd64;
- nginx in front of PHP-FPM;
- Symfony 7.4.19 in production mode;
- `memory_limit=128M`, `post_max_size=8M`, `upload_max_filesize=2M`;
- `max_input_vars=1000`, `max_multipart_body_parts=-1`;
- `session.upload_progress.enabled=On` and cleanup enabled;
- file-backed sessions and `display_errors=Off` for HTTP requests.

The writable, PHP-served `public/proof/` tmpfs is an explicit laboratory
precondition. It is not evidence that the staging application exposes an
equivalent writable path.

## Four-worker topology and the 413 edge

```sh
./scripts/up-fpm.sh
./scripts/verify-fpm.sh
```

The target container has no published port. nginx alone is available on:

- `127.0.0.1:9195`: 512 KiB body cap, for deterministic nginx 413 responses;
- `127.0.0.1:9196`: 32 MiB local-origin cap, for controlled lab probes.

Change both ports before startup if needed:

```sh
export PHP2SHELL_FPM_BLOCKED_PORT=19195
export PHP2SHELL_FPM_ORIGIN_PORT=19196
./scripts/up-fpm.sh
```

An nginx 413 proves only that the edge rejected that body before PHP processed
it. It does not prove that PHP is patched, and it does not prove end-to-end RCE.
The local Assetnote scanner reproduces the distinction: the blocked port stops
at 413, while the open local origin reaches PHP-FPM and can recycle a worker.

## Calibrated RCE proof

Switch the same lab to its deterministic one-worker RCE profile:

```sh
./scripts/up-fpm-rce.sh
./scripts/test-fpm-rce.sh id
```

Validated output on native Contabo amd64:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The proof is pure HTTP. GDB was used only on a disposable calibration profile
to measure offsets; it is not used by `test-fpm-rce.sh`. The exploit
writes the session text to `/var/www/html/public/proof/shell.php`, requests that
file with `?0=id`, and returns the output directly. The next run removes the
old session and proof files first.

The measured profile for the pinned official PHP image is:

| Parameter | Value |
| --- | ---: |
| `PRIME_PRESS` | `700` |
| `FBASE` | `0x86018` |
| `E_OFF` | `0x96000` |
| `DT_OFF` | `0x8b000` |
| `SCALAR_PUSH` | `0x62058` |
| `ARRAY_PUSH` | `0x62050` |
| `WRITER` (`ps_files` start) | `0x57190` |
| fake `zend_string` | `DT+0x20` |

`WRITER` deliberately targets the start of `ps_files`: consecutive decoder
pushes replace `last_key` and then `basedir`. Pointing the first push directly
at `basedir` is incorrect and makes the worker abort during cleanup.

The exploit is derived from
[kengwang/php2shell-fpm-exp](https://github.com/kengwang/php2shell-fpm-exp) and
the FPM direction documented by
[Calif Research](https://calif.io/php2shell/). The upstream 8.4.4 constants do
not work on this official PHP 8.3.21 image; this bundle adds non-page-aligned
`FBASE` support and the build-specific calibration above.

## Multiworker lab proof

The ordinary replica uses four static workers. Direct request rotation was not
reliable: R2b could reach an unarmed child, and R3 could then wait on the
session lock until nginx returned 504. Two live layouts were measured:
`E/DT=0x96000/0x8b000` and `E/DT=0x93000/0x86000`.

The lab now includes an explicit worker-fencing endpoint. The runner opens
parking requests until the pool is full, discovers the live child count, then
releases one worker and runs the single-worker chain through that child:

```sh
./scripts/up-fpm-4worker-rce.sh
./scripts/test-fpm-4worker-rce.sh id

./scripts/up-fpm-6worker-rce.sh
./scripts/test-fpm-multiworker-rce.sh id
```

Contabo receipts confirmed complete RCE with both four and six configured
workers. A pool attempt can still select the alternate heap layout; the generic
runner therefore performs up to three clean attempts by default. Change it with:

```sh
export PHP2SHELL_FPM_POOL_ATTEMPTS=5
```

Therefore:

- four-worker mode accurately reproduces the edge, PHP-FPM worker recycling,
  and the deployment boundary;
- one-worker mode is the validated end-to-end file-write and command proof;
- fenced four- and six-worker modes are validated end-to-end in this lab;
- fencing depends on the added long-running endpoint and must not be presented
  as a generic remote technique;
- none of these results alone proves that an external deployment is exploitable.

`FPM-LEAK-RESEARCH.md` records the failed `Set-Cookie` and SAPI-header paths and
the validated replacement: a same-request body disclosure. The body PoC
returned HTTP 200 with 1,343,207 bytes and raw heap pointers through nginx on
Contabo. Run it with:

```sh
./scripts/test-fpm-body-leak.sh
```

The sink and local layout selector are deliberately lab-only; this result does
not yet establish a generic remote disclosure on an arbitrary Symfony route.

The same disclosure can be replayed without local process inspection once the
single-worker lab is running:

```sh
./scripts/test-fpm-body-leak-http.sh
```

This second client is one Python file, uses only HTTP, sprays every E/DT layout
observed for the pinned image, and validates the leak from the returned body.
It still depends on the explicit lab-only `/body-leak.php` sink.

The profiler-based variant removes that explicit sink and uses the real
WebProfilerBundle 7.4.19 controller instead:

```sh
./scripts/test-fpm-phpinfo-leak-http.sh
```

Its terminal output includes the decimal and hexadecimal pointer evidence plus
the inferred ZendMM base. The PoC never requests `/body-leak.php`.

Restore the four-worker topology with:

```sh
./scripts/up-fpm.sh
```
