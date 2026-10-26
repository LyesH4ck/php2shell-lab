# PHP-FPM leak and worker-pool research

## Result

The public `PS(id)` / `Set-Cookie` ASLR leak is not directly portable from
Apache prefork to this nginx + PHP-FPM profile. Its stale state is produced
during request startup. PHP-FPM exits the child when `php_request_startup()`
fails, so a later request cannot consume that child's dangling `PS(id)`.

An additional nginx boundary was reproduced: a public 9bie leak body arrived
at nginx as chunked HTTP, but nginx forwarded its measured length to FastCGI.
PHP therefore rejected the 33,128,677-byte body against `post_max_size=8M`.
The response contained no `Set-Cookie` disclosure.

## Same-request FastCGI header experiment

The post-RINIT `BG(unserialize)` primitive was aimed at the first SAPI header
node instead of `ps_files`. On the pinned PHP 8.3.21 image:

- ZendMM main chunk header node: `heap+0x57000`;
- ordinary file-write target: `ps_files=heap+0x57190`;
- aiming R3 at `heap+0x57008` replaced the following header value pointer;
- PHP-FPM emitted bytes from the ZendMM heap as a FastCGI header;
- nginx rejected those bytes as an invalid upstream header and returned 502.

This proves a raw FastCGI-side read, but not a usable header leak: nginx returns
only 502 to the client.

## Same-request HTTP body disclosure

The nginx validation boundary was bypassed in the isolated Contabo lab by
moving the sink into the response body:

1. `/body-leak.php` consumes the multipart `BIG` value after parsing;
2. R3 places its sixteenth consecutive pointer write on the `len` member of
   BIG's `zend_string`;
3. PHP-FPM truncates that forged `size_t` to `uint32_t` in
   `sapi_cgibin_ub_write()`;
4. with a positive low 32-bit value, FPM streams the mapped ZendMM region until
   the first inaccessible page;
5. `fastcgi_buffering off` lets nginx preserve the valid partial HTTP 200 body.

Validated receipt on native Contabo amd64:

- client status: HTTP 200;
- client body: 1,343,207 bytes;
- first leaked qwords: `0x7fbf714643a0`, `0x7fbf714643c0`;
- nginx access-log body count: 1,345,824 bytes;
- the same FPM worker remained alive and served the following request;
- response SHA-256:
  `97f1408ab07c078da343a19885e096fe985b7a51cd5f21432ca55df0f95a5c6d`.

The binary receipt is stored under `artifacts/body-leak-http-200/response.bin`.
Run the complete lab proof with:

```sh
./scripts/test-fpm-body-leak.sh
```

The runner recreates only the loopback Docker lab, selects usable E/DT layouts
through local `/proc` inspection, and retries when the low ASLR bits would make
FastCGI interpret the truncated length as negative. The corruption requests
themselves are HTTP-only, but this orchestration is not a generic remote leak:
it depends on the lab-only body sink and local layout selection.

## HTTP-only PoC

The pinned lab now also has a single-file client that makes every exploit
decision from the HTTP response:

```sh
./scripts/test-fpm-body-leak-http.sh
```

`exploits/php8321_fpm_http_leak.py` uses only Python's standard library.
It does not invoke Docker, read `/proc`, or attach a debugger. Instead, each
forged multipart value contains the non-conflicting patches for all E/DT heap
profiles observed on this exact PHP 8.3.21 amd64 image. Fresh session IDs make
whole-chain retries safe. Success requires all of the following remote facts:

- HTTP status 200 and the body-sink marker;
- a response larger than the submitted `BIG` string;
- canonical user-space pointers in the returned bytes;
- at least two pointers in the same 2 MiB ZendMM region.

The validated HTTP-only receipt contained 1,343,207 bytes. Its first two
qwords were `0x7e903ee643a0` and `0x7e903ee643c0`, producing the common heap
base `0x7e903ee00000`.

This removes local layout inspection from the exploit path. It does not remove
the two remaining scope constraints: `/body-leak.php` is an explicit lab sink,
and the FastCGI signed-length truncation only emits a large body for favourable
low ASLR bits. The lab recreation runner can retry that ASLR draw; an arbitrary
remote service cannot be restarted by this client.

## WebProfiler `phpinfo` leak without `/body-leak.php`

The explicit body sink is no longer required when Symfony WebProfilerBundle
7.4.19 exposes its real `/_profiler/phpinfo` controller. The controller calls
`phpinfo()` and returns the captured HTML as a Symfony response. The working
chain avoids binary-string and output-buffering problems as follows:

1. `BIG` shapes the parser heap but is not reflected as the leaked value.
2. A completed nested upload named `pre[]` is sent before upload progress is
   enabled. PHP creates `$_FILES['pre']['error'][0]` as an `IS_LONG` zval.
3. The progress field is sent, followed by a second file that triggers R3.
4. R3 starts at `heap+0x622a0`; its eighteenth pointer lands on the integer
   value at `heap+0x62328`. The adjacent zval type remains `IS_LONG`.
5. `phpinfo()` formats that integer as decimal ASCII in the `$_FILES` table.
6. The client parses the decimal value and reconstructs the aligned ZendMM
   base without needing binary output or a forged response length.

Run the HTTP-only proof with:

```sh
./scripts/test-fpm-phpinfo-leak-http.sh
```

The validated response was HTTP 200 with 77,289 bytes. It contained decimal
`132471168115328`, which is `0x787b58eb2280`; the inferred 2 MiB heap base is
`0x787b58e00000`. nginx logged only `POST /_profiler/phpinfo`; no request used
`/body-leak.php`. The response SHA-256 is
`a439804d606b7d94a0ebd4bc972493d5a1936b0dbd397ce902a9b32d14985a63`.

This path no longer depends on favourable FastCGI signed-length ASLR bits. It
still depends on the pinned PHP build, its calibrated heap geometry, upload
progress being enabled, the real profiler route being exposed, and single
worker affinity (or an equivalent pool-fencing strategy).

## Pool-size discovery in the lab

The lab-only `/calibration-hold.php` endpoint sends its FPM PID and remains
active. `fpm_worker_fence.py --park auto` opens these requests until the next
one cannot obtain a child, thereby discovering the live pool size. It then
releases exactly one child and keeps `N-1` parked.

Validated results on Contabo native amd64:

- four workers discovered, three parked, end-to-end RCE succeeded;
- six workers discovered, five parked;
- the first six-worker run selected the alternate heap layout and failed;
- a fresh six-worker run completed the RCE and returned `uid=33(www-data)`.

This fencing mechanism is a deterministic lab aid, not a generic remote
primitive. An arbitrary deployment does not normally expose a long-running
PID endpoint, and occupying `N-1` real workers could degrade service.

## Remaining research question

A generic remote multiworker chain still needs one of:

1. a body sink already present in the application, or another generic output
   consumer equivalent to the lab's `$_POST['BIG']` echo;
2. a frontend-independent way to retain affinity to one FastCGI child; or
3. a first-shot layout strategy that does not use local `/proc` inspection and
   tolerates a miss without destroying the shared session record.

