# PHP2Shell lab test — 192.168.125.10

Date: 2026-10-26 (Europe/Paris)

## Target observed over HTTP

- URL: `http://192.168.125.10/index.php`
- Response: `HTTP/1.1 200 OK`, body `OK\n`
- Server: `Apache/2.4.69 (Debian)`
- Runtime header: `PHP/8.4.26`
- Effective OOM response: `memory_limit=8M`
- `display_errors=On`
- Externally measured prefork pool: one worker

## Results

The generic `display_errors=Off` profile did not obtain its expected
`Set-Cookie` disclosure and is not compatible with this target geometry.

The PHP 8.4.26 `display_errors=On` chain reached two real, in-band HTTP memory
disclosures:

- Zend MM chunk base: `0x717b64200000`
- leaked `zval_ptr_dtor`: `0x717b6652db60`
- inferred `libphp` base using the official-image offset `0x65eb60`:
  `0x717b65ecf000`

The stock phase-2 request (`N=983`, expanded array index `406`) was overwritten
by later parser allocations on this target. A same-length binary-search probe
confirmed index `406`; retaining it as the final allocation (`N=407`, `T=406`)
returned the expected 16-byte cookie:

```text
100000000000000060db52667b710000
```

Decoded:

```text
nNextFreeElement = 0x10
zval_ptr_dtor    = 0x717b6652db60
```

The published terminal geometry was then validated with:

```text
HTDATA = 0x717b642690d8   (chunk + 0x690d8)
ZIF    = 0x717b66334370   (libphp + 0x465370)
```

The relative-file and direct-response checks were initially inconclusive:
Apache's current directory was not known, and the worker terminated before
PHP flushed its buffered command output.

A filesystem-independent timing proof was then run on a verified fresh
worker with `sleep 5`. The rotation and terminal requests measured:

```text
rotation OOM       4.904 s   693-byte response
rotation cleanup   0.260 s   empty response (child aborted)
terminal A         3.056 s   367-byte OOM response
terminal B         5.220 s   empty response
```

The terminal B request normally closes in approximately `0.2 s`. Its
five-second delay matches the supplied command before the expected worker
termination. This confirms that `zif_system` was reached and that the command
was executed.

## Verdict

The two memory disclosures and full remote command execution are confirmed.
This is not a version-only finding.

The calibrated reproducer is:

```text
lab/offsec/rce_display_on.py
```

Default proof command: `sleep 5`. If Apache has just been restarted, use
`--assume-fresh` so no preliminary request consumes the first-request heap
layout.

The service recovered after the successful attempt. Later calibration retries
left the current child in a non-fresh heap state; restart Apache or its
container before recording a clean full-chain replay.

## Flag recovery

The command carrier was reused after the ASLR disclosures. `whoami` confirmed
execution as `www-data`. Root access was not required: a recursive inventory
found the world-readable proof at `/var/www/proof.txt`.

The short command `cat ../p*>f` copied it temporarily into the DocumentRoot:

```text
31050b60beddc661b64e11663431d2fa
```

The temporary `/var/www/html/f` artifact was removed after collection. Final
checks returned `404` for `/f` and `200` for `/index.php`.

The complete local-to-remote procedure is documented in
`lab/offsec/LOCAL_TO_REMOTE_WALKTHROUGH.md`.

## Existing raw logs

- `artifacts/remote-192.168.125.10-legacy8m-20261026T094732Z.log`
- `artifacts/remote-192.168.125.10-alvarodh5-20261026T094909Z.log`
- `docker/php2shell-lab/results/remote-192.168.125.10-20261026T094524Z/`

