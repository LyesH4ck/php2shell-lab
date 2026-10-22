# Native x86_64 WordPress multiworker receipt

This directory is the successful receipt produced on the isolated Contabo
native x86_64 lab by:

```sh
PHP2SHELL_APACHE_WORKERS=4 ./scripts/wordpress-up.sh
MAX_ATTEMPTS=8 ./scripts/wordpress-retry-test.sh id
```

The successful attempt was the fourth attempt in that retry run. The target
was WordPress 7.1.3 with SQLite Database Integration 3.1.1 on the pinned PHP
8.4.26 Apache build, published only on host loopback.

`multiworker-verification.json` records `verified: true`, four configured
prefork workers, three parked workers, a complete terminal HTTP response, and
an exact healthy WordPress follow-up response. `worker-parking.json` contains
the fail-closed heartbeat transcript and records three opened connections,
zero active connections after cleanup, and `closed: true`.

The observed command output was:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Its SHA-256 is
`6d99797c5e70f1676baffdaab9979d52aef4d97cb7c457054182abe6e4075c1e`.
The post-RCE WordPress body SHA-256 is
`0cab4b9edc46a4c17ba60cf00ebfb234eaec0abffa89e5c00bfa10aaf401b123`.

This is the dedicated multiworker fencing receipt. It is intentionally not
described as the separate single-worker clean-terminal observer proof.
