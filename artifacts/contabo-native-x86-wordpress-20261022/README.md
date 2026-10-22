# Native x86_64 WordPress RCE receipt

This directory contains the evidence bundle emitted by the lab harness on
2026-10-22, plus this explanatory file and `environment.txt`. That environment
snapshot records native Linux x86_64, Docker Engine 29.1.3, the exact image ID,
PHP 8.4.26 Apache, WordPress 7.1.3, the loaded SQLite Database Integration
3.1.1 version, and the runtime hashes.

The tested command was `id`. Its output was returned directly in the terminal
RCE HTTP response:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

`result.json` contains the two disclosed address bases and records the complete
terminal HTTP response plus the final `RCE_OUTPUT_OBSERVED` result.
`environment.txt` hashes that raw response and its extracted command output.
`clean-terminal-evidence.json` verifies the same Apache worker before and after
the final request, an unchanged Apache error log, and a healthy follow-up GET
through the real WordPress/SQLite application. `clean-terminal-transcript.txt`
is the compact human-readable proof.

The leaked addresses are specific to this one ASLR layout and are not reusable
on another process. Fresh runs must perform both disclosures again.
