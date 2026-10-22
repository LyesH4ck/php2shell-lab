# Safe PHP2Shell exposure checker

`scripts/php2shell-audit.py` assesses CVE-2026-109618 and
CVE-2026-109619 without attempting exploitation. It does not trigger OOM,
corrupt memory, leak an address, retire a worker, or execute a command.

## Why a remote-only yes/no answer is unsafe

WordPress does not normally expose the effective PHP patch level, SAPI, MPM,
or INI configuration. A hidden `X-Powered-By` header is not evidence that the
server is safe. Conversely, an HTML page without an upload form is not a
mitigation because PHP parses attacker-created multipart requests before
WordPress runs.

The checker therefore uses explicit verdicts:

- `VULNERABLE_PROFILE_CONFIRMED`: trusted local evidence places PHP in an
  official affected range and all safely observable conditions for the
  demonstrated mod_php/session-upload-progress path are present.
- `NOT_VULNERABLE_PATCHED_RELEASE`: a trusted PHP version is at or above the
  official fixed release.
- `AFFECTED_VERSION_DEMONSTRATED_PATH_BLOCKED`: PHP is old, but the exact
  multipart/session path is disabled or rejected. This is not a complete fix
  for the two advisories, so overall exploitability remains unknown.
- `AFFECTED_OR_AT_RISK_INCOMPLETE_EVIDENCE`: the version is affected or
  unsupported, but not every condition can be verified safely.
- `INDETERMINATE`: remote evidence is insufficient. This must never be
  interpreted as safe.

The official fixed releases are PHP 8.2.35, 8.3.36, 8.4.27, and 8.5.12.
Vendor packages may backport the fixes without changing the upstream-looking
version; verify the vendor advisory in that case.

## Recommended precise check

When Docker access is available, combine read-only container attestation with
the small HTTP probe:

```sh
python3 scripts/php2shell-audit.py \
  --docker-container php2shell-wordpress-lab \
  --url http://127.0.0.1:9091/index.php \
  --probe-multipart \
  --output results/php2shell-audit.json
```

The multipart request is roughly 500 bytes and contains one 21-byte text file.
It exercises ordinary request routing only. It has no oversized allocation,
malformed framing, exploit heap layout, or command payload.
It can create the same transient upload/session files as an ordinary tiny PHP
form submission; normal PHP cleanup applies. Response cookies are redacted
from the JSON report.

Docker evidence is collected using `docker inspect`, `php -r`, and
`apache2ctl -M` (or an equivalent Apache control binary). These operations are
read-only. On distributions where CLI and Apache load separate INI trees, the
report lowers confidence and states that the web configuration still needs
independent confirmation.

## Remote-only triage

The following performs only a GET:

```sh
python3 scripts/php2shell-audit.py \
  --url https://wordpress.example/ \
  --json
```

Add `--probe-multipart` only with authorization to send a benign POST to the
site. Remote mode can prove that a multipart request is blocked and may see a
PHP version advertised by headers, but it cannot reliably prove that a hidden
or vendor-patched runtime is vulnerable or safe. Expect `INDETERMINATE` when
the server does not disclose enough evidence.

If the trusted PHP version is already known:

```sh
python3 scripts/php2shell-audit.py --php-version 8.4.27
```

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | trusted version is an official patched release |
| `2` | checker/input/runtime error |
| `3` | indeterminate, incomplete evidence, or only one demonstrated path blocked |
| `10` | affected profile and all safely testable exploit conditions confirmed |

Only upgrading to a release containing the PHP fixes is a complete
remediation. Disabling `session.upload_progress.enabled` or blocking multipart
before PHP breaks the demonstrated session path but does not patch every path
covered by the advisories.

Official references:

- [CVE-2026-109618 / GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [CVE-2026-109619 / GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
