#!/usr/bin/env python3
"""Non-exploit PHP2Shell exposure checker.

The optional HTTP probe sends one tiny, benign multipart request.  It never
attempts OOM, memory disclosure, worker manipulation, or code execution.
Precise conclusions require trusted local/container evidence because a remote
WordPress response does not normally disclose the effective PHP configuration.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
from pathlib import Path
import re
import secrets
import ssl
import subprocess
import sys
import time
from typing import Any, Sequence
import urllib.error
import urllib.parse
import urllib.request


PATCHED_RELEASES = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}

ADVISORIES = (
    "CVE-2026-109618 / GHSA-w8hw-w9fx-j79w",
    "CVE-2026-109619 / GHSA-6wmf-4rv5-p3rp",
)

MAX_HTTP_RESPONSE = 65_536
SAFE_FILE_CONTENT = b"php2shell-safe-audit\n"


class AuditError(RuntimeError):
    pass


@dataclasses.dataclass
class HTTPResult:
    method: str
    url: str
    status: int
    headers: dict[str, list[str]]
    body_bytes: int
    body_sha256: str
    truncated: bool
    elapsed_ms: int

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


def parse_php_version(text: str) -> tuple[int, int, int] | None:
    match = re.search(r"(?<![0-9])(\d+)\.(\d+)\.(\d+)(?![0-9])", text)
    if not match:
        return None
    return tuple(int(value) for value in match.groups())


def render_version(version: tuple[int, int, int] | None) -> str | None:
    if version is None:
        return None
    return ".".join(str(value) for value in version)


def version_assessment(version: tuple[int, int, int] | None) -> dict[str, Any]:
    if version is None:
        return {
            "status": "UNKNOWN",
            "reason": "no PHP version was available",
            "patched_release": None,
        }
    branch = version[:2]
    patched = PATCHED_RELEASES.get(branch)
    if patched is not None:
        if version >= patched:
            return {
                "status": "PATCHED_RELEASE",
                "reason": (
                    f"PHP {render_version(version)} is at or above the official "
                    f"fixed release {render_version(patched)}"
                ),
                "patched_release": render_version(patched),
            }
        return {
            "status": "OFFICIAL_AFFECTED_RANGE",
            "reason": (
                f"PHP {render_version(version)} is below the official fixed "
                f"release {render_version(patched)}"
            ),
            "patched_release": render_version(patched),
        }
    if branch < (8, 2):
        return {
            "status": "UNSUPPORTED_POTENTIALLY_AFFECTED",
            "reason": (
                f"PHP {render_version(version)} predates the supported fixed "
                "branches; upgrade instead of treating it as safe"
            ),
            "patched_release": None,
        }
    return {
        "status": "UNKNOWN_BRANCH",
        "reason": (
            f"PHP branch {version[0]}.{version[1]} is not in this checker's "
            "pinned advisory table"
        ),
        "patched_release": None,
    }


def ini_bool(value: Any) -> bool | None:
    if value is None:
        return None
    normalized = str(value).strip().lower()
    if normalized in {"1", "on", "yes", "true"}:
        return True
    if normalized in {"", "0", "off", "no", "false", "none"}:
        return False
    return None


def finite_memory_limit(value: Any) -> bool | None:
    if value is None:
        return None
    normalized = str(value).strip().lower()
    if normalized == "-1":
        return False
    if re.fullmatch(r"[0-9]+(?:[kmgt])?", normalized):
        return True
    return None


def run_command(command: list[str], timeout: float = 15.0) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as error:
        raise AuditError(f"required command is unavailable: {command[0]}") from error
    except subprocess.TimeoutExpired as error:
        raise AuditError(f"command timed out: {' '.join(command)}") from error


def docker_evidence(container: str) -> dict[str, Any]:
    inspected = run_command(["docker", "inspect", container])
    if inspected.returncode != 0:
        raise AuditError(
            f"cannot inspect Docker container {container!r}: {inspected.stderr.strip()}"
        )
    try:
        metadata = json.loads(inspected.stdout)[0]
    except (json.JSONDecodeError, IndexError, TypeError) as error:
        raise AuditError("docker inspect returned invalid JSON") from error
    if not metadata.get("State", {}).get("Running"):
        raise AuditError(f"Docker container is not running: {container}")

    php_code = r'''
$keys = [
  "file_uploads",
  "enable_post_data_reading",
  "memory_limit",
  "post_max_size",
  "upload_max_filesize",
  "max_file_uploads",
  "max_input_vars",
  "session.upload_progress.enabled",
  "session.upload_progress.cleanup",
  "session.upload_progress.name",
  "session.save_handler",
  "session.save_path"
];
$ini = [];
foreach ($keys as $key) {
    $value = ini_get($key);
    $ini[$key] = $value === false ? null : $value;
}
echo json_encode([
  "php_version" => PHP_VERSION,
  "php_version_id" => PHP_VERSION_ID,
  "php_sapi" => PHP_SAPI,
  "thread_safety" => PHP_ZTS === 1,
  "ini_loaded_file" => php_ini_loaded_file() ?: null,
  "ini_scanned_files" => php_ini_scanned_files() ?: null,
  "ini" => $ini
], JSON_UNESCAPED_SLASHES);
'''
    php = run_command(["docker", "exec", container, "php", "-r", php_code])
    if php.returncode != 0:
        raise AuditError(
            f"cannot query PHP in {container!r}: {php.stderr.strip()}"
        )
    try:
        runtime = json.loads(php.stdout)
    except json.JSONDecodeError as error:
        raise AuditError("container PHP query returned invalid JSON") from error

    modules_text = ""
    modules_command = None
    for binary in ("apache2ctl", "apachectl", "httpd"):
        modules = run_command(["docker", "exec", container, binary, "-M"])
        if modules.returncode == 0:
            modules_command = binary
            modules_text = modules.stdout + modules.stderr
            break

    config_paths = "\n".join(
        value
        for value in (
            runtime.get("ini_loaded_file"),
            runtime.get("ini_scanned_files"),
        )
        if isinstance(value, str)
    )
    shared_ini_likely = "/cli/" not in config_paths.replace("\\", "/")

    return {
        "source": "docker-read-only-attestation",
        "container": container,
        "container_id": metadata.get("Id"),
        "image_id": metadata.get("Image"),
        "image_reference": metadata.get("Config", {}).get("Image"),
        "runtime": runtime,
        "apache": {
            "module_query": modules_command,
            "mod_php": bool(re.search(r"\bphp(?:[0-9]+)?_module\b", modules_text)),
            "mpm_prefork": "mpm_prefork_module" in modules_text,
            "mpm_event": "mpm_event_module" in modules_text,
            "mpm_worker": "mpm_worker_module" in modules_text,
        },
        "configuration_scope": (
            "shared-ini-likely" if shared_ini_likely else "cli-ini-may-differ"
        ),
        "configuration_scope_note": (
            "The PHP binary version is authoritative for this container. INI "
            "values are read through CLI; paths containing /cli/ may differ "
            "from the web SAPI configuration."
        ),
    }


def normalize_headers(headers: Any) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for name in headers.keys():
        values = headers.get_all(name) or []
        normalized_name = name.lower()
        if normalized_name in {"set-cookie", "proxy-authenticate"}:
            result[normalized_name] = [f"<redacted:{len(values)}>"]
        else:
            result[normalized_name] = [str(value) for value in values]
    return result


def http_request(
    url: str,
    method: str,
    timeout: float,
    insecure: bool,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> HTTPResult:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise AuditError("--url must be an absolute http:// or https:// URL")
    if parsed.username is not None or parsed.password is not None:
        raise AuditError("credentials embedded in --url are not supported")
    if parsed.fragment:
        raise AuditError("--url must not contain a fragment")

    context = None
    if parsed.scheme == "https":
        context = ssl.create_default_context()
        if insecure:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context), NoRedirect()
    )
    request_headers = {
        "Accept": "*/*",
        "Connection": "close",
        "User-Agent": "php2shell-safe-audit/1.0",
    }
    if headers:
        request_headers.update(headers)
    request = urllib.request.Request(
        url, data=body, headers=request_headers, method=method
    )
    started = time.monotonic()
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        response = error
    except (urllib.error.URLError, OSError) as error:
        raise AuditError(f"HTTP {method} failed: {error}") from error
    try:
        response_body = response.read(MAX_HTTP_RESPONSE + 1)
        status = int(response.status)
        response_headers = normalize_headers(response.headers)
    finally:
        response.close()
    elapsed_ms = round((time.monotonic() - started) * 1000)
    truncated = len(response_body) > MAX_HTTP_RESPONSE
    response_body = response_body[:MAX_HTTP_RESPONSE]
    return HTTPResult(
        method=method,
        url=url,
        status=status,
        headers=response_headers,
        body_bytes=len(response_body),
        body_sha256=hashlib.sha256(response_body).hexdigest(),
        truncated=truncated,
        elapsed_ms=elapsed_ms,
    )


def safe_multipart() -> tuple[bytes, str, str]:
    token = secrets.token_hex(16)
    boundary = f"php2shell-safe-audit-{secrets.token_hex(12)}"
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n'
        "\r\n"
        f"safe-audit-{token}\r\n"
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="php2shell_audit_file"; '
        'filename="audit.txt"\r\n'
        "Content-Type: text/plain\r\n"
        "\r\n"
    ).encode("ascii") + SAFE_FILE_CONTENT + (
        f"\r\n--{boundary}--\r\n"
    ).encode("ascii")
    return body, boundary, token


def versions_from_headers(results: list[HTTPResult]) -> list[str]:
    found: set[str] = set()
    for result in results:
        for name in ("x-powered-by", "server"):
            for value in result.headers.get(name, []):
                for match in re.finditer(
                    r"(?i)\bPHP[/ ](\d+\.\d+\.\d+)(?:[-+][^\s;]*)?", value
                ):
                    found.add(match.group(1))
    return sorted(found)


def build_assessment(
    local: dict[str, Any] | None,
    supplied_version: str | None,
    http_results: list[HTTPResult],
    multipart_requested: bool,
) -> dict[str, Any]:
    trusted_version_text = None
    trusted_source = None
    if local is not None:
        trusted_version_text = local.get("runtime", {}).get("php_version")
        trusted_source = "docker-container"
    elif supplied_version is not None:
        trusted_version_text = supplied_version
        trusted_source = "operator-supplied"

    header_versions = versions_from_headers(http_results)
    trusted_version = (
        parse_php_version(str(trusted_version_text))
        if trusted_version_text is not None
        else None
    )
    inferred_version = (
        parse_php_version(header_versions[0])
        if trusted_version is None and len(header_versions) == 1
        else None
    )
    effective_version = trusted_version or inferred_version
    version_result = version_assessment(effective_version)
    version_result.update(
        {
            "php_version": render_version(effective_version),
            "evidence_source": trusted_source or (
                "http-header" if inferred_version is not None else None
            ),
            "http_header_versions": header_versions,
            "trusted": trusted_version is not None,
        }
    )

    conditions: dict[str, Any] = {
        "mod_php": None,
        "mpm_prefork": None,
        "file_uploads": None,
        "enable_post_data_reading": None,
        "session_upload_progress_enabled": None,
        "finite_memory_limit": None,
        "memory_limit": None,
        "multipart_probe_requested": multipart_requested,
        "multipart_probe_reached_endpoint": None,
    }
    if local is not None:
        ini = local.get("runtime", {}).get("ini", {})
        apache = local.get("apache", {})
        conditions.update(
            {
                "mod_php": apache.get("mod_php"),
                "mpm_prefork": apache.get("mpm_prefork"),
                "file_uploads": ini_bool(ini.get("file_uploads")),
                "enable_post_data_reading": ini_bool(
                    ini.get("enable_post_data_reading")
                ),
                "session_upload_progress_enabled": ini_bool(
                    ini.get("session.upload_progress.enabled")
                ),
                "finite_memory_limit": finite_memory_limit(
                    ini.get("memory_limit")
                ),
                "memory_limit": ini.get("memory_limit"),
            }
        )
    post_results = [result for result in http_results if result.method == "POST"]
    if post_results:
        conditions["multipart_probe_reached_endpoint"] = (
            post_results[-1].status not in {400, 403, 405, 411, 413, 415, 429, 501}
            and post_results[-1].status < 500
        )

    version_status = version_result["status"]
    exact_path_values = (
        conditions["mod_php"],
        conditions["mpm_prefork"],
        conditions["file_uploads"],
        conditions["enable_post_data_reading"],
        conditions["session_upload_progress_enabled"],
        conditions["finite_memory_limit"],
        conditions["multipart_probe_reached_endpoint"],
    )
    if version_status == "PATCHED_RELEASE" and version_result["trusted"]:
        verdict = "NOT_VULNERABLE_PATCHED_RELEASE"
        exploitable = False
        confidence = "high"
        summary = "Trusted PHP version is in an official patched release."
    elif version_status == "OFFICIAL_AFFECTED_RANGE" and all(
        value is True for value in exact_path_values
    ):
        verdict = "VULNERABLE_PROFILE_CONFIRMED"
        exploitable = True
        confidence = (
            "high"
            if local and local.get("configuration_scope") == "shared-ini-likely"
            else "medium"
        )
        summary = (
            "The official affected version and every non-destructive condition "
            "for the demonstrated mod_php/session-upload-progress path are present."
        )
    elif version_status == "OFFICIAL_AFFECTED_RANGE" and any(
        value is False
        for value in (
            conditions["file_uploads"],
            conditions["enable_post_data_reading"],
            conditions["session_upload_progress_enabled"],
            conditions["multipart_probe_reached_endpoint"],
        )
    ):
        verdict = "AFFECTED_VERSION_DEMONSTRATED_PATH_BLOCKED"
        exploitable = None
        confidence = "medium"
        summary = (
            "PHP is in an affected release, but at least one condition for this "
            "specific multipart/session exploit path is disabled or blocked. "
            "Overall exploitability remains unknown because this is not "
            "equivalent to applying the PHP security patch."
        )
    elif version_status in {
        "OFFICIAL_AFFECTED_RANGE",
        "UNSUPPORTED_POTENTIALLY_AFFECTED",
    }:
        verdict = "AFFECTED_OR_AT_RISK_INCOMPLETE_EVIDENCE"
        exploitable = None
        confidence = "medium" if version_result["trusted"] else "low"
        summary = (
            "The available PHP version evidence is affected or unsupported, but "
            "the safe checks cannot prove every runtime condition."
        )
    elif version_status == "PATCHED_RELEASE":
        verdict = "LIKELY_PATCHED_REMOTE_VERSION"
        exploitable = None
        confidence = "low"
        summary = (
            "A response header advertises a patched PHP release, but remote "
            "headers are not trusted attestation."
        )
    else:
        verdict = "INDETERMINATE"
        exploitable = None
        confidence = "low"
        summary = (
            "A precise conclusion needs a trusted PHP version and effective "
            "server-side configuration evidence."
        )

    notes = [
        "No exploitation, OOM, memory disclosure, worker retirement, or RCE was attempted.",
        "WordPress version and the presence of an upload form do not determine exposure; PHP parses multipart before application code.",
        "Vendor backports can make an older-looking package safe. Confirm the vendor security status when PHP_VERSION is below the upstream fixed release.",
        "Only upgrading to a patched PHP release is a complete mitigation for these advisories.",
    ]
    if local and local.get("configuration_scope") == "cli-ini-may-differ":
        notes.append(
            "Container INI evidence came from a CLI-specific path and may differ from mod_php."
        )

    return {
        "verdict": verdict,
        "exploitable_assessment": exploitable,
        "confidence": confidence,
        "summary": summary,
        "version": version_result,
        "demonstrated_path_conditions": conditions,
        "notes": notes,
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description=(
            "Safely assess exposure to CVE-2026-109618/109619 without "
            "triggering OOM, memory disclosure, or RCE"
        )
    )
    result.add_argument("--url", help="WordPress/PHP endpoint to inspect")
    result.add_argument(
        "--docker-container",
        metavar="NAME",
        help="read-only local attestation from the web container",
    )
    result.add_argument(
        "--php-version",
        metavar="VERSION",
        help="trusted operator-supplied PHP version when Docker evidence is unavailable",
    )
    result.add_argument(
        "--probe-multipart",
        action="store_true",
        help=(
            "send one tiny benign multipart POST (about 500 bytes); never sends "
            "OOM/leak/RCE payloads"
        ),
    )
    result.add_argument(
        "--timeout", type=float, default=10.0, help="HTTP/command timeout in seconds"
    )
    result.add_argument(
        "--insecure", action="store_true", help="disable HTTPS certificate validation"
    )
    result.add_argument(
        "--output", metavar="FILE", help="write the full JSON report to FILE"
    )
    result.add_argument(
        "--json", action="store_true", help="print the full JSON report"
    )
    return result


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        if not arguments.url and not arguments.docker_container and not arguments.php_version:
            raise AuditError(
                "provide at least one of --url, --docker-container, or --php-version"
            )
        if arguments.probe_multipart and not arguments.url:
            raise AuditError("--probe-multipart requires --url")
        if arguments.timeout <= 0:
            raise AuditError("--timeout must be positive")
        supplied_version = None
        if arguments.php_version:
            parsed_version = parse_php_version(arguments.php_version)
            if parsed_version is None:
                raise AuditError("--php-version must contain MAJOR.MINOR.PATCH")
            supplied_version = render_version(parsed_version)

        local = (
            docker_evidence(arguments.docker_container)
            if arguments.docker_container
            else None
        )
        http_results: list[HTTPResult] = []
        safe_probe: dict[str, Any] | None = None
        if arguments.url:
            http_results.append(
                http_request(
                    arguments.url,
                    "GET",
                    arguments.timeout,
                    arguments.insecure,
                )
            )
        if arguments.probe_multipart:
            body, boundary, token = safe_multipart()
            safe_probe = {
                "body_bytes": len(body),
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "file_bytes": len(SAFE_FILE_CONTENT),
                "safety": (
                    "one tiny benign file part; no OOM, malformed framing, "
                    "memory leak, worker manipulation, or code payload"
                ),
            }
            http_results.append(
                http_request(
                    arguments.url,
                    "POST",
                    arguments.timeout,
                    arguments.insecure,
                    body=body,
                    headers={
                        "Content-Type": f"multipart/form-data; boundary={boundary}",
                        "Cookie": f"PHPSESSID=php2shellaudit{token}",
                        "X-PHP2Shell-Audit": "safe-no-exploit",
                    },
                )
            )

        report = {
            "schema": "php2shell-safe-audit/v1",
            "generated_unix": int(time.time()),
            "advisories": list(ADVISORIES),
            "safety": {
                "exploit_attempted": False,
                "oom_attempted": False,
                "memory_disclosure_attempted": False,
                "command_execution_attempted": False,
            },
            "assessment": build_assessment(
                local, supplied_version, http_results, arguments.probe_multipart
            ),
            "local_evidence": local,
            "http": [result.as_dict() for result in http_results],
            "safe_multipart_probe": safe_probe,
        }
        rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if arguments.output:
            output = Path(arguments.output).expanduser()
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(rendered, encoding="utf-8")
        if arguments.json:
            print(rendered, end="")
        else:
            assessment = report["assessment"]
            print(f"VERDICT={assessment['verdict']}")
            print(f"CONFIDENCE={assessment['confidence']}")
            exploitable = assessment["exploitable_assessment"]
            print(
                "EXPLOITABLE_ASSESSMENT="
                + ("UNKNOWN" if exploitable is None else ("YES" if exploitable else "NO"))
            )
            version = assessment["version"].get("php_version") or "unknown"
            print(f"PHP_VERSION={version}")
            print(f"SUMMARY={assessment['summary']}")
            if arguments.output:
                print(f"REPORT={Path(arguments.output).expanduser()}")
        verdict = report["assessment"]["verdict"]
        if verdict == "VULNERABLE_PROFILE_CONFIRMED":
            return 10
        if verdict in {
            "AFFECTED_VERSION_DEMONSTRATED_PATH_BLOCKED",
            "AFFECTED_OR_AT_RISK_INCOMPLETE_EVIDENCE",
            "INDETERMINATE",
            "LIKELY_PATCHED_REMOTE_VERSION",
        }:
            return 3
        return 0
    except (AuditError, UnicodeError, OSError) as error:
        print(f"AUDIT_ERROR={error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("AUDIT_ERROR=interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
