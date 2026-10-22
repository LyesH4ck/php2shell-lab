from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "php2shell_audit", ROOT / "scripts" / "php2shell-audit.py"
)
assert SPEC is not None and SPEC.loader is not None
audit = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = audit
SPEC.loader.exec_module(audit)


def response(method: str = "POST", status: int = 200):
    return audit.HTTPResult(
        method=method,
        url="http://127.0.0.1/index.php",
        status=status,
        headers={},
        body_bytes=0,
        body_sha256=audit.hashlib.sha256(b"").hexdigest(),
        truncated=False,
        elapsed_ms=1,
    )


def vulnerable_local():
    return {
        "configuration_scope": "shared-ini-likely",
        "runtime": {
            "php_version": "8.4.26",
            "ini": {
                "file_uploads": "1",
                "enable_post_data_reading": "1",
                "memory_limit": "128M",
                "session.upload_progress.enabled": "1",
            },
        },
        "apache": {"mod_php": True, "mpm_prefork": True},
    }


class VersionTests(unittest.TestCase):
    def test_official_fixed_boundaries(self):
        for branch, fixed in audit.PATCHED_RELEASES.items():
            with self.subTest(branch=branch):
                self.assertEqual(
                    audit.version_assessment(fixed)["status"],
                    "PATCHED_RELEASE",
                )
                previous = (fixed[0], fixed[1], fixed[2] - 1)
                self.assertEqual(
                    audit.version_assessment(previous)["status"],
                    "OFFICIAL_AFFECTED_RANGE",
                )

    def test_unsupported_branch_is_not_treated_as_safe(self):
        self.assertEqual(
            audit.version_assessment((8, 1, 99))["status"],
            "UNSUPPORTED_POTENTIALLY_AFFECTED",
        )


class ProbeTests(unittest.TestCase):
    def test_sensitive_response_headers_are_redacted(self):
        class Headers:
            def keys(self):
                return ["Set-Cookie", "Server"]

            def get_all(self, name):
                return {
                    "Set-Cookie": ["wordpress_logged_in=secret"],
                    "Server": ["Apache"],
                }[name]

        normalized = audit.normalize_headers(Headers())
        self.assertEqual(normalized["set-cookie"], ["<redacted:1>"])
        self.assertEqual(normalized["server"], ["Apache"])

    def test_multipart_is_tiny_and_benign(self):
        body, boundary, token = audit.safe_multipart()
        self.assertLess(len(body), 1024)
        self.assertIn(boundary.encode("ascii"), body)
        self.assertIn(token.encode("ascii"), body)
        self.assertIn(audit.SAFE_FILE_CONTENT, body)
        self.assertNotIn(b"Content-Length: 0", body)

    def test_confirmed_vulnerable_profile(self):
        result = audit.build_assessment(
            vulnerable_local(), None, [response()], True
        )
        self.assertEqual(result["verdict"], "VULNERABLE_PROFILE_CONFIRMED")
        self.assertIs(result["exploitable_assessment"], True)
        self.assertEqual(result["confidence"], "high")

    def test_blocked_path_does_not_claim_overall_safety(self):
        result = audit.build_assessment(
            vulnerable_local(), None, [response(status=403)], True
        )
        self.assertEqual(
            result["verdict"],
            "AFFECTED_VERSION_DEMONSTRATED_PATH_BLOCKED",
        )
        self.assertIsNone(result["exploitable_assessment"])

    def test_trusted_fixed_version_is_not_vulnerable(self):
        result = audit.build_assessment(None, "8.4.27", [], False)
        self.assertEqual(result["verdict"], "NOT_VULNERABLE_PATCHED_RELEASE")
        self.assertIs(result["exploitable_assessment"], False)


if __name__ == "__main__":
    unittest.main()
