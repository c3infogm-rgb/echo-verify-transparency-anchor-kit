"""Acceptance tests for the transparency anchor verifier (Stage (1)A v0.1).

These cover the four conditions in the work order:
  1. normal    -- after anchoring, verify returns PASS
  2. tampered  -- flip one byte of the target -> FAIL
  3. missing   -- remove a side-car -> HOLD (one system left) or FAIL (none)
  4. hash tie  -- anchor_record.target_sha256 equals the real file sha256

The tests are hermetic: cosign/openssl crypto re-verification is stubbed out so
the deterministic *linkage* logic is what is exercised (matching how the tool
behaves offline). Full crypto verification is Jun's job at anchor time.
"""
import base64
import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.anchor import verify_anchor


def _rekor_bundle(sha: str, log_index: int = 42) -> dict:
    body = base64.b64encode(json.dumps({
        "apiVersion": "0.0.1",
        "kind": "hashedrekord",
        "spec": {
            "data": {"hash": {"algorithm": "sha256", "value": sha}},
            "signature": {"content": "AAAA", "publicKey": {"content": "AAAA"}},
        },
    }).encode("utf-8")).decode("ascii")
    return {
        "base64Signature": "AAAA",
        "cert": "AAAA",
        "rekorBundle": {
            "SignedEntryTimestamp": "AAAA",
            "Payload": {
                "body": body,
                "integratedTime": 1720000000,
                "logIndex": log_index,
                "logID": "deadbeef",
            },
        },
    }


def _rekor_bundle_v03() -> dict:
    return {
        "mediaType": verify_anchor.SIGSTORE_BUNDLE_V03_MEDIA_TYPE,
        "verificationMaterial": {
            "certificate": {},
            "tlogEntries": [],
            "timestampVerificationData": {},
        },
        "messageSignature": {
            "messageDigest": {},
            "signature": "...",
        },
    }


def _rfc3161_token(sha: str) -> bytes:
    # A stand-in DER blob that embeds the messageImprint digest octets, which is
    # what the offline linkage check looks for.
    return b"\x30\x82STUB-TST" + bytes.fromhex(sha) + b"TRAILER"


class AnchorFixture:
    def __init__(self, root: Path, *, target_bytes: bytes = b'{"kit":"demo"}\n',
                 with_rekor: bool = True, with_rfc3161: bool = True,
                 rekor_bundle=None):
        self.root = root
        self.tdir = root / "transparency"
        self.tdir.mkdir(parents=True, exist_ok=True)
        self.target = root / "run_manifest.json"
        self.target.write_bytes(target_bytes)
        self.sha = hashlib.sha256(target_bytes).hexdigest()

        records = []
        if with_rekor:
            (self.tdir / verify_anchor.REKOR_BUNDLE_NAME).write_text(
                json.dumps(rekor_bundle or _rekor_bundle(self.sha)),
                encoding="utf-8")
            records.append({"type": "sigstore_rekor", "log_index": 42,
                            "bundle_path": "transparency/rekor_bundle.json",
                            "verify_command": "cosign verify-blob ..."})
        if with_rfc3161:
            (self.tdir / verify_anchor.RFC3161_TOKEN_NAME).write_bytes(
                _rfc3161_token(self.sha))
            records.append({"type": "rfc3161", "tsa": "freetsa.org",
                            "token_path": "transparency/rfc3161_token.tsr",
                            "verify_command": "openssl ts -verify ..."})

        self.record_path = self.tdir / "anchor_record.json"
        self.record_path.write_text(json.dumps({
            "target_file": "run_manifest.json",
            "target_path": str(self.target),
            "target_sha256": self.sha,
            "anchored_at": "2026-07-07T00:00:00Z",
            "records": records,
            "claim_boundary": "existence + integrity + time only.",
        }), encoding="utf-8")


class TestAnchorVerify(unittest.TestCase):
    def setUp(self):
        # Isolate the deterministic linkage logic from any real cosign/openssl.
        self._saved = (verify_anchor._cosign_verify_blob,
                       verify_anchor._openssl_ts_verify)
        verify_anchor._cosign_verify_blob = lambda *a, **k: None
        verify_anchor._openssl_ts_verify = lambda *a, **k: None
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        verify_anchor._cosign_verify_blob, verify_anchor._openssl_ts_verify = self._saved
        self._tmp.cleanup()

    # 1. normal system: anchored -> PASS
    def test_normal_pass(self):
        fx = AnchorFixture(self.root)
        result = verify_anchor.evaluate(fx.record_path)
        self.assertEqual(result["verdict"], verify_anchor.PASS, result)
        self.assertEqual(result["records"]["sigstore_rekor"]["log_index"], 42)

    # 4. the recorded hash equals the real file hash
    def test_target_sha256_matches_file(self):
        fx = AnchorFixture(self.root)
        record = json.loads(fx.record_path.read_text(encoding="utf-8"))
        self.assertEqual(record["target_sha256"],
                         verify_anchor.sha256_file(fx.target))

    # 2. tampered target: one byte changed -> FAIL
    def test_tamper_target_fails(self):
        fx = AnchorFixture(self.root)
        fx.target.write_bytes(fx.target.read_bytes() + b"X")  # +1 byte
        result = verify_anchor.evaluate(fx.record_path)
        self.assertEqual(result["verdict"], verify_anchor.FAIL, result)
        self.assertIn(verify_anchor.RC_TARGET_HASH_MISMATCH, result["reasons"])

    # 2b. rekor bundle committing to the wrong hash -> FAIL
    def test_rekor_wrong_hash_fails(self):
        fx = AnchorFixture(self.root)
        wrong = "0" * 64
        (fx.tdir / verify_anchor.REKOR_BUNDLE_NAME).write_text(
            json.dumps(_rekor_bundle(wrong)), encoding="utf-8")
        result = verify_anchor.evaluate(fx.record_path)
        self.assertEqual(result["verdict"], verify_anchor.FAIL, result)
        self.assertIn(verify_anchor.RC_REKOR_HASH_MISMATCH, result["reasons"])

    def test_v03_bundle_cosign_success_passes_rekor(self):
        verify_anchor._cosign_verify_blob = lambda *a, **k: True
        fx = AnchorFixture(self.root, rekor_bundle=_rekor_bundle_v03())
        result = verify_anchor.evaluate(fx.record_path)
        rekor = result["records"]["sigstore_rekor"]
        self.assertEqual(result["verdict"], verify_anchor.PASS, result)
        self.assertEqual(rekor["state"], verify_anchor.REC_PASS)
        self.assertEqual(rekor["crypto"], "cosign-verified")
        self.assertEqual(rekor["certificate_identity"],
                         verify_anchor.EXPECTED_CERTIFICATE_IDENTITY)

    def test_v03_bundle_cosign_nonzero_fails_rekor(self):
        verify_anchor._cosign_verify_blob = lambda *a, **k: False
        fx = AnchorFixture(self.root, rekor_bundle=_rekor_bundle_v03())
        result = verify_anchor.evaluate(fx.record_path)
        rekor = result["records"]["sigstore_rekor"]
        self.assertEqual(result["verdict"], verify_anchor.FAIL, result)
        self.assertEqual(rekor["state"], verify_anchor.REC_FAIL)
        self.assertEqual(rekor["reason"], verify_anchor.RC_REKOR_VERIFY_FAILED)
        self.assertIn(verify_anchor.RC_REKOR_VERIFY_FAILED, result["reasons"])

    def test_v03_bundle_missing_cosign_holds_rekor(self):
        verify_anchor._cosign_verify_blob = lambda *a, **k: None
        fx = AnchorFixture(self.root, rekor_bundle=_rekor_bundle_v03())
        result = verify_anchor.evaluate(fx.record_path)
        rekor = result["records"]["sigstore_rekor"]
        self.assertEqual(result["verdict"], verify_anchor.HOLD, result)
        self.assertEqual(rekor["state"], verify_anchor.REC_HOLD)
        self.assertEqual(rekor["reason"], verify_anchor.RC_COSIGN_MISSING)
        self.assertIn(verify_anchor.RC_COSIGN_MISSING, result["reasons"])

    def test_v03_target_sha256_mismatch_remains_fail(self):
        verify_anchor._cosign_verify_blob = lambda *a, **k: True
        fx = AnchorFixture(self.root, rekor_bundle=_rekor_bundle_v03())
        record = json.loads(fx.record_path.read_text(encoding="utf-8"))
        record["target_sha256"] = "0" * 64
        fx.record_path.write_text(json.dumps(record), encoding="utf-8")
        result = verify_anchor.evaluate(fx.record_path)
        self.assertEqual(result["verdict"], verify_anchor.FAIL, result)
        self.assertIn(verify_anchor.RC_TARGET_HASH_MISMATCH, result["reasons"])

    def test_v03_overall_pass_requires_rfc3161_pass(self):
        verify_anchor._cosign_verify_blob = lambda *a, **k: True
        fx = AnchorFixture(self.root, rekor_bundle=_rekor_bundle_v03())
        (fx.tdir / verify_anchor.RFC3161_TOKEN_NAME).write_bytes(b"wrong-token")
        result = verify_anchor.evaluate(fx.record_path)
        self.assertEqual(result["records"]["sigstore_rekor"]["state"],
                         verify_anchor.REC_PASS)
        self.assertEqual(result["records"]["rfc3161"]["state"],
                         verify_anchor.REC_FAIL)
        self.assertEqual(result["verdict"], verify_anchor.FAIL, result)
        self.assertIn(verify_anchor.RC_RFC3161_HASH_MISMATCH,
                      result["reasons"])

    def test_cosign_runner_uses_known_identity_and_windows_fallback(self):
        original_runner = self._saved[0]
        fallback = r"C:\tools\cosign-windows-amd64.exe"

        def fake_which(name):
            if name == "cosign-windows-amd64.exe":
                return fallback
            return None

        with mock.patch.object(verify_anchor.shutil, "which",
                               side_effect=fake_which), \
                mock.patch.object(verify_anchor.subprocess, "run") as run:
            run.return_value = mock.Mock(returncode=0)
            self.assertTrue(original_runner(Path("bundle.json"),
                                            Path("target.json")))

        cmd = run.call_args[0][0]
        self.assertEqual(cmd[0], fallback)
        self.assertIn("--certificate-identity", cmd)
        identity_at = cmd.index("--certificate-identity") + 1
        self.assertEqual(cmd[identity_at],
                         verify_anchor.EXPECTED_CERTIFICATE_IDENTITY)
        self.assertIn("--certificate-oidc-issuer-regexp", cmd)

    # 3. one side-car missing -> HOLD
    def test_one_system_missing_holds(self):
        fx = AnchorFixture(self.root)
        moved = fx.tdir / "rekor_bundle.json.bak"
        shutil.move(str(fx.tdir / verify_anchor.REKOR_BUNDLE_NAME), str(moved))
        result = verify_anchor.evaluate(fx.record_path)
        self.assertEqual(result["verdict"], verify_anchor.HOLD, result)
        self.assertIn(verify_anchor.RC_ONE_SYSTEM_MISSING, result["reasons"])
        self.assertIn(verify_anchor.RC_REKOR_MISSING, result["reasons"])

    # 3b. both side-cars missing -> FAIL (fail-closed)
    def test_both_missing_fails_closed(self):
        fx = AnchorFixture(self.root, with_rekor=False, with_rfc3161=False)
        result = verify_anchor.evaluate(fx.record_path)
        self.assertEqual(result["verdict"], verify_anchor.FAIL, result)
        self.assertIn(verify_anchor.RC_NO_RECORDS, result["reasons"])

    # anchor_record.json missing entirely -> FAIL
    def test_missing_record_fails(self):
        result = verify_anchor.evaluate(self.root / "transparency" / "nope.json")
        self.assertEqual(result["verdict"], verify_anchor.FAIL, result)
        self.assertIn(verify_anchor.RC_ANCHOR_RECORD_MISSING, result["reasons"])

    # exit-code mapping is stable
    def test_exit_codes(self):
        self.assertEqual(verify_anchor.EXIT_PASS, 0)
        self.assertEqual(verify_anchor.EXIT_FAIL, 1)
        self.assertEqual(verify_anchor.EXIT_HOLD, 3)


if __name__ == "__main__":
    unittest.main()
