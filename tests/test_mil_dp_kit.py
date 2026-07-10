"""Tests for the MIL-DP BYOV verification kit v0.1 (KIT-001..011).

Runs entirely in CI from synthetic fixtures; no live PreToolUse hook required.
Mutation tests operate on a temporary copy so the committed kit stays pristine.
"""
from __future__ import annotations

import json
import pathlib
import shutil
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools import verify_mil_dp_kit as verifier  # noqa: E402
from tools.export_mil_decision_packet import compute_packet_hash  # noqa: E402

try:
    import jsonschema
except ImportError:  # pragma: no cover
    jsonschema = None

KIT_DIR = ROOT / "echo_verify_kit" / "mil_dp"
RESULT_SCHEMA_PATH = ROOT / "schemas" / "mil_dp_verification_result_v0_1.schema.json"
VERIFIER_SRC = (ROOT / "tools" / "verify_mil_dp_kit.py").read_text(encoding="utf-8")


def load(path: pathlib.Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write(path: pathlib.Path, obj: dict) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def rebuild_manifest_hashes(kit_dir: pathlib.Path) -> None:
    """Recompute every listed file's sha256/bytes (so FILE_HASHES stays clean)."""
    manifest_path = kit_dir / "run_manifest.json"
    manifest = load(manifest_path)
    for entry in manifest["files"]:
        fpath = kit_dir / entry["path"]
        entry["sha256"] = verifier.file_sha256(fpath)
        entry["bytes"] = fpath.stat().st_size
    write(manifest_path, manifest)


def regen_manifest_filelist(kit_dir: pathlib.Path) -> None:
    """Rebuild files[]/inputs from the actual tree (handles added/removed files)."""
    manifest_path = kit_dir / "run_manifest.json"
    manifest = load(manifest_path)
    files = []
    for p in sorted(kit_dir.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(kit_dir).as_posix()
        if rel == "run_manifest.json":
            continue
        files.append(
            {"path": rel, "sha256": verifier.file_sha256(p), "bytes": p.stat().st_size}
        )
    manifest["files"] = files
    manifest["inputs"] = sorted(
        f["path"] for f in files if f["path"].startswith("evidence/packets/")
    )
    write(manifest_path, manifest)


def check_status(result: dict, check_id: str) -> str:
    for c in result["checks"]:
        if c["check_id"] == check_id:
            return c["status"]
    return "MISSING"


class KitTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = load(KIT_DIR / "run_manifest.json")
        cls.packets = {
            p.stem: load(p)
            for p in sorted((KIT_DIR / "evidence" / "packets").glob("*.json"))
        }
        cls.result = verifier.verify_kit(KIT_DIR, verifier_id="ci")

    # ---- KIT-001: manifest parse + enumeration integrity
    def test_kit_001_integrity(self):
        self.assertIn("files", self.manifest)
        self.assertEqual(check_status(self.result, "KIT_INTEGRITY"), "PASS")

    # ---- KIT-002: each file's sha256 matches the manifest
    def test_kit_002_file_hashes(self):
        self.assertEqual(check_status(self.result, "FILE_HASHES"), "PASS")

    # ---- KIT-003: every evidence packet validates against the DP schema
    def test_kit_003_packet_schema(self):
        if jsonschema is None:
            self.skipTest("jsonschema is not available")
        self.assertEqual(check_status(self.result, "PACKET_SCHEMA"), "PASS")

    # ---- KIT-004: Level A — independent recompute == stored packet_hash
    def test_kit_004_level_a_independent_recompute(self):
        self.assertTrue(self.packets)
        for name, packet in self.packets.items():
            with self.subTest(packet=name):
                self.assertEqual(
                    verifier.recompute_packet_hash(packet), packet["packet_hash"]
                )
        self.assertEqual(check_status(self.result, "LEVEL_A_PACKET_HASH"), "PASS")

    # ---- KIT-005: cross-check independent impl == exporter, and NOT an import copy
    def test_kit_005_cross_check_not_import_copy(self):
        # the verifier must not import the issuer's hashing function
        self.assertFalse(
            hasattr(verifier, "compute_packet_hash"),
            "verifier must not import compute_packet_hash",
        )
        self.assertNotIn("import compute_packet_hash", VERIFIER_SRC)
        # two independent implementations must still agree on every golden
        for name, packet in self.packets.items():
            with self.subTest(packet=name):
                self.assertEqual(
                    verifier.recompute_packet_hash(packet), compute_packet_hash(packet)
                )

    # ---- KIT-006: tamper a CORE field -> recompute differs -> verdict FAIL
    def test_kit_006_tamper_core_field_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            kit = pathlib.Path(tmp) / "mil_dp"
            shutil.copytree(KIT_DIR, kit)
            target = kit / "evidence" / "packets" / "pass_typo_fix.json"
            packet = load(target)
            packet["decision"] = "FAIL"  # core field; reason_codes already non-empty
            packet["reason_codes"] = ["RC_POLICY_BOUNDARY"]
            write(target, packet)
            rebuild_manifest_hashes(kit)  # so FILE_HASHES is not what fails
            result = verifier.verify_kit(kit)
            self.assertEqual(check_status(result, "LEVEL_A_PACKET_HASH"), "FAIL")
            self.assertEqual(result["verdict"], "FAIL")
            self.assertIn("RC_KIT_PACKET_HASH_MISMATCH", result["reason_codes"])

    # ---- KIT-007: tamper a NON-core (excluded) field -> packet_hash unchanged -> PASS
    def test_kit_007_excluded_field_does_not_change_hash(self):
        # function-level: excluded fields are not in the core
        packet = dict(next(iter(self.packets.values())))
        original = verifier.recompute_packet_hash(packet)
        packet["decision_id"] = "totally-different-id"
        packet["audit_ref"] = "worm://logos-gate-core/other"
        packet["disclosure"] = {"public": True, "private_redacted": True, "explain_due_at": None}
        packet["signature"] = {"present": True, "alg": "x", "kid": "y"}
        self.assertEqual(verifier.recompute_packet_hash(packet), original)

        # kit-level: changing only decision_id keeps Level A and the verdict PASS.
        # Level B is full-packet replay (decision_id is part of the packet), so we
        # drop gate_input to isolate the packet_hash exclusion set under test here.
        with tempfile.TemporaryDirectory() as tmp:
            kit = pathlib.Path(tmp) / "mil_dp"
            shutil.copytree(KIT_DIR, kit)
            shutil.rmtree(kit / "evidence" / "gate_input")
            target = kit / "evidence" / "packets" / "pass_typo_fix.json"
            p = load(target)
            p["decision_id"] = "changed-only-the-id"
            write(target, p)
            regen_manifest_filelist(kit)
            result = verifier.verify_kit(kit)
            self.assertEqual(check_status(result, "LEVEL_A_PACKET_HASH"), "PASS")
            self.assertEqual(check_status(result, "LEVEL_B_EXPORTER_REPLAY"), "SKIP")
            self.assertEqual(result["verdict"], "PASS")

    # ---- KIT-008: a missing evidence file -> integrity FAIL
    def test_kit_008_missing_file_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            kit = pathlib.Path(tmp) / "mil_dp"
            shutil.copytree(KIT_DIR, kit)
            (kit / "evidence" / "packets" / "pass_typo_fix.json").unlink()
            result = verifier.verify_kit(kit)  # manifest still lists it
            self.assertEqual(check_status(result, "KIT_INTEGRITY"), "FAIL")
            self.assertEqual(result["verdict"], "FAIL")
            self.assertIn("RC_KIT_FILE_MISSING", result["reason_codes"])

    # ---- KIT-009: signature absent -> reported "compatible", not a failure
    def test_kit_009_signature_absent_is_compatible(self):
        self.assertEqual(check_status(self.result, "SIGNATURE"), "PASS")
        self.assertEqual(self.result["verdict"], "PASS")
        self.assertFalse(self.result["signature"]["present"])

    # ---- KIT-010: Level B replay reproduces packets from bundled gate_input
    def test_kit_010_level_b_replay(self):
        self.assertEqual(check_status(self.result, "LEVEL_B_EXPORTER_REPLAY"), "PASS")

    # ---- KIT-011: result validates against the result schema; stage 1 unsigned
    def test_kit_011_result_schema_and_unsigned(self):
        if jsonschema is None:
            self.skipTest("jsonschema is not available")
        schema = load(RESULT_SCHEMA_PATH)
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.Draft202012Validator(schema).validate(self.result)
        self.assertEqual(
            self.result["signature"], {"present": False, "alg": None, "kid": None}
        )

    # ---- result schema sanity: FAIL must carry a reason code
    def test_result_schema_fail_requires_reason_codes(self):
        if jsonschema is None:
            self.skipTest("jsonschema is not available")
        schema = load(RESULT_SCHEMA_PATH)
        validator = jsonschema.Draft202012Validator(schema)
        bad = dict(self.result)
        bad["verdict"] = "FAIL"
        bad["reason_codes"] = []
        self.assertTrue(list(validator.iter_errors(bad)))


if __name__ == "__main__":
    unittest.main()
