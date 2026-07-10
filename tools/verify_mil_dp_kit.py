"""Reference verifier for the MIL-DP BYOV verification kit v0.1.

Deterministic, machine-only checks. No generative interpretation feeds the
verdict. This verifier lets a third party recompute ``packet_hash`` from the
packets and the spec; recomputation shows path reproducibility, not correctness
of the decision.

Honesty boundary (see kit README):
  - ECHO-VERIFY-compatible, not complete. Signature is not yet a trust anchor.
  - Stage 1 yields self / implementation-independent replay only. A result is
    independently replayed only when signed by a key other than the issuer's
    (Stage 2); see DD-2 in the result schema.

DD-1: the Level A canonicalization below is re-implemented from the spec (D-2),
NOT imported from tools.export_mil_decision_packet. If it agreed only because it
ran the issuer's hashing code, the check would be circular. The cross-check
(KIT-005) shows two independent implementations land on the same packet_hash.
The exporter is touched only by the optional Level B re-run (lazy import).
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import pathlib
from typing import Any

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
DP_SCHEMA_PATH = REPO_ROOT / "schemas" / "mil_decision_packet_v0_1.schema.json"

SPEC_TARGET = "MIL-DP-0.1"

# D-2 deterministic-core fields, re-stated from the spec (NOT imported).
CORE_FIELDS = (
    "profile",
    "producer",
    "input_hash",
    "rule_hash",
    "decision",
    "state_before",
    "state_after",
    "reason_codes",
    "evidence_refs",
)

# Result reason codes (FAIL only).
RC_KIT_FILE_MISSING = "RC_KIT_FILE_MISSING"
RC_KIT_FILE_UNEXPECTED = "RC_KIT_FILE_UNEXPECTED"
RC_KIT_HASH_MISMATCH = "RC_KIT_HASH_MISMATCH"
RC_KIT_SCHEMA_INVALID = "RC_KIT_SCHEMA_INVALID"
RC_KIT_PACKET_HASH_MISMATCH = "RC_KIT_PACKET_HASH_MISMATCH"
RC_KIT_REPLAY_MISMATCH = "RC_KIT_REPLAY_MISMATCH"

try:
    import jsonschema
except ImportError:  # pragma: no cover
    jsonschema = None


# --- DD-1: independent re-implementation of the D-2 canonicalization rule -----
def recompute_packet_hash(packet: dict) -> str:
    """Recompute packet_hash from the packet's core fields, per spec D-2.

    Rule (D-2): take the core fields only; de-duplicate and ascending-sort the
    two arrays; serialize as UTF-8 JSON with keys ascending and compact
    separators; sha256; prefix ``sha256:``.
    """
    core = {
        "profile": packet["profile"],
        "producer": packet["producer"],
        "input_hash": packet["input_hash"],
        "rule_hash": packet["rule_hash"],
        "decision": packet["decision"],
        "state_before": packet["state_before"],
        "state_after": packet["state_after"],
        "reason_codes": sorted(set(packet.get("reason_codes", []))),
        "evidence_refs": sorted(set(packet.get("evidence_refs", []))),
    }
    blob = json.dumps(core, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(blob).hexdigest()


def file_sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_json(path: pathlib.Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _check(check_id: str, status: str, detail: str) -> dict:
    return {"check_id": check_id, "status": status, "detail": detail}


def verify_kit(kit_dir: str | pathlib.Path, *, verifier_id: str = "anonymous") -> dict:
    """Run the deterministic kit checks and return a verification_result dict."""
    root = pathlib.Path(kit_dir).resolve()
    manifest_path = root / "run_manifest.json"
    checks: list[dict] = []
    reason_codes: set[str] = set()

    manifest = _load_json(manifest_path)
    kit_id = manifest.get("kit_id", root.name)

    # KIT-001 / KIT-008: enumeration integrity (listed == actual, no extras).
    listed = {entry["path"] for entry in manifest.get("files", [])}
    actual = {
        p.relative_to(root).as_posix()
        for p in root.rglob("*")
        if p.is_file() and p.relative_to(root).as_posix() != "run_manifest.json"
    }
    missing = sorted(listed - actual)
    unexpected = sorted(actual - listed)
    if missing or unexpected:
        detail = f"missing={missing} unexpected={unexpected}"
        checks.append(_check("KIT_INTEGRITY", "FAIL", detail))
        if missing:
            reason_codes.add(RC_KIT_FILE_MISSING)
        if unexpected:
            reason_codes.add(RC_KIT_FILE_UNEXPECTED)
    else:
        checks.append(
            _check("KIT_INTEGRITY", "PASS", f"{len(listed)} files enumerated and present")
        )

    # KIT-002: each present file's sha256 matches the manifest.
    hash_failures = []
    for entry in manifest.get("files", []):
        rel = entry["path"]
        fpath = root / rel
        if not fpath.is_file():
            continue  # already reported under integrity
        actual_hash = file_sha256(fpath)
        if actual_hash != entry.get("sha256"):
            hash_failures.append(rel)
    if hash_failures:
        checks.append(_check("FILE_HASHES", "FAIL", f"mismatch: {hash_failures}"))
        reason_codes.add(RC_KIT_HASH_MISMATCH)
    else:
        checks.append(_check("FILE_HASHES", "PASS", "all listed file hashes match"))

    # Load evidence packets.
    packets_dir = root / "evidence" / "packets"
    packet_paths = sorted(packets_dir.glob("*.json")) if packets_dir.is_dir() else []
    packets = {p.stem: _load_json(p) for p in packet_paths}

    # KIT-003: each evidence packet validates against the DP schema.
    if jsonschema is None:
        checks.append(_check("PACKET_SCHEMA", "SKIP", "jsonschema not available"))
    else:
        dp_schema = _load_json(DP_SCHEMA_PATH)
        validator = jsonschema.Draft202012Validator(dp_schema)
        schema_failures = []
        for name, packet in packets.items():
            errs = sorted(validator.iter_errors(packet), key=str)
            if errs:
                schema_failures.append(f"{name}: {errs[0].message}")
        if schema_failures:
            checks.append(_check("PACKET_SCHEMA", "FAIL", "; ".join(schema_failures)))
            reason_codes.add(RC_KIT_SCHEMA_INVALID)
        else:
            checks.append(
                _check("PACKET_SCHEMA", "PASS", f"{len(packets)} packets valid")
            )

    # KIT-004 / 006 / 007: Level A — recompute packet_hash independently.
    level_a_failures = []
    for name, packet in packets.items():
        recomputed = recompute_packet_hash(packet)
        if recomputed != packet.get("packet_hash"):
            level_a_failures.append(name)
    if not packets:
        checks.append(_check("LEVEL_A_PACKET_HASH", "SKIP", "no evidence packets"))
    elif level_a_failures:
        checks.append(
            _check("LEVEL_A_PACKET_HASH", "FAIL", f"hash mismatch: {level_a_failures}")
        )
        reason_codes.add(RC_KIT_PACKET_HASH_MISMATCH)
    else:
        checks.append(
            _check(
                "LEVEL_A_PACKET_HASH",
                "PASS",
                f"{len(packets)} packet_hash values recomputed and matched",
            )
        )

    # KIT-010: Level B (optional) — re-run the exporter if gate_input bundled.
    gate_input_dir = root / "evidence" / "gate_input"
    gate_inputs = (
        sorted(gate_input_dir.glob("*.json")) if gate_input_dir.is_dir() else []
    )
    if not gate_inputs:
        checks.append(
            _check("LEVEL_B_EXPORTER_REPLAY", "SKIP", "no gate_input bundled")
        )
    else:
        # Lazy import: Level B intentionally re-runs the issuer's exporter.
        from tools.export_mil_decision_packet import to_decision_packet

        replay_failures = []
        compared = 0
        for gpath in gate_inputs:
            name = gpath.stem
            golden = packets.get(name)
            if golden is None:
                continue
            compared += 1
            reproduced = to_decision_packet(_load_json(gpath))
            if reproduced != golden:
                replay_failures.append(name)
        if replay_failures:
            checks.append(
                _check(
                    "LEVEL_B_EXPORTER_REPLAY", "FAIL", f"not reproduced: {replay_failures}"
                )
            )
            reason_codes.add(RC_KIT_REPLAY_MISMATCH)
        else:
            checks.append(
                _check(
                    "LEVEL_B_EXPORTER_REPLAY",
                    "PASS",
                    f"{compared} packets reproduced from gate_input",
                )
            )

    # KIT-009: signature. Stage 1 is present:false -> report "absent (compatible)".
    sig = manifest.get("signature", {"present": False, "alg": None, "kid": None})
    if sig.get("present"):
        # Stage 2 territory; Stage 1 never reaches here.
        checks.append(
            _check("SIGNATURE", "SKIP", "signature present; trust-anchor check is Stage 2")
        )
    else:
        checks.append(
            _check("SIGNATURE", "PASS", "signature absent (compatible); not a trust anchor")
        )

    verdict = "FAIL" if any(c["status"] == "FAIL" for c in checks) else "PASS"

    result = {
        "kit_id": kit_id,
        "spec_target": SPEC_TARGET,
        "verifier_id": verifier_id,
        "run_at": datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "checks": checks,
        "verdict": verdict,
        "reason_codes": sorted(reason_codes),
        # Stage 1: never a trust anchor, never independent (DD-2).
        "signature": {"present": False, "alg": None, "kid": None},
    }
    return result


def _cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify a MIL-DP BYOV kit and emit a verification_result."
    )
    parser.add_argument("kit_dir", help="Path to the kit directory (holds run_manifest.json).")
    parser.add_argument("--verifier-id", default="anonymous")
    parser.add_argument("--out", help="Write result JSON here (default: stdout).")
    args = parser.parse_args(argv)

    result = verify_kit(args.kit_dir, verifier_id=args.verifier_id)
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.out:
        pathlib.Path(args.out).write_text(text, encoding="utf-8")
    else:
        import sys

        sys.stdout.write(text)
    # Exit non-zero on FAIL so CI / shells can branch on it.
    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(_cli())
