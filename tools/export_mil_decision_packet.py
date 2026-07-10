"""Export Logos Gate Core decisions as MIL Decision Packets (profile MIL-DP-0.1).

This is an evaluation-stage exporter. The core is a pure function that takes a
synthetic gate decision record and returns a MIL Decision Packet dict. It does
not import or depend on any live PreToolUse hook or gate runtime, so it runs
standalone and in CI from synthetic input alone.

Honesty boundaries (see docs/spec/mil_decision_packet_profile_v0_1.md):
  - MIL-DP-0.1 is ECHO-VERIFY-compatible, not complete / certified / production.
  - The packet-output signature block is NOT a trust anchor in v0.1.
  - Replay determinism shows path reproducibility, not correctness of the
    decision.

Determinism (MIL-DP-006): packet_hash is computed over a deterministic core
only. decision_id, audit_ref, disclosure.*, signature.* and packet_hash itself
are excluded, so the same input + same rules + same config yield the same
packet_hash regardless of execution-specific identifiers or timestamps.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from typing import Any

PROFILE = "MIL-DP-0.1"
PRODUCER = "logos-gate-core"

# Order is documentary; the canonical serialization sorts keys ascending. These
# are the fields that participate in the deterministic packet_hash core (D-2).
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

# D-1: native gate verdict -> MIL canonical decision.
# Native vocabulary is PASS / HOLD / ESCALATE / FAIL. MIL canonical enum is
# PASS | HOLD | FAIL | FREEZE | UNDEFINED. ESCALATE has no MIL verdict of its
# own; it maps to HOLD and is preserved via RC_ESCALATION_REQUIRED. The gate
# does not currently emit FREEZE or UNDEFINED; the exporter never upgrades a
# verdict on its own (e.g. ESCALATE is never promoted to FREEZE).
VERDICT_MAP = {
    "PASS": "PASS",
    "HOLD": "HOLD",
    "ESCALATE": "HOLD",
    "FAIL": "FAIL",
}

# v0.1 reason-code dictionary (profile spec section 5).
RC_OK = "RC_OK"
RC_EVIDENCE_MISSING = "RC_EVIDENCE_MISSING"
RC_POLICY_BOUNDARY = "RC_POLICY_BOUNDARY"
RC_SIGNATURE_MISSING = "RC_SIGNATURE_MISSING"
RC_PRIVATE_RAIL = "RC_PRIVATE_RAIL"
RC_UNSUPPORTED_PROFILE = "RC_UNSUPPORTED_PROFILE"
RC_ESCALATION_REQUIRED = "RC_ESCALATION_REQUIRED"

REASON_DICTIONARY = frozenset(
    {
        RC_OK,
        RC_EVIDENCE_MISSING,
        RC_POLICY_BOUNDARY,
        RC_SIGNATURE_MISSING,
        RC_PRIVATE_RAIL,
        RC_UNSUPPORTED_PROFILE,
        RC_ESCALATION_REQUIRED,
    }
)

# Native gate reason code -> MIL reason code. Unmapped native codes (including
# the whole TG_* family) fall back to RC_POLICY_BOUNDARY: the gate drew a policy
# boundary, even if v0.1 does not yet distinguish which one.
NATIVE_REASON_MAP = {
    "PASS_EVIDENCE_SUFFICIENT": RC_OK,
    "EAG_EVIDENCE_MISSING": RC_EVIDENCE_MISSING,
    "EAG_EVIDENCE_STALE": RC_EVIDENCE_MISSING,
    "EAG_APPROVAL_REQUIRED": RC_POLICY_BOUNDARY,
    "EAG_ROLLBACK_PLAN_MISSING": RC_POLICY_BOUNDARY,
    "EAG_SCOPE_MISMATCH": RC_POLICY_BOUNDARY,
    "SECRET_EXPOSURE_RISK": RC_POLICY_BOUNDARY,
    "SCHEMA_INVALID": RC_POLICY_BOUNDARY,
}

# Default before/after states by MIL decision when a gate record omits them.
DEFAULT_STATES = {
    "PASS": ("evaluating", "released"),
    "HOLD": ("evaluating", "held"),
    "FAIL": ("evaluating", "blocked"),
    "FREEZE": ("evaluating", "frozen"),
    "UNDEFINED": ("evaluating", "undefined"),
}

_BARE_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PREFIXED_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


class UnsupportedProfileError(ValueError):
    """Raised when an unsupported export profile is requested."""


def canonical_json_bytes(value: Any) -> bytes:
    """UTF-8, keys ascending, compact separators (matches gate stable_hash)."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")


def _normalize_hash(value: Any, field: str) -> str:
    """Reuse a gate-produced hash; accept bare hex or already-prefixed form."""
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} missing or not a string: {value!r}")
    candidate = value.lower()
    if _PREFIXED_SHA256.match(candidate):
        return candidate
    if _BARE_SHA256.match(candidate):
        return "sha256:" + candidate
    raise ValueError(f"{field} is not a sha256 digest: {value!r}")


def _input_hash(gate_decision: dict) -> str:
    audit = gate_decision.get("audit") or {}
    raw = gate_decision.get("input_hash") or audit.get("request_hash")
    return _normalize_hash(raw, "input_hash")


def _rule_hash(gate_decision: dict) -> str:
    audit = gate_decision.get("audit") or {}
    raw = gate_decision.get("rule_hash") or audit.get("policy_hash")
    return _normalize_hash(raw, "rule_hash")


def _decision_id(gate_decision: dict) -> str:
    audit = gate_decision.get("audit") or {}
    return str(
        gate_decision.get("decision_id")
        or audit.get("decision_hash")
        or "unknown-decision"
    )


def _audit_ref(gate_decision: dict, decision_id: str) -> str:
    explicit = gate_decision.get("audit_ref")
    if isinstance(explicit, str) and explicit:
        return explicit
    return f"worm://logos-gate-core/{decision_id}"


def _map_reason_codes(gate_decision: dict, decision: str) -> list[str]:
    """Translate native signals to the MIL reason-code dictionary."""
    codes: set[str] = set()

    for native in gate_decision.get("reason_codes", []) or []:
        if not isinstance(native, str):
            continue
        if native in NATIVE_REASON_MAP:
            codes.add(NATIVE_REASON_MAP[native])
        else:
            # Unknown native codes (incl. the TG_* family) are policy boundaries.
            codes.add(RC_POLICY_BOUNDARY)

    # ESCALATE -> HOLD is preserved as an explicit reason, not collapsed into
    # RC_POLICY_BOUNDARY (decision D-1, per work order clarification).
    if gate_decision.get("verdict") == "ESCALATE":
        codes.add(RC_ESCALATION_REQUIRED)

    # Input-side signature (D-3) is an *input* the gate consulted, distinct from
    # the packet-output signature block. Its absence surfaces as a HOLD reason.
    input_signature = gate_decision.get("input_signature")
    if isinstance(input_signature, dict) and input_signature.get("present") is False:
        codes.add(RC_SIGNATURE_MISSING)

    if gate_decision.get("rail") == "private":
        codes.add(RC_PRIVATE_RAIL)

    if decision == "PASS":
        # A clean pass carries RC_OK only; drop boundary noise if any leaked in.
        codes = {RC_OK}
    else:
        codes.discard(RC_OK)
        if not codes:
            # Non-PASS must carry at least one reason (schema minItems 1).
            codes.add(RC_POLICY_BOUNDARY)

    return sorted(codes)


def _states(gate_decision: dict, decision: str) -> tuple[str, str]:
    default_before, default_after = DEFAULT_STATES.get(
        decision, ("evaluating", "undefined")
    )
    before = gate_decision.get("state_before") or default_before
    after = gate_decision.get("state_after") or default_after
    return str(before), str(after)


def _disclosure(gate_decision: dict) -> dict:
    given = gate_decision.get("disclosure")
    if isinstance(given, dict):
        return {
            "public": bool(given.get("public", False)),
            "private_redacted": bool(given.get("private_redacted", False)),
            "explain_due_at": given.get("explain_due_at", None),
        }
    private = gate_decision.get("rail") == "private"
    return {
        "public": False,
        "private_redacted": private,
        "explain_due_at": None,
    }


def to_decision_packet(
    gate_decision: dict,
    *,
    profile: str = PROFILE,
    producer: str = PRODUCER,
    dev_sign: bool = False,
) -> dict:
    """Pure transform: synthetic gate decision record -> MIL Decision Packet.

    `dev_sign` enables a SYNTHETIC dev signature block for local experiments
    only. It is NOT a trust anchor and is excluded from the packet_hash core.
    """
    if profile != PROFILE:
        raise UnsupportedProfileError(
            f"{RC_UNSUPPORTED_PROFILE}: only {PROFILE} is supported, got {profile!r}"
        )

    native_verdict = gate_decision.get("verdict")
    if native_verdict not in VERDICT_MAP:
        raise ValueError(f"unsupported native verdict: {native_verdict!r}")
    decision = VERDICT_MAP[native_verdict]

    decision_id = _decision_id(gate_decision)
    state_before, state_after = _states(gate_decision, decision)
    reason_codes = _map_reason_codes(gate_decision, decision)
    evidence_refs = sorted(
        {str(ref) for ref in (gate_decision.get("evidence_refs") or []) if ref}
    )

    if dev_sign:
        # Synthetic, dev-only. Never a trust anchor; real-key issuance is a
        # later BYOV task.
        signature = {
            "present": True,
            "alg": "dev-hmac-sha256-SYNTHETIC",
            "kid": "dev-synthetic-000",
        }
    else:
        signature = {"present": False, "alg": None, "kid": None}

    packet = {
        "profile": profile,
        "producer": producer,
        "decision_id": decision_id,
        "input_hash": _input_hash(gate_decision),
        "rule_hash": _rule_hash(gate_decision),
        "decision": decision,
        "state_before": state_before,
        "state_after": state_after,
        "reason_codes": reason_codes,
        "evidence_refs": evidence_refs,
        "audit_ref": _audit_ref(gate_decision, decision_id),
        "disclosure": _disclosure(gate_decision),
        "signature": signature,
    }
    packet["packet_hash"] = compute_packet_hash(packet)
    return packet


def extract_core(packet: dict) -> dict:
    """The deterministic core (D-2): hashed fields only, arrays sorted."""
    return {
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


def compute_packet_hash(packet: dict) -> str:
    """sha256 over the canonical deterministic core, prefixed sha256:."""
    core = extract_core(packet)
    digest = hashlib.sha256(canonical_json_bytes(core)).hexdigest()
    return "sha256:" + digest


def _cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Export a synthetic gate decision record as a MIL Decision Packet."
    )
    parser.add_argument(
        "gate_input",
        nargs="?",
        help="Path to a gate_input JSON file (reads stdin if omitted).",
    )
    parser.add_argument("--producer", default=PRODUCER)
    parser.add_argument(
        "--dev-sign",
        action="store_true",
        help="Attach a SYNTHETIC dev signature (not a trust anchor).",
    )
    args = parser.parse_args(argv)

    if args.gate_input:
        with open(args.gate_input, "r", encoding="utf-8") as fh:
            gate_decision = json.load(fh)
    else:
        gate_decision = json.load(sys.stdin)

    packet = to_decision_packet(
        gate_decision, producer=args.producer, dev_sign=args.dev_sign
    )
    json.dump(packet, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
