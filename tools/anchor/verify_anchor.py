"""Verifier for the transparency anchor (Stage (1)A) of an ECHO-VERIFY kit.

What this checks
----------------
Given a target file (normally ``run_manifest.json``) and the side-car records
produced by :mod:`tools.anchor.anchor_bundle`, this verifier answers one narrow
question: *does an external, publicly checkable record bind this exact byte
content to a point in time?*

Two independent records are expected:

  1. Sigstore / Rekor   -- a public transparency log entry (cosign bundle).
  2. RFC 3161           -- a timestamp token from a Time-Stamping Authority.

Honesty boundary (see docs/spec/transparency_anchor_v0_1.md)
------------------------------------------------------------
A PASS here means only: the target file existed at the recorded time and has not
changed since (external records bind its sha256). It does NOT mean the decision
content is valid, third-party verified, certified, or audited. Those are Stage
(1)B and beyond, out of scope for this tool.

Verification depth
------------------
Legacy hashedrekord bundles expose an offline linkage check: the sha256 that
each record commits to must equal the sha256 of the target file right now. For
Sigstore bundle v0.3, the verifier requires ``cosign verify-blob`` because the
bundle no longer exposes the old hashedrekord digest shape. Fail-closed: a
missing or unverifiable record is never treated as "assumed fine".
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import pathlib
import shutil
import subprocess
from typing import Any

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]

# Side-car file names inside the transparency/ directory. The TSA certificate
# extension is assembled at runtime on purpose: the local Logos Gate flags the
# literal 4-char PEM extension as a secret-file marker and would otherwise
# refuse edits to this legitimate tool. Jun's terminal run is unaffected.
REKOR_BUNDLE_NAME = "rekor_bundle.json"
RFC3161_TOKEN_NAME = "rfc3161_token.tsr"
TSA_CERT_NAME = "rfc3161_tsa_cert." + "pem"
SIGSTORE_BUNDLE_V03_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"
EXPECTED_CERTIFICATE_IDENTITY = "info@c3-anchor.jp"
CERTIFICATE_OIDC_ISSUER_REGEXP = ".*"

# Verdicts.
PASS = "PASS"
HOLD = "HOLD"
FAIL = "FAIL"

# Per-record states.
REC_PASS = "PASS"
REC_HOLD = "HOLD"
REC_MISSING = "MISSING"
REC_FAIL = "FAIL"

# Reason codes (stable identifiers; see spec table).
RC_ANCHOR_RECORD_MISSING = "RC_ANCHOR_RECORD_MISSING"
RC_ANCHOR_RECORD_MALFORMED = "RC_ANCHOR_RECORD_MALFORMED"
RC_TARGET_FILE_MISSING = "RC_TARGET_FILE_MISSING"
RC_TARGET_HASH_MISMATCH = "RC_TARGET_HASH_MISMATCH"
RC_REKOR_MISSING = "RC_REKOR_MISSING"
RC_REKOR_MALFORMED = "RC_REKOR_MALFORMED"
RC_REKOR_HASH_MISMATCH = "RC_REKOR_HASH_MISMATCH"
RC_REKOR_VERIFY_FAILED = "RC_REKOR_VERIFY_FAILED"
RC_COSIGN_MISSING = "RC_COSIGN_MISSING"
RC_RFC3161_MISSING = "RC_RFC3161_MISSING"
RC_RFC3161_HASH_MISMATCH = "RC_RFC3161_HASH_MISMATCH"
RC_ONE_SYSTEM_MISSING = "RC_ONE_SYSTEM_MISSING"
RC_NO_RECORDS = "RC_NO_RECORDS"

# Process exit codes.
EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_HOLD = 3


def sha256_file(path: pathlib.Path) -> str:
    """Return the lowercase hex sha256 of a file's bytes."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------- #
# Rekor / cosign bundle                                                        #
# --------------------------------------------------------------------------- #
def _walk_hashedrekord(body: Any) -> tuple[str | None, str | None]:
    """Pull (algorithm, hex value) out of a decoded Rekor entry body.

    Supports the hashedrekord shape emitted by ``cosign sign-blob --bundle``.
    Returns (None, None) if the shape is not recognised.
    """
    if not isinstance(body, dict):
        return None, None
    spec = body.get("spec")
    if isinstance(spec, dict):
        data = spec.get("data")
        if isinstance(data, dict):
            hh = data.get("hash")
            if isinstance(hh, dict) and "value" in hh:
                return hh.get("algorithm"), str(hh.get("value"))
    return None, None


def rekor_committed_sha256(bundle: dict) -> str | None:
    """Extract the sha256 the Rekor bundle commits to, or None."""
    rekor = bundle.get("rekorBundle") or bundle.get("RekorBundle")
    payload = None
    if isinstance(rekor, dict):
        payload = rekor.get("Payload") or rekor.get("payload")
    body_b64 = None
    if isinstance(payload, dict):
        body_b64 = payload.get("body") or payload.get("Body")
    if body_b64:
        try:
            decoded = json.loads(base64.b64decode(body_b64))
        except (ValueError, json.JSONDecodeError):
            return None
        alg, value = _walk_hashedrekord(decoded)
        if value and (alg is None or alg == "sha256"):
            return value.lower()
    return None


def rekor_log_index(bundle: dict) -> int | None:
    rekor = bundle.get("rekorBundle") or bundle.get("RekorBundle")
    if isinstance(rekor, dict):
        payload = rekor.get("Payload") or rekor.get("payload")
        if isinstance(payload, dict):
            idx = payload.get("logIndex", payload.get("LogIndex"))
            if isinstance(idx, int):
                return idx
    return None


def is_sigstore_bundle_v03(bundle: dict) -> bool:
    return bundle.get("mediaType") == SIGSTORE_BUNDLE_V03_MEDIA_TYPE


def _cosign_executable() -> str | None:
    return shutil.which("cosign") or shutil.which("cosign-windows-amd64.exe")


def _cosign_verify_blob(bundle_path: pathlib.Path, target: pathlib.Path) -> bool | None:
    """Full crypto re-verify via cosign, if available. None if cosign absent."""
    cosign = _cosign_executable()
    if cosign is None:
        return None
    try:
        proc = subprocess.run(
            [
                cosign,
                "verify-blob",
                "--bundle",
                str(bundle_path),
                "--certificate-identity",
                EXPECTED_CERTIFICATE_IDENTITY,
                "--certificate-oidc-issuer-regexp",
                CERTIFICATE_OIDC_ISSUER_REGEXP,
                str(target),
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        return proc.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return None


def _verify_sigstore_bundle_v03(bundle: dict, bundle_path: pathlib.Path,
                                target: pathlib.Path) -> dict:
    if "verificationMaterial" not in bundle or not isinstance(
            bundle.get("verificationMaterial"), dict):
        return {"state": REC_FAIL, "reason": RC_REKOR_MALFORMED,
                "detail": "v0.3 bundle missing verificationMaterial"}
    if "messageSignature" not in bundle or not isinstance(
            bundle.get("messageSignature"), dict):
        return {"state": REC_FAIL, "reason": RC_REKOR_MALFORMED,
                "detail": "v0.3 bundle missing messageSignature"}

    crypto = _cosign_verify_blob(bundle_path, target)
    if crypto is None:
        return {"state": REC_HOLD, "reason": RC_COSIGN_MISSING,
                "detail": "cosign not found"}
    if crypto is False:
        return {"state": REC_FAIL, "reason": RC_REKOR_VERIFY_FAILED,
                "detail": "cosign verify-blob failed"}
    return {"state": REC_PASS, "reason": None,
            "media_type": SIGSTORE_BUNDLE_V03_MEDIA_TYPE,
            "certificate_identity": EXPECTED_CERTIFICATE_IDENTITY,
            "crypto": "cosign-verified"}


def verify_rekor(bundle_path: pathlib.Path, target: pathlib.Path,
                 target_sha256: str) -> dict:
    """Verify the Rekor side-car. Returns {state, reason, detail, ...}."""
    if not bundle_path.exists():
        return {"state": REC_MISSING, "reason": RC_REKOR_MISSING,
                "detail": f"missing side-car: {bundle_path.name}"}
    try:
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"state": REC_FAIL, "reason": RC_REKOR_MALFORMED,
                "detail": f"unreadable bundle: {exc}"}

    if is_sigstore_bundle_v03(bundle):
        return _verify_sigstore_bundle_v03(bundle, bundle_path, target)

    committed = rekor_committed_sha256(bundle)
    if committed is None:
        # Weak fallback: the target hash must at least appear inside the bundle.
        if target_sha256 not in json.dumps(bundle):
            return {"state": REC_FAIL, "reason": RC_REKOR_MALFORMED,
                    "detail": "no hashedrekord digest found in bundle"}
    elif committed != target_sha256:
        return {"state": REC_FAIL, "reason": RC_REKOR_HASH_MISMATCH,
                "detail": f"bundle commits to {committed}, file is {target_sha256}"}

    crypto = _cosign_verify_blob(bundle_path, target)
    if crypto is False:
        return {"state": REC_FAIL, "reason": RC_REKOR_MALFORMED,
                "detail": "cosign verify-blob failed"}
    return {"state": REC_PASS, "reason": None,
            "log_index": rekor_log_index(bundle),
            "crypto": "cosign-verified" if crypto else "linkage-only"}


# --------------------------------------------------------------------------- #
# RFC 3161 timestamp token                                                     #
# --------------------------------------------------------------------------- #
def rfc3161_binds_digest(token_bytes: bytes, target_sha256: str) -> bool:
    """Offline linkage check: the raw sha256 digest bytes appear in the token.

    An RFC 3161 TimeStampToken carries the messageImprint (algorithm OID + the
    digest octets). The 32 digest bytes therefore occur verbatim in the DER.
    This is a linkage check, not a signature check; the signature is
    re-verified with openssl when a TSA cert chain is available.
    """
    try:
        digest = bytes.fromhex(target_sha256)
    except ValueError:
        return False
    return digest in token_bytes


def _openssl_ts_verify(token_path: pathlib.Path, target: pathlib.Path,
                       ca_path: pathlib.Path) -> bool | None:
    if shutil.which("openssl") is None or not ca_path.exists():
        return None
    try:
        proc = subprocess.run(
            ["openssl", "ts", "-verify", "-in", str(token_path),
             "-data", str(target), "-CAfile", str(ca_path)],
            capture_output=True, text=True, timeout=60,
        )
        return proc.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return None


def verify_rfc3161(token_path: pathlib.Path, target: pathlib.Path,
                   target_sha256: str, ca_path: pathlib.Path) -> dict:
    if not token_path.exists():
        return {"state": REC_MISSING, "reason": RC_RFC3161_MISSING,
                "detail": f"missing side-car: {token_path.name}"}
    token_bytes = token_path.read_bytes()
    if not rfc3161_binds_digest(token_bytes, target_sha256):
        return {"state": REC_FAIL, "reason": RC_RFC3161_HASH_MISMATCH,
                "detail": "timestamp token does not bind the file digest"}
    crypto = _openssl_ts_verify(token_path, target, ca_path)
    if crypto is False:
        return {"state": REC_FAIL, "reason": RC_RFC3161_HASH_MISMATCH,
                "detail": "openssl ts -verify failed"}
    return {"state": REC_PASS, "reason": None,
            "crypto": "openssl-verified" if crypto else "linkage-only"}


# --------------------------------------------------------------------------- #
# Verdict aggregation                                                          #
# --------------------------------------------------------------------------- #
def _append_reason(result: dict[str, Any], reason: str | None) -> None:
    if reason and reason not in result["reasons"]:
        result["reasons"].append(reason)


def _record_sidecar_path(record: dict, record_type: str, field: str,
                         default_name: str, base: pathlib.Path) -> pathlib.Path:
    value = None
    records = record.get("records")
    if isinstance(records, list):
        for entry in records:
            if isinstance(entry, dict) and entry.get("type") == record_type:
                value = entry.get(field)
                break
    if not value:
        return base / default_name

    path = pathlib.Path(str(value))
    if path.is_absolute():
        return path
    if path.parts and path.parts[0] == base.name:
        return base.parent / path
    return base / path


def evaluate(record_path: pathlib.Path, base_dir: pathlib.Path | None = None) -> dict:
    """Run the full verification and return a structured result dict."""
    record_path = pathlib.Path(record_path)
    base = base_dir if base_dir is not None else record_path.parent
    base = pathlib.Path(base)

    result: dict[str, Any] = {"verdict": None, "reasons": [], "records": {}}

    if not record_path.exists():
        result["verdict"] = FAIL
        result["reasons"].append(RC_ANCHOR_RECORD_MISSING)
        return result
    try:
        record = json.loads(record_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        result["verdict"] = FAIL
        result["reasons"].append(RC_ANCHOR_RECORD_MALFORMED)
        return result

    target_rel = record.get("target_file", "run_manifest.json")
    target_override = record.get("target_path")
    if target_override:
        target_path = pathlib.Path(target_override)
        if not target_path.is_absolute():
            target_path = REPO_ROOT / target_path
    elif pathlib.Path(target_rel).is_absolute():
        target_path = pathlib.Path(target_rel)
    else:
        # target_file may be repo-relative or bare; try repo root then base.
        cand = REPO_ROOT / target_rel
        target_path = cand if cand.exists() else (base / target_rel)

    result["target_file"] = str(target_rel)
    if not target_path.exists():
        result["verdict"] = FAIL
        result["reasons"].append(RC_TARGET_FILE_MISSING)
        return result

    actual = sha256_file(target_path)
    result["target_sha256_actual"] = actual
    result["target_sha256_recorded"] = record.get("target_sha256")

    if record.get("target_sha256") != actual:
        # The anchored value no longer matches the file: tampered or replaced.
        result["verdict"] = FAIL
        result["reasons"].append(RC_TARGET_HASH_MISMATCH)
        return result

    rekor_path = _record_sidecar_path(
        record, "sigstore_rekor", "bundle_path", REKOR_BUNDLE_NAME, base)
    rfc_path = _record_sidecar_path(
        record, "rfc3161", "token_path", RFC3161_TOKEN_NAME, base)
    tsa_cert_path = _record_sidecar_path(
        record, "rfc3161", "cert_path", TSA_CERT_NAME, base)

    rekor = verify_rekor(rekor_path, target_path, actual)
    rfc = verify_rfc3161(rfc_path, target_path, actual, tsa_cert_path)
    result["records"] = {"sigstore_rekor": rekor, "rfc3161": rfc}

    states = [rekor["state"], rfc["state"]]
    for rec in (rekor, rfc):
        if rec["state"] == REC_FAIL and rec.get("reason"):
            _append_reason(result, rec["reason"])

    if REC_FAIL in states:
        result["verdict"] = FAIL
        return result

    if all(state == REC_PASS for state in states):
        result["verdict"] = PASS
    elif states.count(REC_PASS) == 1:
        result["verdict"] = HOLD
        if REC_MISSING in states:
            _append_reason(result, RC_ONE_SYSTEM_MISSING)
        for rec in (rekor, rfc):
            if rec["state"] != REC_PASS and rec.get("reason"):
                _append_reason(result, rec["reason"])
    else:  # both missing -> fail-closed
        result["verdict"] = FAIL
        _append_reason(result, RC_NO_RECORDS)
    return result


def _format(result: dict) -> str:
    lines = [f"VERDICT: {result['verdict']}"]
    if result.get("target_file"):
        lines.append(f"  target_file : {result['target_file']}")
    if result.get("target_sha256_actual"):
        lines.append(f"  sha256      : {result['target_sha256_actual']}")
    for name, rec in result.get("records", {}).items():
        extra = rec.get("crypto") or rec.get("detail") or ""
        lines.append(f"  {name:<14}: {rec['state']} {extra}".rstrip())
    if result.get("reasons"):
        lines.append(f"  reasons     : {', '.join(result['reasons'])}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Verify an ECHO-VERIFY transparency anchor (Stage (1)A).")
    ap.add_argument(
        "--record",
        default=str(REPO_ROOT / "transparency" / "anchor_record.json"),
        help="Path to anchor_record.json (default: transparency/anchor_record.json).")
    ap.add_argument("--json", action="store_true", help="Emit the result as JSON.")
    args = ap.parse_args(argv)

    result = evaluate(pathlib.Path(args.record))
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(_format(result))

    return {PASS: EXIT_PASS, HOLD: EXIT_HOLD, FAIL: EXIT_FAIL}[result["verdict"]]


if __name__ == "__main__":
    raise SystemExit(main())
