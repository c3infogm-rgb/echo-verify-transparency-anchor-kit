# MIL-DP BYOV Verification Kit v0.1

Bring-Your-Own-Verifier kit for the MIL Decision Packet profile (`MIL-DP-0.1`).
It lets a third party recompute `packet_hash` in their own environment and emit
a `verification_result`, following the ECHO-VERIFY five legs: Evidence / Spec /
Auditor Prompt / Manifest / Signature.

This is **Stage 1**: it needs no external signer and is self-contained in this
repository. Signature stays `present:false`. Stage 2 (an external, non-issuer
signer signing the result) is out of scope here.

## Non-claims

- This kit is **ECHO-VERIFY-compatible, not complete**. Signature is not yet a
  trust anchor.
- The kit lets a third party recompute `packet_hash` from the packets and the
  spec. Recomputation demonstrates **path reproducibility, not correctness of
  the decision**.
- Stage 1 produces **self / implementation-independent replay only**. A result
  counts as **independently replayed** only when signed by a key other than the
  issuer's (Stage 2).
- This is **not certification, not production verification, and not a
  third-party-verified claim**.

### 非主張

- 本kitは **ECHO-VERIFY-compatible** であり、complete ではありません。署名はまだ
  信頼アンカーではありません。
- 本kitは、第三者が packets と spec から `packet_hash` を再計算できるようにします。
  再計算が示すのは**経路の再現性であって、判定の正しさではありません**。
- 第一段で得られるのは **self / 実装独立な再現** までです。result が
  **independently replayed** と数えられるのは、発行者以外の鍵で署名された場合に
  限ります(第二段)。
- これは**認証でも本番検証でも第三者検証済みの主張でもありません**。

## What is disclosed

Per the profile's Disclosure Boundary: the packet schema and field meanings, the
reason-code identifiers, the canonicalization rule for `packet_hash`, and
synthetic sample packets. How the gate reaches a verdict is not part of this kit.

## Layout

```
echo_verify_kit/mil_dp/
  README.md              # this file (Evidence/Spec/Prompt/Manifest/Signature overview)
  run_manifest.json      # Manifest leg: file list + sha256 + bytes, signature present:false
  verify_prompt.md       # Auditor Prompt leg: advisory BYO-AI review steps
  evidence/
    packets/*.json       # Evidence: synthetic positive golden packets (verification targets)
    gate_input/*.json    # optional Level B inputs (synthetic)
```

The reference verifier lives at `tools/verify_mil_dp_kit.py`; the result schema
at `schemas/mil_dp_verification_result_v0_1.schema.json`.

## Two verification levels

- **Level A (portable, primary).** From the packets and the spec alone — no gate
  code — recompute `packet_hash` and compare it to each packet's stored
  `packet_hash`. This is the check a third party most wants. The reference
  verifier re-implements the canonicalization rule **independently from the
  spec** (it does not import the issuer's hashing code), so agreement means two
  independent implementations reach the same hash.
- **Level B (optional, deeper).** Only when `evidence/gate_input/` is bundled:
  re-run the issuer's exporter and check that the whole packet is reproduced.
  This needs the issuer's code, so it is auxiliary.

## How to run

```
python -m tools.verify_mil_dp_kit echo_verify_kit/mil_dp --verifier-id you@example
```

The verifier performs deterministic, machine-only checks (enumeration integrity,
file hashes, schema validation, Level A recomputation, optional Level B replay,
signature reporting) and emits a `verification_result` conforming to
`mil_dp_verification_result_v0_1.schema.json`. It exits non-zero on `FAIL`.

## Independence (DD-2)

A `verification_result` is counted as **independent replay** only when
`signature.present == true` **and** the signature verifies under a key whose
`kid` is not the issuer's. Stage 1 always emits `signature.present == false`, so
a Stage 1 result is by definition not independent. There is no self-asserted
`independent: true` flag — independence is established by a non-issuer signature
(Stage 2), not by a claim in the result.

## Auditor prompt is advisory

`verify_prompt.md` is for an optional BYO-AI auditor. Its output is advisory and
**does not override the deterministic verdict**; an AI-generated summary is not
an audit log. The Reference Verifier performs the machine checks; the BYO-AI
Auditor is auxiliary.
