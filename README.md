# ECHO-VERIFY Transparency Anchor Kit v0.1

This repository is a minimal public export for reviewing and reproducing the
ECHO-VERIFY Transparency Anchor Kit v0.1. It contains the externally anchored
manifest, transparency proof side cars, focused verification tools, focused
tests, and the MIL-DP evidence files needed to reproduce ①A verification.

This kit is an external-recorded existence proof
（外部記録による存在証明） for one manifest. It supports checking existence
time and tamper-evidence for the exact target bytes.

## Anchor Facts

- Target: `echo_verify_kit/mil_dp/run_manifest.json`
- Target SHA-256: `6d96d6cc2da589c8d7e23dbf1e94cbe0f2dd49ba6a37601506436bdb002d1758`
- Signer identity: `info@c3-anchor.jp`
- Rekor log index: `2100277685`
- Rekor search URL: https://search.sigstore.dev/?logIndex=2100277685
- RFC3161 timestamp: present in `transparency/rfc3161_token.tsr`

## ①A And ①B

①A is complete for this export only when all three hold: the manifest hash
matches, `cosign verify-blob` succeeds against the Sigstore/Rekor bundle, and
`openssl ts -verify` succeeds against the RFC3161 timestamp for the target
manifest. An offline digest-linkage match by itself (the recorded hash simply
appearing inside a side-car) is diagnostic information only and never
satisfies ①A on its own.

If `cosign` or `openssl` is not on `PATH`, the affected record reports `HOLD`
(reason codes `RC_COSIGN_MISSING` / `RC_OPENSSL_MISSING`) and the overall
verdict cannot be `PASS`; install the missing tool and re-run.

①B is not complete in this export. ①B remains pending until an external
verifier clones this kit, runs the checks in their own environment, and returns
`REPRODUCED`, `NOT_REPRODUCED`, or `INCONCLUSIVE`.

## Quick Start

From the repository root:

```powershell
python -m pytest tests/test_anchor_verify.py
python -m tools.anchor.verify_anchor --record transparency\anchor_record.json
python -m unittest tests.test_mil_dp_kit
```

The anchor verifier should report:

```text
VERDICT: PASS
sigstore_rekor: PASS cosign-verified
rfc3161: PASS openssl-verified
```

## Non-Claim Boundary

This kit records an externally anchored manifest and provides verification
steps for that anchor. It does not state that packet decisions are correct, does
not grant a certification mark, and does not imply endorsement by Sigstore,
FreeTSA, Microsoft, or any other third party.
