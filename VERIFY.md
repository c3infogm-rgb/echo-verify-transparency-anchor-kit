# Verification Instructions

Use these commands from the repository root in Windows PowerShell.

## Setup Notes

Python 3 must be available as `python`. The focused test commands use `pytest`
and `jsonschema`; install them in your local environment if they are not already
available.

For full ①A crypto verification, make sure both `cosign` and `openssl` are on
`PATH`:

```powershell
where.exe cosign
where.exe openssl
```

If either command is missing, install it through your normal trusted channel and
restart PowerShell so the updated `PATH` is visible.

## Automated Checks

```powershell
python -m pytest tests/test_anchor_verify.py
python -m tools.anchor.verify_anchor --record transparency\anchor_record.json
python -m unittest tests.test_mil_dp_kit
```

Expected anchor output includes:

```text
VERDICT: PASS
sigstore_rekor: PASS cosign-verified
rfc3161: PASS openssl-verified
```

The first command runs focused verifier tests. The second command verifies the
externally anchored manifest. The third command verifies the MIL-DP kit file
hashes, packet schema checks, deterministic packet hashes, and bundled replay
checks.

## Manual Sigstore/Rekor Verification

```powershell
cosign verify-blob `
  --bundle transparency\rekor_bundle.json `
  --certificate-identity "info@c3-anchor.jp" `
  --certificate-oidc-issuer-regexp ".*" `
  echo_verify_kit\mil_dp\run_manifest.json
```

Rekor search URL:

```text
https://search.sigstore.dev/?logIndex=2100277685
```

## Manual RFC3161 Verification

```powershell
openssl ts -verify `
  -in transparency\rfc3161_token.tsr `
  -data echo_verify_kit\mil_dp\run_manifest.json `
  -CAfile transparency\rfc3161_tsa_cert.pem
```

The RFC3161 check confirms timestamp binding for the same manifest bytes.
