# Claim Boundary

This file defines the public claim boundary for the ECHO-VERIFY Transparency
Anchor Kit v0.1 export.

- ①A means external-recorded existence proof.
- ①A means 外部記録による存在証明.
- ①A means existence time and tamper-evidence.
- ①A means this export contains an externally anchored manifest.
- ①A does not mean third-party verification.
- ①A does not mean certification.
- ①A does not validate content correctness.
- ①B remains pending until an external verifier runs the kit and returns `REPRODUCED`, `NOT_REPRODUCED`, or `INCONCLUSIVE`.

The anchor binds the target manifest bytes to external records. It does not
upgrade the contained decision packets into correctness findings.
