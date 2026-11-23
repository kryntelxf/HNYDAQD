# HNYDAQD Threat Model (Implementation Status)

This document tracks every threat identified in the original audit
(`THREAT_MODEL.md` at repo root) and states the current mitigation status
in the HNYDAQD layer.

Status legend:
- **MITIGATED**: code exists and is tested.
- **PARTIAL**: code exists but requires operator configuration.
- **OPEN**: not yet implemented.

| ID | Threat | Status | Mitigation |
|---|---|---|---|
| T-001 | Stolen credentials | PARTIAL | Onyx handles auth. HNYDAQD records all blocked access via audit chain. |
| T-002 | Compromised Owner | PARTIAL | `identity/roles.py` limits Owner to RAW_SECRET but every access is audited. `OWNER != bypass` for the audit chain itself. |
| T-003 | Compromised Administrator | PARTIAL | Audit chain is hash-linked; tampering is detected (`audit/sink.py::verify_integrity`). |
| T-004 | Malicious insider | **MITIGATED** | `disclosure/ledger.py` blocks cumulative disclosure after 3 sensitive chunks per user window. |
| T-005 | Malicious document | PARTIAL | `dlp/output.py` scans AI output. Input-side prompt injection relies on Onyx's existing filters (not re-implemented). |
| T-006 | Cumulative disclosure | **MITIGATED** | `disclosure/ledger.py` + `policy/context_gate.py`. Tested by `test_disclosure_ledger.py`. |
| T-007 | Compromised AI agent | PARTIAL | Tool authorization is Onyx's responsibility. HNYDAQD enforces provider routing (`providers/router.py`). |
| T-008 | Provider disclosure | **MITIGATED** | `providers/router.py` enforces: RAW_SECRET → PRIVATE only. Tested by `test_provider_routing.py`. |
| T-009 | Export abuse | OPEN | Export authorization is Onyx's. HNYDAQD adds audit events but not export-specific gating yet. |
| T-010 | Encryption failure | **MITIGATED** | `encryption/envelope.py` uses AES-256-GCM (replacing the FOSS no-op). Tested by `test_encryption.py`. |

## Residual Risks

These remain outside HNYDAQD's current control and must be handled by
operators or future work:

- Screen capture by authorized users.
- Manual copying by an authorized insider (beyond disclosure thresholds).
- Collusion between two authorized users.
- Compromise of the external KMS/HSM (not yet integrated; the master key is
  currently provided via environment).
- Side-channel attacks on the host.
