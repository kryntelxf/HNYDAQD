# HNYDAQD Security Decisions

This log records the decisions that shaped the HNYDAQD layer. Each decision
references the source file that implements it.

## SD-001: Extend Onyx, do not fork it
- Status: implemented in `backend/hnydaqd/`.
- Reason: Onyx's 10,000+ file codebase is mature. Rewriting auth, indexing,
  or connectors would be months of work with no security benefit.
- Consequence: all HNYDAQD changes are additive; upstream can be updated.

## SD-002: Real encryption replaces the FOSS no-op
- Status: implemented in `backend/hnydaqd/encryption/envelope.py`.
- Reason: Onyx's `backend/onyx/utils/encryption.py` returns plaintext.
- Consequence: every confidential field must call `EnvelopeEncryption`
  explicitly; the FOSS helper is untouched for backwards compatibility.

## SD-003: Authorization precedes LLM context
- Status: implemented in `backend/hnydaqd/policy/service.py` and called from
  `backend/onyx/server/query_and_chat/chat_backend.py`.
- Reason: prompt instructions alone are not a security boundary.
- Consequence: a malicious prompt cannot extract chunks the user's role
  cannot see, because those chunks never reach the model.

## SD-004: Cumulative disclosure is stateful
- Status: implemented in `backend/hnydaqd/disclosure/ledger.py`.
- Reason: three harmless queries can compose a secret.
- Consequence: the ledger keeps a per-user, time-windowed history.

## SD-005: Provider routing is classification-driven
- Status: implemented in `backend/hnydaqd/providers/router.py`.
- Reason: RAW_SECRET must never leave the private boundary.
- Consequence: EXTERNAL providers can only receive INTERNAL and below.

## SD-006: Audit chain is hash-linked
- Status: implemented in `backend/hnydaqd/audit/sink.py`.
- Reason: ordinary logs can be edited by a privileged attacker.
- Consequence: deleting or modifying any past record breaks
  `verify_integrity()` and is surfaced in `/hnydaqd/status`.

## SD-007: DLP is defense-in-depth, not the only layer
- Status: implemented in `backend/hnydaqd/dlp/output.py`.
- Reason: regex DLP alone is insufficient.
- Consequence: DLP runs *after* authorization; it catches leaks that slip
  past both the context gate and the model itself.
