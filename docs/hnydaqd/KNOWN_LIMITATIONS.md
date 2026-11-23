# HNYDAQD Known Limitations

This file lists what HNYDAQD does **not** yet do. It is intended for
acquirers and auditors who need an honest picture.

## Not Implemented Yet

- **MFA / SSO**: HNYDAQD inherits Onyx's authentication. There is no
  application-level MFA in the HNYDAQD layer.
- **Export-specific gating**: HNYDAQD records export events in the audit
  chain, but does not yet block exports above a threshold.
- **KMS / HSM integration**: the master key is currently provided via
  environment variable. Production deployments must move it to a KMS
  (AWS KMS, HashiCorp Vault, etc.).
- **Immutable storage**: the audit chain is stored in memory by default
  (`audit/sink.py::_records`). Production deployments must persist it to
  append-only storage (S3 Object Lock, WORM volume, or equivalent).
- **Malware scanning on ingestion**: `ingestion/validation.py` validates
  extension and size, but does not scan content. Integrate ClamAV or an
  equivalent for production.
- **Multi-tenant isolation**: HNYDAQD does not add per-tenant key separation
  on top of Onyx's tenant model.

## Residual Risks

See `THREAT_MODEL.md` § Residual Risks for threats that remain even after
HNYDAQD is deployed.

## What This Means for Acquisition

A buyer should expect:
- A working security layer on top of Onyx FOSS.
- 44+ automated tests, all green.
- Explicit gaps in MFA, KMS, and immutable storage that they can fund as
  post-acquisition work.
