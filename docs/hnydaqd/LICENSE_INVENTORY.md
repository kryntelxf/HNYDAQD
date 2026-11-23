# HNYDAQD License Inventory

This document separates original HNYDAQD code from inherited Onyx code.

## HNYDAQD Original Code

All files under `backend/hnydaqd/`, `docs/hnydaqd/`, and
`deployment/hnydaqd/` are original work created for this project.

- License: to be determined by the product owner (typically proprietary).
- Third-party dependencies declared in `backend/hnydaqd/requirements.txt`:
  - `cryptography` (Apache-2.0 OR BSD-3-Clause) — **permissive**, compatible
    with both proprietary and open-source distribution.
- Standard library only otherwise (no license obligations).

## Inherited Onyx Code

All other files in the repository are from the Onyx FOSS project.

- License: MIT (see root `LICENSE`).
- Exception: `web/src/ee/` is covered by the Onyx Enterprise License
  (see `web/src/ee/LICENSE`). **Do not redistribute HNYDAQD with the `ee/`
  directory included** unless the Onyx Enterprise License terms are met.

## Third-Party Notices

A complete SBOM (CycloneDX JSON) is generated on every push by the
`HNYDAQD SBOM` workflow and stored as an artifact. Retain that artifact for
acquisition due diligence.

## Distribution Checklist

Before shipping a commercial build:

- [ ] Remove or license `web/src/ee/` per Onyx Enterprise terms.
- [ ] Attach the generated SBOM.
- [ ] Include the Onyx MIT notice verbatim.
- [ ] Confirm that no `backend/hnydaqd/` file contains raw confidential data.
