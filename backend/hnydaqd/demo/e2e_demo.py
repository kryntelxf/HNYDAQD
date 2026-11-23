"""
HNYDAQD End-to-End Demo

Simulates the full HNYDAQD security pipeline: ingestion, role-based
authorization, DLP, provider routing, and audit chain integrity.

Run with:
    python -m hnydaqd.demo.e2e_demo
from the backend directory.
"""

import json
import sys
from typing import List

from hnydaqd.audit.events import AuditEventType
from hnydaqd.audit.sink import AuditSink
from hnydaqd.config import ClassificationLevel
from hnydaqd.dlp.output import enforce_output_policy
from hnydaqd.identity.roles import UserRole
from hnydaqd.ingestion.pipeline import process_upload
from hnydaqd.policy.context_gate import ContextGate
from hnydaqd.providers.router import route_for_classification


def _print_header(title: str) -> None:
    print()
    print("=" * 70)
    print(title)
    print("=" * 70)


def _print_user_header(role: UserRole) -> None:
    print()
    print(f"--- User role: {role.value} ---")


def run_demo() -> int:
    sink = AuditSink()

    # ------------------------------------------------------------------
    # 1. Ingestion
    # ------------------------------------------------------------------
    _print_header("STEP 1: Secure Ingestion")

    documents = [
        ("public-brochure.pdf", b"%PDF-1.4 brochure"),
        ("lab-results.docx", b"PK dummy docx"),
        ("secret-recipe.pdf", b"%PDF-1.4 CONFIDENTIAL: formula X"),
    ]

    ingested = []
    for filename, content in documents:
        try:
            result = process_upload(filename, content)
            ingested.append(result)
            sink.record(
                event_type=AuditEventType.INGESTION_ACCEPTED,
                actor_id="system",
                details={
                    "filename": result.filename,
                    "hash": result.content_hash,
                    "classification": result.classification.value,
                },
            )
            print(
                f"  OK  {filename:30s} -> {result.classification.value}"
                f"  (hash={result.content_hash[:12]}...)"
            )
        except Exception as e:
            sink.record(
                event_type=AuditEventType.INGESTION_REJECTED,
                actor_id="system",
                details={"filename": filename, "reason": str(e)},
            )
            print(f"  REJ {filename:30s} -> {e}")

    # Try to upload a malicious file
    try:
        process_upload("malware.exe", b"MZ malicious")
    except Exception as e:
        sink.record(
            event_type=AuditEventType.INGESTION_REJECTED,
            actor_id="system",
            details={"filename": "malware.exe", "reason": str(e)},
        )
        print(f"  REJ malware.exe                    -> {e}")

    # ------------------------------------------------------------------
    # 2. Role-based retrieval
    # ------------------------------------------------------------------
    _print_header("STEP 2: Role-Based Context Authorization")

    chunks = [
        {"id": "pub-1", "classification": ClassificationLevel.PUBLIC},
        {"id": "int-1", "classification": ClassificationLevel.INTERNAL},
        {"id": "conf-1", "classification": ClassificationLevel.CONFIDENTIAL},
        {"id": "secret-1", "classification": ClassificationLevel.RAW_SECRET},
    ]

    for role in [UserRole.OWNER, UserRole.SCIENTIST, UserRole.INVESTOR]:
        _print_user_header(role)
        gate = ContextGate(user_role=role)
        try:
            allowed = gate.authorize_context(chunks, user_id=f"demo_{role.value}")
            allowed_ids = [c["id"] for c in allowed]
            blocked_ids = [c["id"] for c in chunks if c["id"] not in allowed_ids]
            print(f"  Allowed: {allowed_ids}")
            print(f"  Blocked: {blocked_ids}")
            if blocked_ids:
                sink.record(
                    event_type=AuditEventType.ACCESS_DENIED,
                    actor_id=f"demo_{role.value}",
                    details={"blocked": blocked_ids},
                )
        except Exception as e:
            print(f"  BLOCKED by ledger: {e}")
            sink.record(
                event_type=AuditEventType.CONTEXT_BLOCKED,
                actor_id=f"demo_{role.value}",
                details={"error": str(e)},
            )

    # ------------------------------------------------------------------
    # 3. DLP on AI output
    # ------------------------------------------------------------------
    _print_header("STEP 3: Output DLP")

    ai_outputs: List[str] = [
        "Here is your answer: 42.",
        "Use this key: sk-abcdefghijklmnopqrstuvwxyz1234",
        "Recipe: formula: Bahan A 50%, Bahan B 30%",
    ]

    for text in ai_outputs:
        redacted = enforce_output_policy(text, strict=False)
        if redacted != text:
            sink.record(
                event_type=AuditEventType.DLP_REDACTION,
                actor_id="ai",
                details={"original_len": len(text)},
            )
            print(f"  REDACTED: {text[:40]!r} -> {redacted[:60]!r}")
        else:
            print(f"  CLEAN:    {text[:60]!r}")

    # ------------------------------------------------------------------
    # 4. Provider routing
    # ------------------------------------------------------------------
    _print_header("STEP 4: Classification-Aware Provider Routing")

    for level in ClassificationLevel:
        decision = route_for_classification(level)
        sink.record(
            event_type=AuditEventType.PROVIDER_ROUTED,
            actor_id="system",
            details={"level": level.value, "provider": decision.provider.value},
        )
        print(f"  {level.value:25s} -> {decision.provider.value}")

    # ------------------------------------------------------------------
    # 5. Audit chain integrity
    # ------------------------------------------------------------------
    _print_header("STEP 5: Audit Chain Integrity")

    try:
        sink.verify_integrity()
        print(f"  Integrity: OK ({sink.count()} events)")
    except Exception as e:
        print(f"  Integrity: COMPROMISED ({e})")
        return 1

    # ------------------------------------------------------------------
    # 6. Summary
    # ------------------------------------------------------------------
    _print_header("SUMMARY")

    records = sink.get_records()
    counts: dict[str, int] = {}
    for r in records:
        et = r["event_type"]
        counts[et] = counts.get(et, 0) + 1

    print(
        json.dumps(
            {
                "total_events": len(records),
                "by_event_type": counts,
                "integrity_ok": True,
            },
            indent=2,
        )
    )

    return 0


if __name__ == "__main__":
    sys.exit(run_demo())
