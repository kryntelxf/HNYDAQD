import logging
from typing import Any, Dict, List, Optional

from hnydaqd.audit.events import AuditEventType
from hnydaqd.audit.sink import default_audit_sink
from hnydaqd.config import ClassificationLevel
from hnydaqd.identity.roles import UserRole
from hnydaqd.policy.context_gate import ContextGate

logger = logging.getLogger(__name__)


class PolicyService:
    """
    Service tunggal yang dipanggil oleh Onyx chat_backend.py.
    Menyatukan gate, DLP, audit, dan routing dalam satu entry point.
    """

    def authorize_and_record(
        self,
        user_id: str,
        user_role: UserRole,
        chunks: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        gate = ContextGate(user_role=user_role)
        try:
            allowed = gate.authorize_context(chunks, user_id=user_id)
        except Exception as e:
            default_audit_sink.record(
                event_type=AuditEventType.CONTEXT_BLOCKED,
                actor_id=user_id,
                details={"error": str(e), "chunk_count": len(chunks)},
            )
            raise

        blocked_count = len(chunks) - len(allowed)
        if blocked_count > 0:
            default_audit_sink.record(
                event_type=AuditEventType.ACCESS_DENIED,
                actor_id=user_id,
                details={"blocked_count": blocked_count},
            )

        return allowed

    def route_for_user(self, data_level: ClassificationLevel) -> Optional[str]:
        # Placeholder: nanti akan memanggil providers/router.py
        from hnydaqd.providers.router import route_for_classification

        decision = route_for_classification(data_level)
        default_audit_sink.record(
            event_type=AuditEventType.PROVIDER_ROUTED,
            actor_id="system",
            details={"level": data_level.value, "provider": decision.provider.value},
        )
        return decision.provider.value


# Instance global
policy_service = PolicyService()
