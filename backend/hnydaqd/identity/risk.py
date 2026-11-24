import logging
from dataclasses import dataclass
from typing import List

logger = logging.getLogger(__name__)


# IP ranges yang dianggap berisiko (contoh: TOR exit nodes, negara tertentu)
SUSPICIOUS_IP_PREFIXES = [
    "185.",
    "45.",  # contoh placeholder
]

# Jam kerja (UTC). Login di luar jam ini menambah risiko.
BUSINESS_HOURS = (7, 22)  # 07:00 - 22:00 UTC


@dataclass
class SessionContext:
    user_id: str
    ip_address: str
    hour_utc: int
    user_agent: str
    previous_failed_logins: int = 0


@dataclass
class RiskAssessment:
    score: int  # 0-100
    reasons: List[str]
    decision: str  # "ALLOW", "CHALLENGE", "DENY"


def assess_risk(ctx: SessionContext) -> RiskAssessment:
    """
    Menilai risiko sesi berdasarkan sinyal sederhana.
    Skor akhir:
      - <30: ALLOW
      - 30-69: CHALLENGE (wajib MFA / step-up)
      - >=70: DENY
    """
    score = 0
    reasons: List[str] = []

    if any(ctx.ip_address.startswith(p) for p in SUSPICIOUS_IP_PREFIXES):
        score += 40
        reasons.append("Suspicious IP range")

    if ctx.hour_utc < BUSINESS_HOURS[0] or ctx.hour_utc >= BUSINESS_HOURS[1]:
        score += 15
        reasons.append("Outside business hours")

    if ctx.previous_failed_logins >= 3:
        score += 30
        reasons.append("Recent failed login attempts")

    if "python-requests" in ctx.user_agent.lower():
        score += 20
        reasons.append("Non-browser user agent")

    if score < 30:
        decision = "ALLOW"
    elif score < 70:
        decision = "CHALLENGE"
    else:
        decision = "DENY"

    logger.info(
        "Session risk: user=%s ip=%s score=%d decision=%s",
        ctx.user_id,
        ctx.ip_address,
        score,
        decision,
    )
    return RiskAssessment(score=score, reasons=reasons, decision=decision)
