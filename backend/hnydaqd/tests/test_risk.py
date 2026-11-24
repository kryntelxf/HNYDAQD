from hnydaqd.identity.risk import SessionContext, assess_risk


def _normal_context() -> SessionContext:
    return SessionContext(
        user_id="u1",
        ip_address="10.0.0.1",
        hour_utc=12,
        user_agent="Mozilla/5.0 Chrome",
    )


def test_normal_session_allowed() -> None:
    result = assess_risk(_normal_context())
    assert result.decision == "ALLOW"
    assert result.score == 0


def test_suspicious_ip_raises_score() -> None:
    ctx = _normal_context()
    ctx.ip_address = "185.220.101.1"
    result = assess_risk(ctx)
    assert result.score >= 40
    assert "Suspicious IP range" in result.reasons


def test_outside_business_hours_raises_score() -> None:
    ctx = _normal_context()
    ctx.hour_utc = 3
    result = assess_risk(ctx)
    assert "Outside business hours" in result.reasons


def test_failed_logins_trigger_challenge() -> None:
    ctx = _normal_context()
    ctx.previous_failed_logins = 5
    result = assess_risk(ctx)
    assert result.score >= 30
    assert result.decision in ("CHALLENGE", "DENY")


def test_multiple_signals_can_deny() -> None:
    ctx = _normal_context()
    ctx.ip_address = "185.220.101.1"
    ctx.previous_failed_logins = 5
    ctx.hour_utc = 3
    result = assess_risk(ctx)
    assert result.decision == "DENY"


def test_non_browser_user_agent_adds_score() -> None:
    ctx = _normal_context()
    ctx.user_agent = "python-requests/2.31"
    result = assess_risk(ctx)
    assert "Non-browser user agent" in result.reasons
