from __future__ import annotations

import logging
from operator import attrgetter

from src.risk.matcher import RiskCandidate, ThreatMatch

logger = logging.getLogger(__name__)

W_INTERNET = 0.25
W_EXPLOIT = 0.20
W_RANSOMWARE = 0.20
W_CRITICALITY = 0.15
W_CVSS = 0.10
W_CONTROLS = 0.10

ASSET_CRIT_SCORE = {"Critical": 10, "High": 7, "Medium": 4, "Low": 2, "Unknown": 3}
REVENUE_IMPACT_SCORE = {"Critical": 10, "High": 7, "Medium": 4, "Low": 2}
RISK_APPETITE_MULTIPLIER = {"Very Low": 1.2, "Low": 1.1, "Medium": 1.0, "High": 0.9}


def score_all(candidates: list[RiskCandidate]) -> list[RiskCandidate]:
    for c in candidates:
        _score(c)
    candidates.sort(key=attrgetter("risk_score"), reverse=True)
    logger.info("Scored %d candidates; top score = %.1f", len(candidates), candidates[0].risk_score if candidates else 0)
    return candidates


def _score(c: RiskCandidate) -> None:
    internet_score = 10.0 if c.internet_exposed or c.asset_exposure == "internet" else 0.0
    exploit_score = _exploit_score(c)
    ransomware_score = _ransomware_score(c)
    criticality_score = _criticality_score(c)
    cvss_score = min(c.cvss, 10.0)
    controls_score = _controls_gap_score(c)

    raw = (
        internet_score * W_INTERNET
        + exploit_score * W_EXPLOIT
        + ransomware_score * W_RANSOMWARE
        + criticality_score * W_CRITICALITY
        + cvss_score * W_CVSS
        + controls_score * W_CONTROLS
    )

    appetite = c.bs_risk_appetite if c.bs_risk_appetite else "Medium"
    multiplier = RISK_APPETITE_MULTIPLIER.get(appetite, 1.0)
    raw *= multiplier

    c.risk_score = round(min(raw * 10, 100.0), 1)
    c.score_breakdown = {
        "internet_exposure": round(internet_score, 1),
        "active_exploit": round(exploit_score, 1),
        "ransomware_campaign": round(ransomware_score, 1),
        "business_criticality": round(criticality_score, 1),
        "cvss_normalised": round(cvss_score, 1),
        "controls_gap": round(controls_score, 1),
        "risk_appetite_multiplier": multiplier,
        "raw_weighted": round(raw, 3),
    }


def _exploit_score(c: RiskCandidate) -> float:
    if not c.exploit_available:
        return 0.0
    if c.kev_entry:
        ransomware_in_kev = str(c.kev_entry.get("knownRansomwareCampaignUse", "")).lower() == "known"
        return 10.0 if ransomware_in_kev else 8.0
    if c.threat_matches:
        best_maturity = max(
            (m.exploit_maturity for m in c.threat_matches),
            key=_maturity_rank,
            default="Unknown",
        )
        if _maturity_rank(best_maturity) >= 3:
            return 9.0
        return 7.0
    return 6.0


def _ransomware_score(c: RiskCandidate) -> float:
    if not c.threat_matches:
        if c.kev_entry and str(c.kev_entry.get("knownRansomwareCampaignUse", "")).lower() == "known":
            return 8.0
        return 0.0
    ransomware_matches = [m for m in c.threat_matches if m.ransomware_association]
    high_confidence = [m for m in ransomware_matches if m.confidence.lower() == "high"]
    if high_confidence:
        return 10.0
    if ransomware_matches:
        return 7.0
    high_conf_any = [m for m in c.threat_matches if m.confidence.lower() == "high"]
    return 5.0 if high_conf_any else 3.0


def _criticality_score(c: RiskCandidate) -> float:
    asset_crit = ASSET_CRIT_SCORE.get(c.asset_criticality, 3)
    revenue = REVENUE_IMPACT_SCORE.get(c.bs_revenue_impact, 2)

    cf_bonus = 1.5 if c.bs_customer_facing else 0

    compliance_bonus = 0
    scope = c.bs_compliance_scope.upper()
    if "PCI DSS" in scope:
        compliance_bonus += 1.0
    if "GDPR" in scope or "UAE PDPL" in scope:
        compliance_bonus += 0.5

    rto_bonus = 0
    if c.bs_rto_hours <= 1:
        rto_bonus = 1.5
    elif c.bs_rto_hours <= 4:
        rto_bonus = 1.0

    composite = (asset_crit * 0.5 + revenue * 0.5) + cf_bonus + compliance_bonus + rto_bonus
    return min(composite, 10.0)


def _controls_gap_score(c: RiskCandidate) -> float:
    score = 0.0

    if not c.edr_installed:
        score += 3.5

    if c.patch_available and c.days_open > 14:
        if c.days_open > 90:
            score += 4.0
        elif c.days_open > 30:
            score += 3.0
        else:
            score += 2.0
    elif not c.patch_available and c.days_open > 0:
        score += 3.0

    return min(score, 10.0)


def _maturity_rank(maturity: str) -> int:
    ranks = {
        "weaponized": 4,
        "active exploitation": 4,
        "proof of concept": 3,
        "commodity exploit": 2,
        "social engineering": 1,
        "not applicable": 0,
        "unknown": 0,
    }
    return ranks.get(maturity.lower(), 0)


def top_n(candidates: list[RiskCandidate], n: int = 5) -> list[RiskCandidate]:
    seen_services: dict[str, int] = {}
    result: list[RiskCandidate] = []
    overflow: list[RiskCandidate] = []

    for c in candidates:
        service_count = seen_services.get(c.business_service, 0)
        if service_count < 2:
            result.append(c)
            seen_services[c.business_service] = service_count + 1
            if len(result) == n:
                break
        else:
            overflow.append(c)

    while len(result) < n and overflow:
        result.append(overflow.pop(0))

    return result
