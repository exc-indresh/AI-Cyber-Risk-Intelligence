from __future__ import annotations

import logging
import os
from dataclasses import dataclass

from groq import Groq

from src.risk.matcher import RiskCandidate
from src.rag.retriever import NISTRetrievalResult

logger = logging.getLogger(__name__)


@dataclass
class RiskNarrative:
    ranking_reason: str
    nist_application: str
    executive_summary: str


def build_client() -> Groq:
    api_key = os.environ.get("GROQ_API_KEY", "")
    if not api_key:
        raise EnvironmentError(
            "GROQ_API_KEY not set. Add it to your .env file. "
            "Get a free key at https://console.groq.com"
        )
    return Groq(api_key=api_key)


def generate_narrative(
    rank: int,
    candidate: RiskCandidate,
    nist_result: NISTRetrievalResult | None,
    client: Groq,
    model: str = "qwen/qwen3.8-27b",
) -> RiskNarrative:
    threat_context = ""
    if candidate.threat_matches:
        actors = list({m.threat_actor for m in candidate.threat_matches})
        campaigns = list({m.campaign_name for m in candidate.threat_matches})
        ransomware = any(m.ransomware_association for m in candidate.threat_matches)
        threat_context = (
            f"Active threat intel: {', '.join(actors)} running '{', '.join(campaigns)}' campaign. "
            f"Ransomware-associated: {'YES' if ransomware else 'NO'}."
        )

    nist_context = ""
    if nist_result:
        nist_context = (
            f"Retrieved NIST SP 800-53 Control — {nist_result.control_id}: {nist_result.control_title}\n"
            f"Prose: {nist_result.prose[:800]}"
        )

    kev_context = ""
    if candidate.kev_entry:
        kev_context = (
            f"CISA KEV: This CVE is in the Known Exploited Vulnerabilities catalog. "
            f"Required action: {candidate.kev_entry.get('requiredAction', 'See CISA KEV')}. "
            f"Ransomware use: {candidate.kev_entry.get('knownRansomwareCampaignUse', 'Unknown')}."
        )

    prompt = f"""You are a senior cybersecurity analyst preparing a risk briefing for TawasolPay's CISO.

Risk #{rank} — Context:
- Asset: {candidate.asset_name} ({candidate.asset_type}, {candidate.environment})
- Vulnerability: {candidate.vuln_name} ({candidate.cve}) — CVSS {candidate.cvss}
- Business Service: {candidate.business_service} (customer-facing: {candidate.bs_customer_facing}, RTO: {candidate.bs_rto_hours}h)
- Compliance scope: {candidate.bs_compliance_scope}
- Internet exposed: {candidate.internet_exposed}
- Exploit available: {candidate.exploit_available}
- EDR installed: {candidate.edr_installed}
- Days open: {candidate.days_open}
- Risk score: {candidate.risk_score}/100
{threat_context}
{kev_context}

{nist_context}

Write THREE short outputs. Respond ONLY with a JSON object with these exact keys:
{{
  "ranking_reason": "<one sentence explaining why this specific risk ranks #{rank} — mention the key factors: internet exposure, active campaign, ransomware, business criticality, compliance. Be concrete and specific to TawasolPay. Max 60 words.>",
  "nist_application": "<two sentences explaining how the retrieved NIST control applies to this specific risk. Reference the control ID and title. Do NOT make up control text — summarise what the retrieved prose says. Max 50 words.>",
  "executive_summary": "<one sharp sentence a non-technical board member can understand. What is the threat, what is the impact. Max 25 words.>"
}}

Return ONLY valid JSON. No markdown, no preamble."""

    try:
        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=600,
            response_format={"type": "json_object"},
        )
        content = response.choices[0].message.content
        import json
        parsed = json.loads(content)
        return RiskNarrative(
            ranking_reason=parsed.get("ranking_reason", ""),
            nist_application=parsed.get("nist_application", ""),
            executive_summary=parsed.get("executive_summary", ""),
        )
    except Exception as exc:
        logger.error("LLM generation failed for %s: %s", candidate.vuln_id, exc)
        return _fallback_narrative(rank, candidate, nist_result)


def _fallback_narrative(
    rank: int, candidate: RiskCandidate, nist_result: NISTRetrievalResult | None
) -> RiskNarrative:
    threat_str = ""
    if candidate.threat_matches:
        actors = {m.threat_actor for m in candidate.threat_matches}
        threat_str = f" Active campaign by {', '.join(actors)} targets this CVE."

    reason = (
        f"Ranked #{rank} because {candidate.asset_name} is "
        f"{'internet-exposed' if candidate.internet_exposed else 'internal'} "
        f"with an {'actively exploitable' if candidate.exploit_available else 'open'} vulnerability "
        f"affecting the {candidate.business_service} service (RTO {candidate.bs_rto_hours}h, "
        f"scope: {candidate.bs_compliance_scope}).{threat_str}"
    )

    nist_app = ""
    if nist_result:
        nist_app = (
            f"NIST {nist_result.control_id} ({nist_result.control_title}) applies: "
            f"{nist_result.prose[:200]}..."
        )

    exec_summary = (
        f"{candidate.vuln_name} on {candidate.asset_name} threatens "
        f"{candidate.business_service} — immediate action required."
    )

    return RiskNarrative(
        ranking_reason=reason,
        nist_application=nist_app,
        executive_summary=exec_summary,
    )
