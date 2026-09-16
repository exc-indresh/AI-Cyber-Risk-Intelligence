from __future__ import annotations

import logging
from dataclasses import dataclass

import chromadb

from src.rag.embedder import encode
from src.risk.matcher import RiskCandidate

logger = logging.getLogger(__name__)

CONTROL_HINT_MAP: dict[str, str] = {
    "vpn": "SI-2 flaw remediation patch VPN firmware vulnerability",
    "rce": "SI-2 flaw remediation remote code execution patch apply",
    "exploit": "SI-2 RA-5 vulnerability monitoring patch management exploit",
    "ransomware": "IR-4 incident handling ransomware response containment recovery",
    "authentication": "IA-2 AC-2 account management authentication bypass multi-factor",
    "backup": "CP-9 information system backup immutable recovery ransomware",
    "ci/cd": "SA-11 CM-2 developer security build pipeline secrets management",
    "database": "AC-6 RA-5 least privilege database privilege escalation",
    "edr": "SI-3 malicious code protection endpoint detection response",
    "eol": "SA-22 unsupported system components end-of-life decommission",
    "session": "SC-23 session authenticity token session management",
    "secrets": "SA-11 CM-6 secrets management build pipeline credential exposure",
    "citrix": "SI-2 SC-23 patch session token leak Citrix NetScaler",
    "exchange": "SI-2 SC-8 Microsoft Exchange NTLM relay patch",
    "confluence": "SI-2 AC-3 Confluence RCE OGNL injection access control",
    "teamcity": "SI-2 SA-11 TeamCity authentication bypass CI/CD",
    "jenkins": "SI-2 SA-11 Jenkins file read CLI arbitrary secrets",
    "solarwinds": "IR-4 SI-2 SolarWinds deserialization RCE incident response",
    "storage": "SC-28 CP-9 encryption at rest storage backup protection",
    "kubernetes": "CM-7 AC-6 least functionality Kubernetes dashboard RBAC",
    "php": "SI-2 SA-22 PHP CGI injection outdated runtime",
    "wordpress": "SI-2 SA-22 CMS plugin outdated patch web server",
    "firewall": "SC-7 boundary protection firewall access control",
}


@dataclass
class NISTRetrievalResult:
    control_id: str
    control_title: str
    family: str
    family_name: str
    prose: str
    relevance_score: float
    query_used: str


def retrieve_nist_control(
    candidate: RiskCandidate,
    collection: chromadb.Collection,
    n_results: int = 3,
) -> NISTRetrievalResult | None:
    query = _build_query(candidate)
    logger.debug("NIST retrieval query for %s: %s", candidate.vuln_id, query[:120])

    query_embedding = encode([query])[0]

    results = collection.query(
        query_embeddings=[query_embedding],
        n_results=n_results,
        include=["metadatas", "distances", "documents"],
    )

    if not results["ids"] or not results["ids"][0]:
        logger.warning("No NIST control found for %s", candidate.vuln_id)
        return None

    best_idx = 0
    meta = results["metadatas"][0][best_idx]
    distance = results["distances"][0][best_idx]
    relevance = round(1.0 - distance, 4)

    return NISTRetrievalResult(
        control_id=meta.get("id", ""),
        control_title=meta.get("title", ""),
        family=meta.get("family", ""),
        family_name=meta.get("family_name", ""),
        prose=meta.get("prose", ""),
        relevance_score=relevance,
        query_used=query,
    )


def _build_query(candidate: RiskCandidate) -> str:
    parts: list[str] = []

    parts.append(f"Vulnerability: {candidate.vuln_name}")
    parts.append(f"Affected component: {candidate.affected_component}")
    parts.append(f"CVE: {candidate.cve}")

    if candidate.internet_exposed:
        parts.append("internet-facing asset")
    if candidate.exploit_available:
        parts.append("actively exploited in the wild")
    if any(m.ransomware_association for m in candidate.threat_matches):
        parts.append("linked to active ransomware campaign")
    if not candidate.edr_installed:
        parts.append("missing endpoint detection")
    if not candidate.patch_available:
        parts.append("no patch available end-of-life system unsupported component")

    hint = _get_hint(candidate)
    if hint:
        parts.append(hint)

    return " ".join(parts)


def _get_hint(candidate: RiskCandidate) -> str:
    text = (candidate.vuln_name + " " + candidate.affected_component + " " + candidate.cve).lower()
    for keyword, hint in CONTROL_HINT_MAP.items():
        if keyword in text:
            return hint
    if candidate.exploit_available:
        return "SI-2 flaw remediation patch vulnerability exploit"
    return "RA-5 vulnerability monitoring risk assessment"
