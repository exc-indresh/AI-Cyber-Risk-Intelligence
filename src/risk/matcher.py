from __future__ import annotations

import logging
from dataclasses import dataclass, field

import pandas as pd

logger = logging.getLogger(__name__)


@dataclass
class ThreatMatch:
    intel_id: str
    threat_actor: str
    campaign_name: str
    ransomware_association: bool
    exploit_maturity: str
    confidence: str
    summary: str


@dataclass
class RiskCandidate:
    vuln_id: str
    asset_id: str
    asset_name: str
    asset_type: str
    environment: str
    location: str
    vendor_product: str
    business_service: str
    owner_team: str

    cve: str
    vuln_name: str
    cvss: float
    exploit_available: bool
    patch_available: bool
    days_open: int
    affected_component: str

    internet_exposed: bool
    asset_criticality: str
    edr_installed: bool
    asset_exposure: str

    bs_customer_facing: bool
    bs_revenue_impact: str
    bs_rto_hours: float
    bs_compliance_scope: str
    bs_risk_appetite: str

    threat_matches: list[ThreatMatch] = field(default_factory=list)
    kev_entry: dict = field(default_factory=dict)

    risk_score: float = 0.0
    score_breakdown: dict = field(default_factory=dict)


def build_candidates(
    assets: pd.DataFrame,
    vulnerabilities: pd.DataFrame,
    threat_intel: pd.DataFrame,
    business_services: pd.DataFrame,
    kev_catalog: dict[str, dict],
) -> list[RiskCandidate]:
    asset_idx: dict[str, dict] = assets.set_index("asset_id").to_dict("index")
    bs_idx: dict[str, dict] = business_services.set_index("business_service").to_dict("index")

    cve_to_intel: dict[str, list[ThreatMatch]] = {}
    for _, row in threat_intel.iterrows():
        cve_key = str(row.get("matched_cve_or_control", "")).strip()
        if not cve_key:
            continue
        match = ThreatMatch(
            intel_id=str(row.get("intel_id", "")),
            threat_actor=str(row.get("threat_actor", "Unknown")),
            campaign_name=str(row.get("campaign_name", "")),
            ransomware_association=bool(row.get("ransomware_association", False)),
            exploit_maturity=str(row.get("exploit_maturity", "Unknown")),
            confidence=str(row.get("confidence", "Low")),
            summary=str(row.get("summary", "")),
        )
        cve_to_intel.setdefault(cve_key, []).append(match)

    candidates: list[RiskCandidate] = []
    skipped = 0

    for _, vuln_row in vulnerabilities.iterrows():
        asset_id = str(vuln_row.get("asset_id", "")).strip()

        if asset_id not in asset_idx:
            skipped += 1
            continue

        asset = asset_idx[asset_id]
        service_name = str(asset.get("business_service", "Unknown")).strip()
        bs = bs_idx.get(service_name, {})

        cve = str(vuln_row.get("cve", "")).strip()
        threat_matches = cve_to_intel.get(cve, [])

        if not threat_matches:
            for key in cve_to_intel:
                if key == cve:
                    threat_matches = cve_to_intel[key]
                    break

        kev_entry = kev_catalog.get(cve, {})

        candidate = RiskCandidate(
            vuln_id=str(vuln_row.get("vuln_id", "")),
            asset_id=asset_id,
            asset_name=str(asset.get("asset_name", "")),
            asset_type=str(asset.get("asset_type", "")),
            environment=str(asset.get("environment", "")),
            location=str(asset.get("location", "")),
            vendor_product=str(asset.get("vendor_product", "")),
            business_service=service_name,
            owner_team=str(asset.get("owner_team", "Unassigned")),
            cve=cve,
            vuln_name=str(vuln_row.get("vulnerability_name", "")),
            cvss=float(vuln_row.get("cvss", 0.0)),
            exploit_available=bool(vuln_row.get("exploit_available", False)),
            patch_available=bool(vuln_row.get("patch_available", False)),
            days_open=int(vuln_row.get("days_open", 0)),
            affected_component=str(vuln_row.get("affected_component", "")),
            internet_exposed=bool(asset.get("internet_exposed", False)),
            asset_criticality=str(asset.get("criticality", "Unknown")),
            edr_installed=bool(asset.get("edr_installed", False)),
            asset_exposure=str(vuln_row.get("asset_exposure", "internal")).lower(),
            bs_customer_facing=str(bs.get("customer_facing", "No")).lower() == "yes",
            bs_revenue_impact=str(bs.get("revenue_impact", "Low")),
            bs_rto_hours=_parse_rto(str(bs.get("rto_hours", "24"))),
            bs_compliance_scope=str(bs.get("compliance_scope", "")),
            bs_risk_appetite=str(bs.get("risk_appetite", "Medium")),
            threat_matches=threat_matches,
            kev_entry=kev_entry,
        )
        candidates.append(candidate)

    logger.info(
        "Built %d risk candidates (%d skipped — asset not found)", len(candidates), skipped
    )
    return candidates


def _parse_rto(rto_str: str) -> float:
    try:
        return float(rto_str)
    except (ValueError, TypeError):
        return 24.0
