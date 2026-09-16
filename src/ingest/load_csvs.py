from __future__ import annotations

import os
import logging
from pathlib import Path
from dataclasses import dataclass

import pandas as pd

logger = logging.getLogger(__name__)


@dataclass
class DataPack:
    assets: pd.DataFrame
    vulnerabilities: pd.DataFrame
    threat_intel: pd.DataFrame
    business_services: pd.DataFrame
    remediation_guidance: pd.DataFrame
    threat_report_text: str


def load_all(dataset_dir: str | Path) -> DataPack:
    dataset_dir = Path(dataset_dir)
    logger.info("Loading structured data from %s", dataset_dir)

    assets = _load_csv(dataset_dir / "assets.csv")
    vulnerabilities = _load_csv(dataset_dir / "vulnerabilities.csv")
    threat_intel = _load_csv(dataset_dir / "threat_intelligence.csv")
    business_services = _load_csv(dataset_dir / "business_services.csv")
    remediation_guidance = _load_csv(dataset_dir / "remediation_guidance.csv")

    threat_report_path = dataset_dir / "synthetic_threat_report.md"
    threat_report_text = threat_report_path.read_text(encoding="utf-8")

    assets = _clean_assets(assets)
    vulnerabilities = _clean_vulnerabilities(vulnerabilities)
    threat_intel = _clean_threat_intel(threat_intel)

    logger.info(
        "Loaded: %d assets, %d vulns, %d threat-intel records, "
        "%d business services, %d remediation hints",
        len(assets),
        len(vulnerabilities),
        len(threat_intel),
        len(business_services),
        len(remediation_guidance),
    )
    return DataPack(
        assets=assets,
        vulnerabilities=vulnerabilities,
        threat_intel=threat_intel,
        business_services=business_services,
        remediation_guidance=remediation_guidance,
        threat_report_text=threat_report_text,
    )


def _load_csv(path: Path) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"Required data file not found: {path}")
    df = pd.read_csv(path, dtype=str)
    df = df.apply(lambda col: col.str.strip() if col.dtype == object else col)
    df.dropna(how="all", inplace=True)
    return df


def _clean_assets(df: pd.DataFrame) -> pd.DataFrame:
    df["internet_exposed"] = df["internet_exposed"].str.lower().map(
        {"yes": True, "no": False}
    ).fillna(False)
    df["edr_installed"] = df["edr_installed"].str.lower().map(
        {"yes": True, "no": False}
    ).fillna(False)
    df["last_seen_days"] = pd.to_numeric(df["last_seen_days"], errors="coerce").fillna(999)
    df["criticality"] = df["criticality"].fillna("Unknown")
    df["owner_team"] = df["owner_team"].fillna("Unassigned")
    df["business_service"] = df["business_service"].fillna("Unknown")
    return df


def _clean_vulnerabilities(df: pd.DataFrame) -> pd.DataFrame:
    df["cvss"] = pd.to_numeric(df["cvss"], errors="coerce").fillna(0.0)
    df["exploit_available"] = df["exploit_available"].str.lower().map(
        {"yes": True, "no": False}
    ).fillna(False)
    df["patch_available"] = df["patch_available"].str.lower().map(
        {"yes": True, "no": False}
    ).fillna(False)
    df["days_open"] = pd.to_numeric(df["days_open"], errors="coerce").fillna(0)
    df["asset_exposure"] = df["asset_exposure"].str.lower().fillna("internal")
    return df


def _clean_threat_intel(df: pd.DataFrame) -> pd.DataFrame:
    df["ransomware_association"] = df["ransomware_association"].str.lower().map(
        {"yes": True, "no": False}
    ).fillna(False)
    df["confidence"] = df["confidence"].fillna("Low")
    df["exploit_maturity"] = df["exploit_maturity"].fillna("Unknown")
    return df
