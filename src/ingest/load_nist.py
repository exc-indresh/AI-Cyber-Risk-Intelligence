from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

import requests

logger = logging.getLogger(__name__)

NIST_OSCAL_URL = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
    "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
)
CACHE_FILENAME = "nist_800_53_rev5.json"


def load_nist_controls(cache_dir: str | Path) -> list[dict]:
    cache_dir = Path(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_path = cache_dir / CACHE_FILENAME

    raw = _load_from_cache_or_download(cache_path)
    controls = _parse_oscal(raw)
    logger.info("Parsed %d NIST 800-53 controls from OSCAL catalog", len(controls))
    return controls


def _load_from_cache_or_download(cache_path: Path) -> dict:
    if cache_path.exists():
        age_hours = (time.time() - cache_path.stat().st_mtime) / 3600
        if age_hours < 168:
            logger.info("Using cached NIST 800-53 catalog (%s)", cache_path)
            with open(cache_path, encoding="utf-8") as f:
                return json.load(f)
        logger.info("Cache is >1 week old — refreshing NIST catalog")

    return _download(cache_path)


def _download(cache_path: Path) -> dict:
    logger.info("Downloading NIST SP 800-53 Rev 5 OSCAL catalog from GitHub...")
    try:
        resp = requests.get(NIST_OSCAL_URL, timeout=120)
        resp.raise_for_status()
        data = resp.json()
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(data, f)
        logger.info("NIST catalog downloaded and cached at %s", cache_path)
        return data
    except Exception as exc:
        logger.error("NIST download failed: %s", exc)
        raise RuntimeError(
            f"Could not download NIST 800-53 catalog. "
            f"Check internet connection. Error: {exc}"
        ) from exc


def _parse_oscal(catalog: dict) -> list[dict]:
    controls: list[dict] = []
    groups = catalog.get("catalog", {}).get("groups", [])

    for group in groups:
        family_id = group.get("id", "").upper()
        family_name = group.get("title", "")
        for ctrl in group.get("controls", []):
            parsed = _extract_control(ctrl, family_id, family_name)
            if parsed:
                controls.append(parsed)
            for enh in ctrl.get("controls", []):
                parsed_enh = _extract_control(enh, family_id, family_name, is_enhancement=True)
                if parsed_enh:
                    controls.append(parsed_enh)

    return controls


def _extract_control(
    ctrl: dict[str, Any],
    family_id: str,
    family_name: str,
    is_enhancement: bool = False,
) -> dict | None:
    ctrl_id = ctrl.get("id", "").upper()
    title = ctrl.get("title", "")

    prose_parts: list[str] = []
    for part in ctrl.get("parts", []):
        if part.get("name") in ("statement", "item", "guidance"):
            _collect_prose(part, prose_parts)

    props = {p["name"]: p["value"] for p in ctrl.get("props", [])}
    if "status" in props and props["status"] == "withdrawn":
        return None

    prose = " ".join(prose_parts).strip()
    if not prose:
        return None

    return {
        "id": ctrl_id,
        "title": title,
        "family": family_id,
        "family_name": family_name,
        "prose": prose,
        "is_enhancement": is_enhancement,
        "embed_text": f"Control {ctrl_id}: {title}\n\n{prose}",
    }


def _collect_prose(part: dict, collector: list[str]) -> None:
    if "prose" in part and part["prose"]:
        collector.append(part["prose"])
    for sub in part.get("parts", []):
        _collect_prose(sub, collector)
