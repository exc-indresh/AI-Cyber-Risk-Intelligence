from __future__ import annotations

import json
import logging
import time
from pathlib import Path

import requests

logger = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_FILENAME = "cisa_kev.json"


def load_kev(cache_dir: str | Path) -> dict[str, dict]:
    cache_dir = Path(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_path = cache_dir / CACHE_FILENAME

    raw = _load_from_cache_or_download(cache_path)
    return _parse(raw)


def _load_from_cache_or_download(cache_path: Path) -> dict:
    if cache_path.exists():
        age_hours = (time.time() - cache_path.stat().st_mtime) / 3600
        if age_hours < 24:
            logger.info("Using cached CISA KEV (%s)", cache_path)
            with open(cache_path, encoding="utf-8") as f:
                return json.load(f)
        else:
            logger.info("Cache is >24 h old — refreshing KEV catalog")

    return _download(cache_path)


def _download(cache_path: Path) -> dict:
    logger.info("Downloading CISA KEV catalog from %s", KEV_URL)
    try:
        resp = requests.get(KEV_URL, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(data, f)
        logger.info("Downloaded %d KEV entries", len(data.get("vulnerabilities", [])))
        return data
    except Exception as exc:
        logger.warning("KEV download failed (%s). Using empty catalog.", exc)
        return {"vulnerabilities": []}


def _parse(raw: dict) -> dict[str, dict]:
    entries: list[dict] = raw.get("vulnerabilities", [])
    return {entry["cveID"]: entry for entry in entries if "cveID" in entry}
