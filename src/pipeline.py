from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from dotenv import load_dotenv

load_dotenv()

from src.ingest.load_csvs import load_all
from src.ingest.load_kev import load_kev
from src.ingest.load_nist import load_nist_controls
from src.rag.vectorstore import get_client, build_nist_index, build_threat_report_index
from src.rag.retriever import retrieve_nist_control, NISTRetrievalResult
from src.risk.matcher import build_candidates, RiskCandidate
from src.risk.scorer import score_all, top_n
from src.llm.analyst import build_client as build_groq_client, generate_narrative, RiskNarrative

logger = logging.getLogger(__name__)


@dataclass
class RiskEntry:
    rank: int
    candidate: RiskCandidate
    nist_result: NISTRetrievalResult | None
    narrative: RiskNarrative


@dataclass
class RiskReport:
    generated_at: str
    top_risks: list[RiskEntry]
    total_assets: int
    total_vulnerabilities: int
    total_threat_intel: int
    pipeline_duration_seconds: float
    errors: list[str] = field(default_factory=list)


def run_pipeline(
    dataset_dir: str | Path | None = None,
    chroma_dir: str | Path | None = None,
    cache_dir: str | Path | None = None,
    force_rebuild_index: bool = False,
    progress_callback: Callable[[str], None] | None = None,
) -> RiskReport:
    t0 = time.time()
    errors: list[str] = []

    def emit(msg: str) -> None:
        logger.info(msg)
        if progress_callback:
            progress_callback(msg)

    dataset_dir = Path(dataset_dir or os.environ.get("DATASET_DIR", "./Dataset"))
    chroma_dir = Path(chroma_dir or os.environ.get("CHROMA_DB_DIR", "./data/chroma"))
    cache_dir = Path(cache_dir or os.environ.get("CACHE_DIR", "./data/cache"))

    emit("📂 Loading structured data (CSVs)…")
    data = load_all(dataset_dir)

    emit("🔍 Fetching CISA KEV catalog…")
    try:
        kev_catalog = load_kev(cache_dir)
        emit(f"   ✓ {len(kev_catalog)} KEV entries loaded")
    except Exception as exc:
        errors.append(f"KEV fetch failed: {exc}")
        kev_catalog = {}
        emit(f"   ⚠ KEV unavailable — {exc}")

    emit("📖 Loading NIST SP 800-53 Rev 5 catalog…")
    nist_controls = load_nist_controls(cache_dir)
    emit(f"   ✓ {len(nist_controls)} controls parsed")

    emit("🔢 Building ChromaDB vector indexes…")
    chroma_client = get_client(chroma_dir)
    nist_collection = build_nist_index(
        chroma_client, nist_controls, force_rebuild=force_rebuild_index
    )
    build_threat_report_index(
        chroma_client, data.threat_report_text, force_rebuild=force_rebuild_index
    )
    emit(f"   ✓ NIST index: {nist_collection.count()} vectors")

    emit("🔗 Matching assets → vulnerabilities → threat intel → business services…")
    candidates = build_candidates(
        assets=data.assets,
        vulnerabilities=data.vulnerabilities,
        threat_intel=data.threat_intel,
        business_services=data.business_services,
        kev_catalog=kev_catalog,
    )
    emit(f"   ✓ {len(candidates)} risk candidates built")

    emit("⚖️  Scoring all candidates (multi-factor)…")
    scored = score_all(candidates)
    top5 = top_n(scored, n=5)
    emit(f"   ✓ Top 5 selected (scores: {[c.risk_score for c in top5]})")

    groq_client = build_groq_client()
    groq_model = os.environ.get("GROQ_MODEL", "qwen/qwen3.8-27b")

    risk_entries: list[RiskEntry] = []
    for rank, candidate in enumerate(top5, start=1):
        emit(f"🧠 Analysing risk #{rank}: {candidate.vuln_name} on {candidate.asset_name}…")

        nist_result = retrieve_nist_control(candidate, nist_collection)
        if nist_result:
            emit(f"   ✓ NIST control retrieved: {nist_result.control_id} — {nist_result.control_title}")
        else:
            emit(f"   ⚠ No NIST control matched for {candidate.vuln_id}")

        emit(f"   💬 Generating narrative (Groq/{groq_model})…")
        narrative = generate_narrative(
            rank=rank,
            candidate=candidate,
            nist_result=nist_result,
            client=groq_client,
            model=groq_model,
        )

        risk_entries.append(
            RiskEntry(rank=rank, candidate=candidate, nist_result=nist_result, narrative=narrative)
        )

    duration = round(time.time() - t0, 1)
    emit(f"✅ Pipeline complete in {duration}s")

    return RiskReport(
        generated_at=_now_iso(),
        top_risks=risk_entries,
        total_assets=len(data.assets),
        total_vulnerabilities=len(data.vulnerabilities),
        total_threat_intel=len(data.threat_intel),
        pipeline_duration_seconds=duration,
        errors=errors,
    )


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    report = run_pipeline()
    print("\n" + "=" * 70)
    print(f"TAWASOL PAY - CYBER RISK TOP 5 REPORT  ({report.generated_at})")
    print("=" * 70)
    for entry in report.top_risks:
        c = entry.candidate
        n = entry.nist_result
        narr = entry.narrative
        print("\n" + "-" * 70)
        print(f"RISK #{entry.rank}  |  Score: {c.risk_score}/100  |  {c.vuln_name}")
        print(f"Asset:     {c.asset_name} ({c.asset_type}, {c.environment})")
        print(f"CVE:       {c.cve}  |  CVSS: {c.cvss}  |  Days open: {c.days_open}")
        print(f"Service:   {c.business_service} (RTO {c.bs_rto_hours}h)")
        if c.threat_matches:
            actors = {m.threat_actor for m in c.threat_matches}
            print(f"Threat:    {', '.join(actors)}")
        if n:
            print(f"NIST:      {n.control_id} - {n.control_title}")
            print(f"           {n.prose[:300]}...")
        print(f"\nWhy ranked here:\n  {narr.ranking_reason}")
        print(f"\nNIST guidance:\n  {narr.nist_application}")
    print("\n" + "=" * 70)
    if report.errors:
        print(f"Warnings: {report.errors}")
    print(f"Pipeline ran in {report.pipeline_duration_seconds}s")
