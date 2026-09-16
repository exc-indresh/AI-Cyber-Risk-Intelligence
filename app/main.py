from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(
    title="TawasolPay AI Cyber Risk Assistant",
    description="AI-powered cyber risk prioritisation with NIST 800-53 RAG guidance",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

_cached_report = None
_is_running = False


@app.get("/", response_class=HTMLResponse)
async def serve_spa() -> HTMLResponse:
    html_path = STATIC_DIR / "index.html"
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"))


@app.get("/api/health")
async def health() -> JSONResponse:
    return JSONResponse({"status": "ok", "service": "TawasolPay Cyber Risk Assistant"})


@app.post("/api/analyze")
async def analyze(request: Request) -> JSONResponse:
    global _cached_report, _is_running

    if _is_running:
        return JSONResponse({"error": "Analysis already running"}, status_code=409)

    _is_running = True
    try:
        from src.pipeline import run_pipeline
        report = await asyncio.get_event_loop().run_in_executor(
            None, lambda: run_pipeline()
        )
        _cached_report = report
        return JSONResponse(_serialise_report(report))
    except Exception as exc:
        logger.exception("Pipeline failed")
        return JSONResponse({"error": str(exc)}, status_code=500)
    finally:
        _is_running = False


@app.get("/api/analyze/stream")
async def analyze_stream(request: Request) -> StreamingResponse:
    global _cached_report, _is_running

    async def event_generator():
        global _cached_report, _is_running

        if _is_running:
            yield _sse_event({"type": "error", "message": "Analysis already running"})
            return

        _is_running = True
        progress_messages = []

        def on_progress(msg: str):
            progress_messages.append(msg)

        try:
            from src.pipeline import run_pipeline
            loop = asyncio.get_event_loop()

            future = loop.run_in_executor(
                None,
                lambda: run_pipeline(progress_callback=on_progress),
            )

            last_sent = 0
            while not future.done():
                await asyncio.sleep(0.3)
                while last_sent < len(progress_messages):
                    msg = progress_messages[last_sent]
                    yield _sse_event({"type": "progress", "message": msg})
                    last_sent += 1

            while last_sent < len(progress_messages):
                msg = progress_messages[last_sent]
                yield _sse_event({"type": "progress", "message": msg})
                last_sent += 1

            report = await future
            _cached_report = report

            yield _sse_event({"type": "result", "data": _serialise_report(report)})

        except Exception as exc:
            logger.exception("Pipeline streaming failed")
            yield _sse_event({"type": "error", "message": str(exc)})
        finally:
            _is_running = False

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/api/report")
async def get_cached_report() -> JSONResponse:
    if _cached_report is None:
        return JSONResponse({"error": "No report generated yet. Run /api/analyze first."}, status_code=404)
    return JSONResponse(_serialise_report(_cached_report))


def _serialise_report(report) -> dict:
    return {
        "generated_at": report.generated_at,
        "total_assets": report.total_assets,
        "total_vulnerabilities": report.total_vulnerabilities,
        "total_threat_intel": report.total_threat_intel,
        "pipeline_duration_seconds": report.pipeline_duration_seconds,
        "errors": report.errors,
        "top_risks": [_serialise_entry(e) for e in report.top_risks],
    }


def _serialise_entry(entry) -> dict:
    c = entry.candidate
    n = entry.nist_result
    narr = entry.narrative

    threat_actors = []
    campaigns = []
    has_ransomware = False
    if c.threat_matches:
        threat_actors = list({m.threat_actor for m in c.threat_matches if m.threat_actor != "Unknown"})
        campaigns = list({m.campaign_name for m in c.threat_matches})
        has_ransomware = any(m.ransomware_association for m in c.threat_matches)

    return {
        "rank": entry.rank,
        "risk_score": c.risk_score,
        "score_breakdown": c.score_breakdown,
        "asset_id": c.asset_id,
        "asset_name": c.asset_name,
        "asset_type": c.asset_type,
        "environment": c.environment,
        "location": c.location,
        "vendor_product": c.vendor_product,
        "internet_exposed": c.internet_exposed,
        "edr_installed": c.edr_installed,
        "vuln_id": c.vuln_id,
        "vuln_name": c.vuln_name,
        "cve": c.cve,
        "cvss": c.cvss,
        "exploit_available": c.exploit_available,
        "patch_available": c.patch_available,
        "days_open": c.days_open,
        "affected_component": c.affected_component,
        "business_service": c.business_service,
        "bs_customer_facing": c.bs_customer_facing,
        "bs_revenue_impact": c.bs_revenue_impact,
        "bs_rto_hours": c.bs_rto_hours,
        "bs_compliance_scope": c.bs_compliance_scope,
        "threat_actors": threat_actors,
        "campaigns": campaigns,
        "has_ransomware": has_ransomware,
        "kev_confirmed": bool(c.kev_entry),
        "kev_ransomware": str(c.kev_entry.get("knownRansomwareCampaignUse", "")).lower() == "known" if c.kev_entry else False,
        "nist_control_id": n.control_id if n else None,
        "nist_control_title": n.control_title if n else None,
        "nist_family": n.family_name if n else None,
        "nist_prose": n.prose if n else None,
        "nist_relevance": n.relevance_score if n else None,
        "ranking_reason": narr.ranking_reason,
        "nist_application": narr.nist_application,
        "executive_summary": narr.executive_summary,
    }


def _sse_event(data: dict) -> str:
    return f"data: {json.dumps(data)}\n\n"


if __name__ == "__main__":
    import uvicorn
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("app.main:app", host=host, port=port, reload=True)
