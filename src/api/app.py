"""FastAPI service — single endpoint POST /chain."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from src.ingestion.schema import Engagement
from src.ingestion.adapters import get_adapter
from src.ingestion.detector import detect_format
from src.graph.builder import build_graph
from src.graph.pathfinder import find_primary_chain, find_secondary_findings
from src.graph.scorer import compute_chain_risk_score
from src.renderer.html import render_html
from src.renderer.json_export import export_graph_json

app = FastAPI(
    title="Attack Chain Mapper",
    description="AI-powered pentest attack chain visualizer",
    version="0.1.0",
)


class ChainResponse(BaseModel):
    engagement_id: str
    chain_risk_score: float
    primary_chain_length: int
    secondary_findings_count: int
    graph_json: dict
    html: str


@app.post("/chain", response_model=ChainResponse)
async def generate_chain(
    file: UploadFile = File(...),
    format_override: Optional[str] = Form(None),
):
    """Generate an attack chain from an uploaded findings JSON file."""
    try:
        raw = await file.read()
        data = json.loads(raw)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {e}")

    format_name = format_override or detect_format(data)
    try:
        adapter_cls = get_adapter(format_name)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    adapter = adapter_cls()
    try:
        engagement = adapter.parse(data)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Failed to parse findings: {e}")

    G = build_graph(engagement.findings)
    primary_chain = find_primary_chain(G)
    secondary = find_secondary_findings(G, primary_chain)
    risk_score = compute_chain_risk_score(primary_chain)
    html = render_html(engagement, primary_chain, secondary, risk_score)
    graph_json = export_graph_json(engagement, primary_chain, secondary, risk_score)

    return ChainResponse(
        engagement_id=engagement.engagement_id,
        chain_risk_score=risk_score,
        primary_chain_length=len(primary_chain),
        secondary_findings_count=len(secondary),
        graph_json=graph_json,
        html=html,
    )


@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}
