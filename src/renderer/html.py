"""Interactive HTML renderer — produces a single self-contained HTML file.

All 10 renderer requirements are implemented here:
1. Left panel: findings ranked by severity, colour-coded, clickable
2. Right panel: primary attack chain bottom-to-top
3. Animated SVG flow arrows
4. Node click: highlights in both panels simultaneously
5. Finding detail drawer (slides in from right)
6. Secondary findings section
7. Chain risk score
8. Timeline bar
9. Export button
10. Responsive layout (1200px and 1600px)
"""
from __future__ import annotations

import json
from pathlib import Path

from src.ingestion.schema import Finding, Engagement
from src.graph.scorer import label_color, compute_chain_risk_score, risk_score_color


def _severity_css_class(label: str) -> str:
    return label.lower()


def _mitre_url(technique: str) -> str:
    """Convert a MITRE technique ID to the full attack.mitre.org URL."""
    base_id = technique.split(".")[0] if "." in technique else technique
    return f"https://attack.mitre.org/techniques/{base_id}/"


def _escape(text: str | None) -> str:
    if not text:
        return ""
    return (
        text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
    )


def _finding_to_js_obj(f: Finding) -> dict:
    return {
        "id": f.id,
        "title": f.title,
        "severity": f.severity,
        "severity_label": f.severity_label,
        "mitre_technique": f.mitre_technique,
        "step_index": f.step_index,
        "timestamp_offset_s": f.timestamp_offset_s,
        "enabled_by": f.enabled_by,
        "evidence": f.evidence,
        "host": f.host,
        "ai_detail": f.ai_detail,
        "ai_remediation": f.ai_remediation,
        "ai_confidence": f.ai_confidence,
    }


def render_html(
    engagement: Engagement,
    primary_chain: list[Finding],
    secondary_findings: list[Finding],
    chain_risk_score: float,
) -> str:
    """Render the full interactive HTML visualization."""

    all_findings_sorted = sorted(
        engagement.findings, key=lambda f: f.severity, reverse=True
    )

    # Build JS data
    all_findings_js = json.dumps([_finding_to_js_obj(f) for f in engagement.findings])
    chain_js = json.dumps([f.id for f in primary_chain])
    secondary_js = json.dumps([f.id for f in secondary_findings])

    # Timeline data
    timeline_findings = [
        f for f in primary_chain if f.timestamp_offset_s is not None
    ]
    max_ts = max((f.timestamp_offset_s for f in timeline_findings), default=1)

    risk_color = risk_score_color(chain_risk_score)

    # Build left panel HTML
    left_panel_html = ""
    for f in all_findings_sorted:
        color = label_color(f.severity_label)
        mitre_html = ""
        if f.mitre_technique:
            mitre_html = f'<span class="mitre-badge">{_escape(f.mitre_technique)}</span>'
        left_panel_html += f"""
        <div class="finding-item" id="left-{_escape(f.id)}" onclick="selectFinding('{_escape(f.id)}')" data-id="{_escape(f.id)}">
            <div class="finding-item-header">
                <span class="severity-dot" style="background:{color}"></span>
                <span class="severity-score" style="color:{color}">{f.severity:.1f}</span>
                <span class="finding-title">{_escape(f.title)}</span>
            </div>
            <div class="finding-item-meta">
                <span class="severity-badge" style="background:{color}20;color:{color};border:1px solid {color}40">{_escape(f.severity_label)}</span>
                {mitre_html}
            </div>
        </div>"""

    # Build chain nodes HTML (bottom-to-top = reversed for display)
    chain_nodes_html = ""
    chain_reversed = list(reversed(primary_chain))
    for i, f in enumerate(chain_reversed):
        color = label_color(f.severity_label)
        is_crown = (i == 0)
        is_entry = (i == len(chain_reversed) - 1)
        crown_label = " <span class='node-crown'>👑 CROWN JEWEL</span>" if is_crown else ""
        entry_label = " <span class='node-entry'>⚡ ENTRY POINT</span>" if is_entry else ""
        mitre_html = ""
        if f.mitre_technique:
            mitre_url = _mitre_url(f.mitre_technique)
            mitre_html = f'<a href="{mitre_url}" target="_blank" class="mitre-link-small">{_escape(f.mitre_technique)}</a>'

        # Add connector arrow between nodes (except after the last one)
        arrow_html = ""
        if i < len(chain_reversed) - 1:
            arrow_html = f"""
        <div class="chain-connector">
            <svg class="flow-arrow" viewBox="0 0 40 60" xmlns="http://www.w3.org/2000/svg">
                <defs>
                    <linearGradient id="arrowGrad-{i}" x1="0" y1="1" x2="0" y2="0">
                        <stop offset="0%" stop-color="{label_color(chain_reversed[i+1].severity_label)}" stop-opacity="0.6"/>
                        <stop offset="100%" stop-color="{color}" stop-opacity="0.9"/>
                    </linearGradient>
                </defs>
                <line x1="20" y1="55" x2="20" y2="10"
                    stroke="url(#arrowGrad-{i})" stroke-width="2.5"
                    stroke-dasharray="40" stroke-dashoffset="40"
                    class="flow-line" style="animation-delay:{i*0.3}s">
                </line>
                <polygon points="20,2 14,18 26,18" fill="{color}" opacity="0.9" class="arrow-head" style="animation-delay:{i*0.3}s"/>
            </svg>
        </div>"""

        chain_nodes_html += f"""
        {arrow_html}
        <div class="chain-node" id="chain-{_escape(f.id)}" onclick="selectFinding('{_escape(f.id)}')" data-id="{_escape(f.id)}" style="--node-color:{color}">
            <div class="node-glow" style="box-shadow:0 0 0 0 {color}"></div>
            <div class="node-header">
                <div class="node-severity-bar" style="background:{color}"></div>
                <div class="node-content">
                    <div class="node-title">{_escape(f.title)}{crown_label}{entry_label}</div>
                    <div class="node-meta">
                        <span class="severity-badge" style="background:{color}20;color:{color};border:1px solid {color}40">{f.severity:.1f} {_escape(f.severity_label)}</span>
                        {mitre_html}
                        {'<span class="step-label">Step ' + str(f.step_index) + '</span>' if f.step_index is not None else ''}
                    </div>
                </div>
            </div>
        </div>"""

    # Build secondary findings HTML
    secondary_html = ""
    if secondary_findings:
        secondary_html = '<div class="secondary-findings"><h3 class="section-label">Additional findings not in primary chain</h3>'
        for f in secondary_findings:
            color = label_color(f.severity_label)
            mitre_html = ""
            if f.mitre_technique:
                mitre_url = _mitre_url(f.mitre_technique)
                mitre_html = f'<a href="{mitre_url}" target="_blank" class="mitre-link-small">{_escape(f.mitre_technique)}</a>'
            secondary_html += f"""
            <div class="secondary-node" onclick="selectFinding('{_escape(f.id)}')" data-id="{_escape(f.id)}" style="--node-color:{color}">
                <div class="node-severity-bar" style="background:{color}"></div>
                <div class="node-content">
                    <div class="node-title">{_escape(f.title)}</div>
                    <div class="node-meta">
                        <span class="severity-badge" style="background:{color}20;color:{color};border:1px solid {color}40">{f.severity:.1f} {_escape(f.severity_label)}</span>
                        {mitre_html}
                    </div>
                </div>
            </div>"""
        secondary_html += "</div>"

    # Build timeline
    timeline_html = ""
    if timeline_findings:
        timeline_html = '<div class="timeline-bar"><div class="timeline-label">Attack Timeline</div><div class="timeline-track">'
        for f in sorted(timeline_findings, key=lambda x: x.timestamp_offset_s):
            pct = (f.timestamp_offset_s / max(max_ts, 1)) * 100
            color = label_color(f.severity_label)
            minutes = f.timestamp_offset_s // 60
            hours = minutes // 60
            mins = minutes % 60
            time_str = f"{hours}h{mins:02d}m" if hours else f"{mins}m"
            timeline_html += f"""
            <div class="timeline-node" style="left:{pct:.1f}%;--node-color:{color}" onclick="selectFinding('{_escape(f.id)}')" title="{_escape(f.title)} — {time_str}">
                <div class="timeline-dot" style="background:{color}"></div>
                <div class="timeline-step-label">S{f.step_index}</div>
                <div class="timeline-time">{time_str}</div>
            </div>"""
        timeline_html += "</div></div>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Attack Chain — {_escape(engagement.target_name or engagement.engagement_id)}</title>
<style>
/* ===== RESET & BASE ===== */
*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
:root {{
    --bg: #0f1117;
    --surface: #1a1f2e;
    --surface2: #212736;
    --border: #2a3040;
    --border2: #333a50;
    --text: #e8eaf0;
    --text-muted: #8892a4;
    --text-dim: #5a6478;
    --critical: #e74c3c;
    --high: #e67e22;
    --medium: #f39c12;
    --low: #7f8c8d;
    --info: #95a5a6;
    --accent: #5b8dee;
    --drawer-w: 480px;
}}
html, body {{ height: 100%; background: var(--bg); color: var(--text); font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; font-size: 14px; }}
a {{ color: var(--accent); text-decoration: none; }}
a:hover {{ text-decoration: underline; }}

/* ===== LAYOUT ===== */
.app-wrapper {{
    display: flex;
    flex-direction: column;
    height: 100vh;
    overflow: hidden;
}}
.topbar {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 20px;
    background: var(--surface);
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
    gap: 16px;
}}
.topbar-title {{
    font-size: 16px;
    font-weight: 600;
    color: var(--text);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}}
.topbar-right {{
    display: flex;
    align-items: center;
    gap: 12px;
    flex-shrink: 0;
}}
.risk-score-badge {{
    display: flex;
    align-items: center;
    gap: 8px;
    background: var(--surface2);
    border: 1px solid var(--border2);
    border-radius: 8px;
    padding: 6px 14px;
}}
.risk-score-label {{
    color: var(--text-muted);
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}}
.risk-score-value {{
    font-size: 22px;
    font-weight: 700;
    line-height: 1;
}}
.export-btn {{
    display: flex;
    align-items: center;
    gap: 6px;
    background: var(--accent);
    color: #fff;
    border: none;
    border-radius: 6px;
    padding: 8px 14px;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    white-space: nowrap;
    transition: opacity 0.15s;
}}
.export-btn:hover {{ opacity: 0.85; }}

.main-panels {{
    display: flex;
    flex: 1;
    overflow: hidden;
    min-height: 0;
}}

/* ===== LEFT PANEL ===== */
.left-panel {{
    width: 320px;
    min-width: 280px;
    background: var(--surface);
    border-right: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    overflow: hidden;
    flex-shrink: 0;
}}
.panel-header {{
    padding: 14px 16px 10px;
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
}}
.panel-title {{
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    color: var(--text-muted);
}}
.findings-list {{
    flex: 1;
    overflow-y: auto;
    padding: 8px;
}}
.finding-item {{
    padding: 10px 12px;
    border-radius: 6px;
    cursor: pointer;
    border: 1px solid transparent;
    margin-bottom: 4px;
    transition: background 0.15s, border-color 0.15s;
}}
.finding-item:hover {{ background: var(--surface2); border-color: var(--border2); }}
.finding-item.selected {{ background: #1e2640; border-color: var(--node-color, var(--accent)); }}
.finding-item-header {{
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 6px;
}}
.severity-dot {{
    width: 8px;
    height: 8px;
    border-radius: 50%;
    flex-shrink: 0;
}}
.severity-score {{
    font-size: 13px;
    font-weight: 700;
    font-variant-numeric: tabular-nums;
    min-width: 28px;
    flex-shrink: 0;
}}
.finding-title {{
    font-size: 13px;
    font-weight: 500;
    line-height: 1.3;
    color: var(--text);
}}
.finding-item-meta {{
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
    padding-left: 16px;
}}

/* ===== RIGHT PANEL ===== */
.right-panel {{
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    min-width: 0;
}}
.chain-area {{
    flex: 1;
    overflow-y: auto;
    padding: 24px 32px;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 0;
}}
.chain-area-inner {{
    width: 100%;
    max-width: 720px;
    display: flex;
    flex-direction: column;
    align-items: center;
}}
.chain-header {{
    width: 100%;
    text-align: center;
    margin-bottom: 24px;
}}
.chain-title {{
    font-size: 13px;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--text-muted);
    font-weight: 600;
}}

/* ===== CHAIN NODES ===== */
.chain-node {{
    width: 100%;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    cursor: pointer;
    transition: transform 0.15s, border-color 0.2s, box-shadow 0.2s;
    position: relative;
    overflow: hidden;
}}
.chain-node:hover {{ transform: translateY(-2px); border-color: var(--node-color); box-shadow: 0 4px 20px color-mix(in srgb, var(--node-color) 20%, transparent); }}
.chain-node.selected {{
    border-color: var(--node-color);
    box-shadow: 0 0 0 2px color-mix(in srgb, var(--node-color) 40%, transparent), 0 6px 24px color-mix(in srgb, var(--node-color) 25%, transparent);
    animation: node-glow-pulse 2s ease-in-out infinite;
}}
@keyframes node-glow-pulse {{
    0%, 100% {{ box-shadow: 0 0 0 2px color-mix(in srgb, var(--node-color) 40%, transparent), 0 6px 24px color-mix(in srgb, var(--node-color) 20%, transparent); }}
    50% {{ box-shadow: 0 0 0 4px color-mix(in srgb, var(--node-color) 60%, transparent), 0 8px 32px color-mix(in srgb, var(--node-color) 35%, transparent); }}
}}
.node-header {{
    display: flex;
    align-items: stretch;
}}
.node-severity-bar {{
    width: 4px;
    border-radius: 10px 0 0 10px;
    flex-shrink: 0;
}}
.node-content {{
    padding: 12px 14px;
    flex: 1;
    min-width: 0;
}}
.node-title {{
    font-size: 14px;
    font-weight: 600;
    margin-bottom: 6px;
    line-height: 1.3;
}}
.node-meta {{
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
    align-items: center;
}}
.node-crown {{ font-size: 11px; color: gold; font-weight: 700; }}
.node-entry {{ font-size: 11px; color: var(--accent); font-weight: 700; }}
.step-label {{
    font-size: 11px;
    color: var(--text-dim);
    font-family: monospace;
}}

/* ===== CHAIN CONNECTOR (ANIMATED ARROWS) ===== */
.chain-connector {{
    display: flex;
    justify-content: center;
    height: 60px;
    flex-shrink: 0;
}}
.flow-arrow {{
    width: 40px;
    height: 60px;
}}
.flow-line {{
    animation: flow-dash 1.5s ease-in-out forwards;
}}
.arrow-head {{
    opacity: 0;
    animation: arrow-appear 0.3s ease forwards;
    animation-delay: calc(var(--delay, 0s) + 1.2s);
}}
@keyframes flow-dash {{
    from {{ stroke-dashoffset: 40; opacity: 0.3; }}
    to {{ stroke-dashoffset: 0; opacity: 1; }}
}}
@keyframes arrow-appear {{
    from {{ opacity: 0; transform: translateY(4px); }}
    to {{ opacity: 0.9; transform: translateY(0); }}
}}

/* ===== SEVERITY BADGE ===== */
.severity-badge {{
    font-size: 10px;
    font-weight: 700;
    padding: 2px 7px;
    border-radius: 4px;
    text-transform: uppercase;
    letter-spacing: 0.3px;
    white-space: nowrap;
}}
.mitre-badge {{
    font-size: 10px;
    color: var(--text-muted);
    background: var(--surface2);
    border: 1px solid var(--border2);
    padding: 2px 7px;
    border-radius: 4px;
    font-family: monospace;
}}
.mitre-link-small {{
    font-size: 10px;
    color: var(--accent);
    background: #1e2640;
    border: 1px solid #2a3a60;
    padding: 2px 7px;
    border-radius: 4px;
    font-family: monospace;
}}

/* ===== SECONDARY FINDINGS ===== */
.secondary-findings {{
    width: 100%;
    max-width: 720px;
    margin-top: 32px;
    padding-top: 24px;
    border-top: 1px solid var(--border);
}}
.section-label {{
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    color: var(--text-muted);
    margin-bottom: 12px;
}}
.secondary-node {{
    display: flex;
    align-items: stretch;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    cursor: pointer;
    margin-bottom: 8px;
    transition: border-color 0.15s, transform 0.15s;
}}
.secondary-node:hover {{ border-color: var(--node-color); transform: translateX(2px); }}
.secondary-node.selected {{ border-color: var(--node-color); background: #1e2640; }}
.secondary-node .node-content {{ padding: 10px 14px; }}
.secondary-node .node-title {{ font-size: 13px; font-weight: 600; margin-bottom: 4px; }}
.secondary-node .node-severity-bar {{ border-radius: 8px 0 0 8px; width: 4px; }}

/* ===== TIMELINE BAR ===== */
.timeline-bar {{
    flex-shrink: 0;
    background: var(--surface);
    border-top: 1px solid var(--border);
    padding: 10px 32px 12px;
    position: relative;
}}
.timeline-label {{
    font-size: 11px;
    color: var(--text-dim);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 8px;
}}
.timeline-track {{
    position: relative;
    height: 48px;
    background: var(--surface2);
    border-radius: 6px;
    border: 1px solid var(--border);
    overflow: visible;
}}
.timeline-track::before {{
    content: '';
    position: absolute;
    left: 0;
    top: 50%;
    width: 100%;
    height: 2px;
    background: linear-gradient(90deg, var(--border2), var(--border));
    transform: translateY(-50%);
}}
.timeline-node {{
    position: absolute;
    top: 50%;
    transform: translate(-50%, -50%);
    cursor: pointer;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 2px;
}}
.timeline-dot {{
    width: 12px;
    height: 12px;
    border-radius: 50%;
    border: 2px solid var(--bg);
    transition: transform 0.15s;
    box-shadow: 0 0 6px color-mix(in srgb, var(--node-color, #888) 60%, transparent);
}}
.timeline-node:hover .timeline-dot {{ transform: scale(1.4); }}
.timeline-step-label {{
    font-size: 9px;
    color: var(--text-dim);
    font-family: monospace;
    position: absolute;
    top: -18px;
    white-space: nowrap;
}}
.timeline-time {{
    font-size: 9px;
    color: var(--text-dim);
    position: absolute;
    bottom: -18px;
    white-space: nowrap;
}}

/* ===== DETAIL DRAWER ===== */
.detail-drawer {{
    position: fixed;
    top: 0;
    right: -520px;
    width: var(--drawer-w);
    height: 100vh;
    background: var(--surface);
    border-left: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    overflow: hidden;
    transition: right 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    z-index: 100;
    box-shadow: -8px 0 32px rgba(0,0,0,0.4);
}}
.detail-drawer.open {{ right: 0; }}
.drawer-header {{
    padding: 16px 20px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 12px;
    flex-shrink: 0;
}}
.drawer-close {{
    background: none;
    border: 1px solid var(--border2);
    color: var(--text-muted);
    cursor: pointer;
    padding: 4px 8px;
    border-radius: 4px;
    font-size: 18px;
    line-height: 1;
    flex-shrink: 0;
    transition: background 0.15s;
}}
.drawer-close:hover {{ background: var(--surface2); color: var(--text); }}
.drawer-title {{
    font-size: 15px;
    font-weight: 600;
    line-height: 1.3;
}}
.drawer-body {{
    flex: 1;
    overflow-y: auto;
    padding: 20px;
}}
.drawer-section {{
    margin-bottom: 20px;
}}
.drawer-section-label {{
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    color: var(--text-dim);
    margin-bottom: 8px;
}}
.drawer-section-content {{
    font-size: 13px;
    line-height: 1.6;
    color: var(--text-muted);
    white-space: pre-wrap;
    word-break: break-word;
}}
.drawer-section-content.text-bright {{ color: var(--text); }}
.mitre-drawer-link {{
    display: inline-flex;
    align-items: center;
    gap: 6px;
    background: #1e2640;
    border: 1px solid #2a3a60;
    color: var(--accent);
    padding: 6px 12px;
    border-radius: 6px;
    font-family: monospace;
    font-size: 13px;
    font-weight: 600;
    text-decoration: none;
}}
.mitre-drawer-link:hover {{ background: #243060; text-decoration: none; }}
.evidence-block {{
    background: #0d1018;
    border: 1px solid var(--border2);
    border-radius: 6px;
    padding: 12px 14px;
    font-family: 'Courier New', monospace;
    font-size: 11px;
    line-height: 1.6;
    color: #8be0a4;
    overflow-x: auto;
    white-space: pre;
    max-height: 200px;
    overflow-y: auto;
}}
.confidence-bar-wrap {{
    display: flex;
    align-items: center;
    gap: 10px;
}}
.confidence-bar-bg {{
    flex: 1;
    height: 6px;
    background: var(--surface2);
    border-radius: 3px;
    overflow: hidden;
}}
.confidence-bar-fill {{
    height: 100%;
    border-radius: 3px;
    transition: width 0.5s ease;
}}
.confidence-pct {{
    font-size: 12px;
    font-weight: 600;
    min-width: 36px;
    text-align: right;
}}

/* ===== SCROLLBAR ===== */
::-webkit-scrollbar {{ width: 6px; height: 6px; }}
::-webkit-scrollbar-track {{ background: transparent; }}
::-webkit-scrollbar-thumb {{ background: var(--border2); border-radius: 3px; }}
::-webkit-scrollbar-thumb:hover {{ background: #404a60; }}

/* ===== RESPONSIVE ===== */
@media (max-width: 1300px) {{
    .left-panel {{ width: 280px; min-width: 240px; }}
    .chain-area {{ padding: 16px 16px; }}
    :root {{ --drawer-w: 400px; }}
}}
@media (min-width: 1600px) {{
    .left-panel {{ width: 360px; }}
    :root {{ --drawer-w: 520px; }}
}}
</style>
</head>
<body>
<div class="app-wrapper">

<!-- TOP BAR -->
<div class="topbar">
    <div class="topbar-title">
        ⛓ Attack Chain — {_escape(engagement.target_name or engagement.engagement_id)}
    </div>
    <div class="topbar-right">
        <div class="risk-score-badge">
            <span class="risk-score-label">Chain risk score</span>
            <span class="risk-score-value" style="color:{risk_color}">{chain_risk_score}</span>
        </div>
        <button class="export-btn" onclick="exportHTML()">
            ↓ Export HTML
        </button>
    </div>
</div>

<!-- MAIN PANELS -->
<div class="main-panels">

    <!-- LEFT PANEL: ALL FINDINGS -->
    <div class="left-panel">
        <div class="panel-header">
            <div class="panel-title">All Findings ({len(engagement.findings)})</div>
        </div>
        <div class="findings-list" id="findingsList">
            {left_panel_html}
        </div>
    </div>

    <!-- RIGHT PANEL: CHAIN + TIMELINE -->
    <div class="right-panel">
        <div class="chain-area" id="chainArea">
            <div class="chain-area-inner">
                <div class="chain-header">
                    <div class="chain-title">Primary Attack Chain ({len(primary_chain)} steps)</div>
                </div>
                {chain_nodes_html}
                {secondary_html}
            </div>
        </div>
        {timeline_html}
    </div>

</div>
</div>

<!-- DETAIL DRAWER -->
<div class="detail-drawer" id="detailDrawer">
    <div class="drawer-header">
        <div>
            <div id="drawerTitle" class="drawer-title"></div>
            <div id="drawerBadges" style="margin-top:8px;display:flex;gap:8px;flex-wrap:wrap"></div>
        </div>
        <button class="drawer-close" onclick="closeDrawer()">✕</button>
    </div>
    <div class="drawer-body" id="drawerBody"></div>
</div>

<script>
// ===== DATA =====
const ALL_FINDINGS = {all_findings_js};
const PRIMARY_CHAIN = {chain_js};
const SECONDARY_IDS = {secondary_js};
const FINDING_MAP = Object.fromEntries(ALL_FINDINGS.map(f => [f.id, f]));

// ===== STATE =====
let selectedId = null;

// ===== SELECTION =====
function selectFinding(id) {{
    if (selectedId === id) {{
        closeDrawer();
        clearSelection();
        selectedId = null;
        return;
    }}
    selectedId = id;
    clearSelection();
    highlightBoth(id);
    openDrawer(id);
}}

function clearSelection() {{
    document.querySelectorAll('.selected').forEach(el => el.classList.remove('selected'));
}}

function highlightBoth(id) {{
    const leftEl = document.getElementById('left-' + id);
    if (leftEl) {{
        leftEl.classList.add('selected');
        leftEl.style.setProperty('--node-color', getColor(id));
        leftEl.scrollIntoView({{behavior:'smooth', block:'nearest'}});
    }}
    const chainEl = document.getElementById('chain-' + id);
    if (chainEl) {{
        chainEl.classList.add('selected');
        chainEl.scrollIntoView({{behavior:'smooth', block:'nearest'}});
    }}
    // Secondary nodes
    document.querySelectorAll('[data-id="' + id + '"]').forEach(el => {{
        el.classList.add('selected');
    }});
}}

function getColor(id) {{
    const f = FINDING_MAP[id];
    if (!f) return '#888';
    const colors = {{CRITICAL:'#e74c3c',HIGH:'#e67e22',MEDIUM:'#f39c12',LOW:'#7f8c8d',INFO:'#95a5a6'}};
    return colors[f.severity_label] || '#888';
}}

// ===== DRAWER =====
function openDrawer(id) {{
    const f = FINDING_MAP[id];
    if (!f) return;
    const color = getColor(id);
    const drawer = document.getElementById('detailDrawer');
    const body = document.getElementById('drawerBody');
    document.getElementById('drawerTitle').textContent = f.title;

    const badges = document.getElementById('drawerBadges');
    badges.innerHTML = '';
    const badge = document.createElement('span');
    badge.className = 'severity-badge';
    badge.style.cssText = `background:${{color}}20;color:${{color}};border:1px solid ${{color}}40;font-size:12px;padding:4px 10px`;
    badge.textContent = f.severity.toFixed(1) + ' ' + f.severity_label;
    badges.appendChild(badge);

    if (f.mitre_technique) {{
        const baseId = f.mitre_technique.includes('.') ? f.mitre_technique.split('.')[0] : f.mitre_technique;
        const mitreUrl = 'https://attack.mitre.org/techniques/' + baseId + '/';
        const ml = document.createElement('a');
        ml.href = mitreUrl;
        ml.target = '_blank';
        ml.className = 'mitre-drawer-link';
        ml.textContent = '↗ ' + f.mitre_technique;
        badges.appendChild(ml);
    }}

    let html = '';

    if (f.host) {{
        html += `<div class="drawer-section">
            <div class="drawer-section-label">Target Host</div>
            <div class="drawer-section-content text-bright">${{esc(f.host)}}</div>
        </div>`;
    }}

    if (f.ai_detail) {{
        html += `<div class="drawer-section">
            <div class="drawer-section-label">AI Analysis</div>
            <div class="drawer-section-content">${{esc(f.ai_detail)}}</div>
        </div>`;
    }}

    if (f.ai_remediation) {{
        html += `<div class="drawer-section">
            <div class="drawer-section-label">Remediation</div>
            <div class="drawer-section-content">${{esc(f.ai_remediation)}}</div>
        </div>`;
    }}

    if (f.ai_confidence !== null && f.ai_confidence !== undefined) {{
        const pct = Math.round(f.ai_confidence * 100);
        const confColor = pct >= 90 ? '#2ecc71' : pct >= 70 ? '#f39c12' : '#e74c3c';
        html += `<div class="drawer-section">
            <div class="drawer-section-label">AI Confidence</div>
            <div class="confidence-bar-wrap">
                <div class="confidence-bar-bg">
                    <div class="confidence-bar-fill" style="width:${{pct}}%;background:${{confColor}}"></div>
                </div>
                <span class="confidence-pct" style="color:${{confColor}}">${{pct}}%</span>
            </div>
        </div>`;
    }}

    if (f.evidence) {{
        html += `<div class="drawer-section">
            <div class="drawer-section-label">Evidence</div>
            <div class="evidence-block">${{esc(f.evidence)}}</div>
        </div>`;
    }}

    if (f.step_index !== null && f.step_index !== undefined) {{
        const ts = f.timestamp_offset_s;
        const timeStr = ts !== null && ts !== undefined ? formatTime(ts) : 'N/A';
        html += `<div class="drawer-section">
            <div class="drawer-section-label">Step Info</div>
            <div class="drawer-section-content">Step ${{f.step_index}} &nbsp;·&nbsp; T+${{timeStr}}</div>
        </div>`;
    }}

    if (f.enabled_by && f.enabled_by.length > 0) {{
        const titles = f.enabled_by.map(pid => (FINDING_MAP[pid] || {{title:pid}}).title).join(', ');
        html += `<div class="drawer-section">
            <div class="drawer-section-label">Enabled By</div>
            <div class="drawer-section-content">${{esc(titles)}}</div>
        </div>`;
    }}

    body.innerHTML = html;
    drawer.classList.add('open');
}}

function closeDrawer() {{
    document.getElementById('detailDrawer').classList.remove('open');
    clearSelection();
    selectedId = null;
}}

// ===== HELPERS =====
function esc(s) {{
    if (!s) return '';
    return String(s)
        .replace(/&/g,'&amp;')
        .replace(/</g,'&lt;')
        .replace(/>/g,'&gt;')
        .replace(/"/g,'&quot;');
}}

function formatTime(secs) {{
    const h = Math.floor(secs / 3600);
    const m = Math.floor((secs % 3600) / 60);
    const s = secs % 60;
    if (h > 0) return h + 'h' + String(m).padStart(2,'0') + 'm';
    if (m > 0) return m + 'm' + String(s).padStart(2,'0') + 's';
    return s + 's';
}}

// ===== EXPORT =====
function exportHTML() {{
    const content = '<!DOCTYPE html>' + document.documentElement.outerHTML;
    const blob = new Blob([content], {{type:'text/html'}});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'attack-chain-{_escape(engagement.engagement_id)}.html';
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {{ URL.revokeObjectURL(url); a.remove(); }}, 100);
}}

// Close drawer on Escape
document.addEventListener('keydown', e => {{ if (e.key === 'Escape') closeDrawer(); }});
</script>
</body>
</html>"""

    return html


def render_to_file(
    engagement: Engagement,
    primary_chain: list[Finding],
    secondary_findings: list[Finding],
    chain_risk_score: float,
    output_path: str | Path,
) -> Path:
    """Render HTML and write to file. Returns the output path."""
    html = render_html(engagement, primary_chain, secondary_findings, chain_risk_score)
    out = Path(output_path)
    out.write_text(html, encoding="utf-8")
    return out
