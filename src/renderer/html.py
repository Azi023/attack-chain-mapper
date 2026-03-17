"""Interactive HTML renderer — Pentera-style SVG chain visualization.

Design: light/dark adaptive CSS variables, SVG-based chain panel, bottom detail drawer.
All 10 renderer requirements preserved; visual redesign from div-cards to SVG nodes.
"""
from __future__ import annotations

import json
from pathlib import Path

from src.ingestion.schema import Finding, Engagement
from src.graph.scorer import compute_chain_risk_score, risk_score_color

# ── SVG layout constants ────────────────────────────────────────────────────
_SVG_W = 580
_NODE_X = 50        # left edge of all nodes
_NODE_W = 480       # full-width node
_NODE_W_HALF = 228  # half-width node (two side-by-side + 24px gap = 480)
_NODE_GAP = 24      # gap between side-by-side nodes
_NODE_H = 68        # node box height
_ARROW_H = 50       # vertical space reserved for arrows between rows
_ROW_H = _NODE_H + _ARROW_H
_TIMELINE_PAD = 60  # height below last node for timeline


# ── Helpers ─────────────────────────────────────────────────────────────────

def _esc(s: str | None) -> str:
    if not s:
        return ""
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _color(label: str) -> str:
    return {
        "CRITICAL": "#e74c3c",
        "HIGH": "#e67e22",
        "MEDIUM": "#f39c12",
        "LOW": "#7f8c8d",
        "INFO": "#95a5a6",
    }.get((label or "INFO").upper(), "#95a5a6")


def _mitre_url(technique: str) -> str:
    base = technique.split(".")[0] if "." in technique else technique
    return f"https://attack.mitre.org/techniques/{base}/"


def _wrap(text: str, max_len: int = 52) -> list[str]:
    """Split a title into ≤2 lines of max_len chars each."""
    if len(text) <= max_len:
        return [text]
    # Try to split at a word boundary
    cut = text[:max_len].rfind(" ")
    if cut == -1:
        cut = max_len
    part1 = text[:cut]
    part2 = text[cut:].strip()
    if len(part2) > max_len:
        part2 = part2[:max_len - 1] + "…"
    return [part1, part2]


def _finding_to_js(f: Finding) -> dict:
    return {k: getattr(f, k) for k in Finding.model_fields}


# ── Layout engine ────────────────────────────────────────────────────────────

def _compute_rows(
    primary_chain: list[Finding],
    all_findings: list[Finding],
) -> list[list[Finding]]:
    """Assign findings to display rows (row 0 = crown jewel at top).

    Secondary findings that are direct parents of a primary chain node are shown
    side-by-side with the primary chain predecessor at that level.
    """
    fmap = {f.id: f for f in all_findings}
    primary_ids = {f.id for f in primary_chain}
    # display order: crown jewel first
    display = list(reversed(primary_chain))

    def sec_parents(f: Finding) -> list[Finding]:
        return [
            fmap[eid] for eid in (f.enabled_by or [])
            if eid in fmap and eid not in primary_ids
        ]

    rows: list[list[Finding]] = []
    for i, f in enumerate(display):
        # Secondary parents of display[i-1] (the node above) appear at this level
        siblings = sec_parents(display[i - 1]) if i > 0 else []
        rows.append([f] + siblings)

    return rows


def _node_rect(row_idx: int, node_idx: int, row_size: int) -> tuple[float, float, float, float]:
    """Return (x, y, w, h) for a node in the SVG."""
    y = 20 + row_idx * _ROW_H
    h = float(_NODE_H)
    if row_size == 1:
        return float(_NODE_X), y, float(_NODE_W), h
    w = float(_NODE_W_HALF)
    x = float(_NODE_X) + node_idx * (w + _NODE_GAP)
    return x, y, w, h


# ── SVG rendering ─────────────────────────────────────────────────────────────

def _svg_defs() -> str:
    return """<defs>
  <marker id="ah-red" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
    <path d="M2 1L8 5L2 9" fill="none" stroke="#e74c3c" stroke-width="1.5" stroke-linecap="round"/>
  </marker>
  <marker id="ah-grey" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
    <path d="M2 1L8 5L2 9" fill="none" stroke="var(--c-border2)" stroke-width="1.5" stroke-linecap="round"/>
  </marker>
  <style>
    @keyframes dashflow { to { stroke-dashoffset: -20; } }
    .flow-line { stroke-dasharray: 6 4; animation: dashflow 1.2s linear infinite; }
    .chain-node { cursor: pointer; }
    .chain-node rect.bg { transition: opacity 0.15s; }
    .chain-node:hover rect.bg { opacity: 0.15; }
    .chain-node.selected rect.bg { opacity: 0.15; }
  </style>
</defs>"""


def _svg_node(
    f: Finding,
    x: float, y: float, w: float, h: float,
    is_crown: bool,
    is_entry: bool,
) -> str:
    c = _color(f.severity_label)
    bg_opacity = "0.10" if is_crown else "0.04"
    stroke_w = "1" if is_crown else "0.5"
    stroke_color = c if is_crown else "var(--c-border)"

    title_lines = _wrap(f.title, max_len=52 if w > 400 else 28)
    title_y1 = y + 45
    title_y2 = y + 59

    meta_parts = []
    if f.mitre_technique:
        meta_parts.append(f"· {_esc(f.mitre_technique)}")
    if f.step_index is not None:
        meta_parts.append(f"· Step {f.step_index}")
    meta_str = "  " + "  ".join(meta_parts) if meta_parts else ""

    badge_x = x + w - 90
    badge_text = ""
    badge_color = ""
    if is_crown:
        badge_text = "👑 CROWN JEWEL"
        badge_color = "#e8a87c"
    elif is_entry:
        badge_text = "⚡ ENTRY POINT"
        badge_color = "#3498db"

    # Timestamp label
    ts_label = ""
    if f.timestamp_offset_s is not None:
        mins = f.timestamp_offset_s // 60
        h_part = mins // 60
        m_part = mins % 60
        ts_label = f"+{h_part}h{m_part:02d}m" if h_part else f"+{m_part}m"

    svg = f"""<g class="chain-node" id="cn-{_esc(f.id)}" onclick="sel('{_esc(f.id)}')" data-id="{_esc(f.id)}" data-has-ai="{'true' if f.ai_detail else 'false'}">
  <rect class="bg" x="{x}" y="{y}" width="{w}" height="{h}" rx="5" fill="{c}" fill-opacity="{bg_opacity}" stroke="{stroke_color}" stroke-width="{stroke_w}"/>
  <rect x="{x}" y="{y}" width="4" height="{h}" rx="2" fill="{c}"/>
  <text x="{x+14}" y="{y+22}" font-size="11" font-weight="600" fill="{c}">{f.severity:.1f} {_esc(f.severity_label)}</text>
  <text x="{x+14+65}" y="{y+22}" font-size="10" fill="var(--c-text3)" class="svg-meta">{_esc(meta_str)}</text>"""

    if badge_text:
        svg += f'\n  <text x="{badge_x}" y="{y+22}" font-size="10" fill="{badge_color}" text-anchor="middle">{badge_text}</text>'

    if ts_label:
        svg += f'\n  <text x="{x+w-8}" y="{y+h-8}" font-size="9" fill="var(--c-text3)" text-anchor="end">{_esc(ts_label)}</text>'

    svg += f'\n  <text x="{x+14}" y="{title_y1}" font-size="12" font-weight="500" fill="var(--c-text1)">{_esc(title_lines[0])}</text>'
    if len(title_lines) > 1:
        svg += f'\n  <text x="{x+14}" y="{title_y2}" font-size="12" font-weight="500" fill="var(--c-text2)">{_esc(title_lines[1])}</text>'

    svg += "\n</g>"
    return svg


def _svg_arrow(
    sx: float, sy: float,  # source bottom-center
    tx: float, ty: float,  # target top-center
    color: str,
    label: str = "",
    dashed: bool = True,
) -> str:
    mid_y = sy + (ty - sy) * 0.45
    marker = f'marker-end="url(#ah-{"red" if color == "#e74c3c" else "grey"})"'
    cls = 'class="flow-line"' if dashed else ""
    label_html = ""
    if label:
        lx = (sx + tx) / 2 + 4
        ly = (sy + ty) / 2
        label_html = f'<text x="{lx:.1f}" y="{ly:.1f}" font-size="9.5" fill="var(--c-text3)">{_esc(label)}</text>'

    if abs(sx - tx) < 2:
        # Straight vertical line
        path = f'<line x1="{sx:.1f}" y1="{sy:.1f}" x2="{tx:.1f}" y2="{ty:.1f}" stroke="{color}" stroke-width="1.5" {cls} {marker}/>'
    else:
        # L-shaped path: down, then diagonal to target
        d = f"M{sx:.1f} {sy:.1f} L{sx:.1f} {mid_y:.1f} L{tx:.1f} {mid_y:.1f} L{tx:.1f} {ty:.1f}"
        path = f'<path d="{d}" fill="none" stroke="{color}" stroke-width="1.5" {cls} {marker}/>'

    return path + label_html


def _svg_timeline(primary_chain: list[Finding], pos_map: dict, n_rows: int) -> str:
    tl_y = 20 + n_rows * _ROW_H + 20
    findings_with_ts = [f for f in primary_chain if f.timestamp_offset_s is not None]
    if not findings_with_ts:
        return ""

    max_ts = max(f.timestamp_offset_s for f in findings_with_ts)
    min_ts = 0

    def px(ts: int) -> float:
        span = max(max_ts - min_ts, 1)
        return _NODE_X + (ts - min_ts) / span * _NODE_W

    axis = f'<line x1="{_NODE_X}" y1="{tl_y}" x2="{_NODE_X + _NODE_W}" y2="{tl_y}" stroke="var(--c-border)" stroke-width="0.5"/>'
    axis += f'<text x="{_NODE_X}" y="{tl_y + 24}" font-size="9" fill="var(--c-text3)">ATTACK TIMELINE</text>'

    for f in sorted(findings_with_ts, key=lambda x: x.timestamp_offset_s):
        cx = px(f.timestamp_offset_s)
        c = _color(f.severity_label)
        r = 5 if f.severity >= 9 else 4
        mins = f.timestamp_offset_s // 60
        hh = mins // 60
        mm = mins % 60
        ts_label = f"+{hh}h{mm:02d}m" if hh else f"+{mm}m"
        step_label = f"S{f.step_index}" if f.step_index is not None else ""
        axis += f'<circle cx="{cx:.1f}" cy="{tl_y}" r="{r}" fill="{c}" style="cursor:pointer" onclick="sel(\'{_esc(f.id)}\')"/>'
        if step_label:
            axis += f'<text x="{cx:.1f}" y="{tl_y-8}" font-size="9" fill="var(--c-text3)" text-anchor="middle">{step_label}</text>'
        axis += f'<text x="{cx:.1f}" y="{tl_y+14}" font-size="9" fill="var(--c-text3)" text-anchor="middle">{ts_label}</text>'

    return axis


def _render_chain_svg(
    primary_chain: list[Finding],
    secondary_findings: list[Finding],
    all_findings: list[Finding],
) -> str:
    rows = _compute_rows(primary_chain, all_findings)
    n_rows = len(rows)
    svg_h = 20 + n_rows * _ROW_H + _TIMELINE_PAD

    # Build position map: finding_id → (x, y, w, h)
    pos_map: dict[str, tuple] = {}
    for ri, row in enumerate(rows):
        for ni, f in enumerate(row):
            pos_map[f.id] = _node_rect(ri, ni, len(row))

    svg = f'<svg width="100%" viewBox="0 0 {_SVG_W} {svg_h}" style="overflow:visible">\n'
    svg += _svg_defs()

    # Draw arrows first (so they appear under nodes)
    primary_ids = {f.id for f in primary_chain}
    for ri, row in enumerate(rows):
        for ni, f in enumerate(row):
            x, y, w, h = pos_map[f.id]
            bx, by = x + w / 2, y + h
            for eid in (f.enabled_by or []):
                if eid not in pos_map:
                    continue
                tx, ty, tw, th = pos_map[eid]
                tcx, tty = tx + tw / 2, ty
                is_primary_link = (eid in primary_ids)
                c = _color(f.severity_label) if (is_primary_link and f.severity >= 6) else "var(--c-border2)"
                svg += _svg_arrow(bx, by, tcx, tty, c, dashed=True)

    # Draw nodes
    for ri, row in enumerate(rows):
        for ni, f in enumerate(row):
            x, y, w, h = pos_map[f.id]
            is_crown = (ri == 0 and ni == 0)
            is_entry = (ri == n_rows - 1 and ni == 0)
            svg += _svg_node(f, x, y, w, h, is_crown, is_entry)

    # Timeline
    svg += _svg_timeline(primary_chain, pos_map, n_rows)

    svg += "\n</svg>"
    return svg


# ── Left panel ────────────────────────────────────────────────────────────────

def _left_panel(
    all_findings: list[Finding],
    primary_chain: list[Finding],
    secondary_findings: list[Finding],
) -> str:
    primary_ids = {f.id for f in primary_chain}
    ranked = sorted(all_findings, key=lambda f: f.severity, reverse=True)
    in_chain = [f for f in ranked if f.id in primary_ids]
    not_chain = [f for f in ranked if f.id not in primary_ids]

    def row(f: Finding, dimmed: bool = False) -> str:
        c = _color(f.severity_label)
        bg_style = "" if dimmed else ""
        opacity = "opacity:0.55;" if dimmed else ""
        border = "transparent" if dimmed else c
        mitre_chip = ""
        if f.mitre_technique:
            mitre_chip = f'<span class="chip chip-mitre">{_esc(f.mitre_technique)}</span>'
        sev_score = f.severity if f.severity > 0 else "INFO" if f.severity == 0 else f.severity
        score_str = "INFO" if f.severity == 0 else f"{f.severity:.1f}"
        return f"""<div class="frow" id="lr-{_esc(f.id)}" onclick="sel('{_esc(f.id)}')" data-id="{_esc(f.id)}" style="{opacity}border-left:3px solid {border};--frow-color:{c}">
  <span class="frow-score" style="color:{c}">{score_str}</span>
  <div class="frow-body">
    <div class="frow-title">{_esc(f.title)}</div>
    <div class="frow-chips">
      <span class="chip chip-sev" style="background:{c};color:#fff">{_esc(f.severity_label)}</span>
      {mitre_chip}
    </div>
  </div>
</div>"""

    html = '<div class="panel-label">ALL FINDINGS (' + str(len(all_findings)) + ')</div>'
    for f in in_chain:
        html += row(f)
    if not_chain:
        html += '<div class="panel-label panel-label-dim" style="margin-top:10px;border-top:0.5px solid var(--c-border)">NOT IN PRIMARY CHAIN</div>'
        for f in not_chain:
            html += row(f, dimmed=True)
    return html


# ── Full HTML ─────────────────────────────────────────────────────────────────

def render_html(
    engagement: Engagement,
    primary_chain: list[Finding],
    secondary_findings: list[Finding],
    chain_risk_score: float,
) -> str:
    title = _esc(engagement.target_name or engagement.engagement_id)
    risk_color = risk_score_color(chain_risk_score)

    all_findings_js = json.dumps([_finding_to_js(f) for f in engagement.findings])
    chain_ids_js = json.dumps([f.id for f in primary_chain])

    left_html = _left_panel(engagement.findings, primary_chain, secondary_findings)
    chain_svg = _render_chain_svg(primary_chain, secondary_findings, engagement.findings)

    sec_label = ""
    if secondary_findings:
        names = "; ".join(f.title[:40] for f in secondary_findings[:3])
        if len(secondary_findings) > 3:
            names += f" +{len(secondary_findings)-3} more"
        sec_label = f'<div class="sec-note">⊕ Additional findings not in primary chain: {_esc(names)}</div>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Attack Chain — {title}</title>
<style>
/* ── THEME ── */
:root {{
  --c-bg:       #ffffff;
  --c-surf:     #f8f9fc;
  --c-surf2:    #f0f2f7;
  --c-border:   #e2e6ef;
  --c-border2:  #ccd1de;
  --c-text1:    #0d1117;
  --c-text2:    #3a4560;
  --c-text3:    #8892a4;
  --c-text4:    #b0b8c8;
  --font: system-ui,-apple-system,'Segoe UI',sans-serif;
}}
@media (prefers-color-scheme: dark) {{
  :root {{
    --c-bg:     #0f1117;
    --c-surf:   #1a1f2e;
    --c-surf2:  #212736;
    --c-border: #2a3040;
    --c-border2:#3a4458;
    --c-text1:  #e8eaf0;
    --c-text2:  #a8b2c4;
    --c-text3:  #6a7488;
    --c-text4:  #4a5268;
  }}
}}
/* ── RESET ── */
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
html,body{{height:100%;background:var(--c-bg);color:var(--c-text1);font-family:var(--font);font-size:14px}}
a{{color:#3498db;text-decoration:none}}
a:hover{{text-decoration:underline}}
::-webkit-scrollbar{{width:5px;height:5px}}
::-webkit-scrollbar-track{{background:transparent}}
::-webkit-scrollbar-thumb{{background:var(--c-border2);border-radius:3px}}

/* ── LAYOUT ── */
.app{{display:flex;flex-direction:column;height:100vh;overflow:hidden}}
.topbar{{display:flex;align-items:center;justify-content:space-between;padding:11px 20px;border-bottom:0.5px solid var(--c-border);flex-shrink:0;gap:12px;background:var(--c-surf)}}
.topbar-left{{display:flex;align-items:center;gap:8px;min-width:0}}
.topbar-dot{{width:8px;height:8px;border-radius:50%;background:#e74c3c;flex-shrink:0}}
.topbar-title{{font-size:13px;font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
.topbar-right{{display:flex;align-items:center;gap:14px;flex-shrink:0}}
.risk-label{{font-size:11px;color:var(--c-text3)}}
.risk-value{{font-size:20px;font-weight:500}}
.export-btn{{font-size:12px;padding:6px 14px;border-radius:6px;border:0.5px solid var(--c-border2);background:var(--c-surf);color:var(--c-text1);cursor:pointer;white-space:nowrap;transition:background 0.15s}}
.export-btn:hover{{background:var(--c-surf2)}}

.panels{{display:grid;grid-template-columns:262px 1fr;flex:1;overflow:hidden;min-height:0}}

/* ── LEFT PANEL ── */
.left-panel{{border-right:0.5px solid var(--c-border);overflow-y:auto;background:var(--c-surf)}}
.panel-label{{padding:10px 16px 6px;font-size:10px;letter-spacing:0.08em;color:var(--c-text3);font-weight:600;text-transform:uppercase}}
.panel-label-dim{{padding-top:8px}}
.frow{{display:flex;align-items:flex-start;gap:10px;padding:9px 16px;cursor:pointer;border-left:3px solid transparent;transition:background 0.12s}}
.frow:hover{{background:color-mix(in srgb,var(--frow-color,#888) 6%,var(--c-surf))}}
.frow.selected{{background:color-mix(in srgb,var(--frow-color,#888) 8%,var(--c-bg));border-left-color:var(--frow-color,#888)!important}}
.frow-score{{font-size:15px;font-weight:500;min-width:30px;flex-shrink:0;line-height:1.2}}
.frow-body{{min-width:0}}
.frow-title{{font-size:12px;font-weight:500;line-height:1.35;color:var(--c-text1);margin-bottom:5px}}
.frow-chips{{display:flex;gap:5px;flex-wrap:wrap}}
.chip{{font-size:10px;padding:2px 6px;border-radius:3px;font-weight:500;white-space:nowrap}}
.chip-sev{{}}
.chip-mitre{{background:var(--c-surf2);color:var(--c-text3);border:0.5px solid var(--c-border2);font-family:monospace}}

/* ── RIGHT PANEL ── */
.right-panel{{display:flex;flex-direction:column;overflow:hidden;min-width:0}}
.chain-area{{flex:1;overflow-y:auto;padding:20px 28px}}
.chain-label{{font-size:10px;letter-spacing:0.08em;color:var(--c-text3);font-weight:600;text-transform:uppercase;margin-bottom:18px}}
.sec-note{{font-size:11px;color:var(--c-text3);margin-top:16px;padding:8px 12px;border:0.5px solid var(--c-border);border-radius:5px;background:var(--c-surf2)}}

/* SVG text helpers */
.svg-meta{{font-family:monospace}}

/* ── DETAIL DRAWER (bottom) ── */
.drawer{{flex-shrink:0;border-top:0.5px solid var(--c-border);background:var(--c-surf);display:none}}
.drawer.open{{display:block}}
.drawer-inner{{padding:16px 20px}}
.drawer-head{{display:flex;align-items:center;gap:10px;margin-bottom:10px}}
.drawer-title{{font-size:15px;font-weight:500;color:var(--c-text1);flex:1;min-width:0}}
.drawer-close{{background:none;border:0.5px solid var(--c-border2);color:var(--c-text3);cursor:pointer;padding:3px 9px;border-radius:4px;font-size:16px;line-height:1;flex-shrink:0}}
.drawer-close:hover{{background:var(--c-surf2)}}
.drawer-meta{{display:flex;align-items:center;gap:10px;margin-bottom:14px;flex-wrap:wrap}}
.dsev{{font-size:11px;padding:3px 10px;border-radius:4px;font-weight:600}}
.dmitre{{font-size:11px;font-family:monospace}}
.dhost{{font-size:11px;color:var(--c-text3);margin-left:auto}}
.drawer-body{{display:grid;grid-template-columns:1fr 1fr;gap:24px}}
.drawer-col-label{{font-size:10px;letter-spacing:0.08em;color:var(--c-text3);font-weight:600;text-transform:uppercase;margin-bottom:6px}}
.drawer-col-text{{font-size:12px;color:var(--c-text2);line-height:1.7;white-space:pre-wrap;word-break:break-word;max-height:160px;overflow-y:auto}}
.drawer-loading{{color:var(--c-text4);font-style:italic}}
.evidence-block{{font-size:11px;font-family:monospace;background:var(--c-bg);border:0.5px solid var(--c-border2);border-radius:5px;padding:8px 10px;color:#5cb85c;line-height:1.5;max-height:120px;overflow-y:auto;white-space:pre}}

/* ── RESPONSIVE ── */
@media(max-width:1100px){{
  .panels{{grid-template-columns:240px 1fr}}
  .drawer-body{{grid-template-columns:1fr}}
}}
@media(min-width:1600px){{
  .panels{{grid-template-columns:300px 1fr}}
}}
</style>
</head>
<body>
<div class="app">

<!-- TOP BAR -->
<div class="topbar">
  <div class="topbar-left">
    <div class="topbar-dot"></div>
    <span class="topbar-title">Attack Chain — {title}</span>
  </div>
  <div class="topbar-right">
    <span class="risk-label">Chain risk score</span>
    <span class="risk-value" style="color:{risk_color}">{chain_risk_score}</span>
    <button class="export-btn" onclick="exportHTML()">↓ Export HTML</button>
  </div>
</div>

<div class="panels">

  <!-- LEFT -->
  <div class="left-panel">
    {left_html}
  </div>

  <!-- RIGHT -->
  <div class="right-panel">
    <div class="chain-area">
      <div class="chain-label">PRIMARY ATTACK CHAIN — {len(primary_chain)} STEPS</div>
      {chain_svg}
      {sec_label}
    </div>
  </div>

</div>

<!-- BOTTOM DETAIL DRAWER -->
<div class="drawer" id="drawer">
  <div class="drawer-inner">
    <div class="drawer-head">
      <div class="drawer-title" id="d-title"></div>
      <button class="drawer-close" onclick="closeDrawer()">✕</button>
    </div>
    <div class="drawer-meta" id="d-meta"></div>
    <div class="drawer-body">
      <div>
        <div class="drawer-col-label">AI Analysis</div>
        <div class="drawer-col-text" id="d-detail"></div>
      </div>
      <div>
        <div class="drawer-col-label">Remediation</div>
        <div class="drawer-col-text" id="d-rem"></div>
      </div>
    </div>
    <div id="d-evidence-wrap" style="margin-top:12px;display:none">
      <div class="drawer-col-label" style="margin-bottom:5px">Evidence</div>
      <div class="evidence-block" id="d-evidence"></div>
    </div>
  </div>
</div>

</div><!-- .app -->

<script>
const ALL_FINDINGS = {all_findings_js};
const PRIMARY_CHAIN = {chain_ids_js};
const FMAP = Object.fromEntries(ALL_FINDINGS.map(f=>[f.id,f]));
const COLORS = {{CRITICAL:'#e74c3c',HIGH:'#e67e22',MEDIUM:'#f39c12',LOW:'#7f8c8d',INFO:'#95a5a6'}};

let current = null;

function sel(id) {{
  if (current === id) {{ closeDrawer(); return; }}
  current = id;

  // Clear all selection states
  document.querySelectorAll('.frow').forEach(el=>el.classList.remove('selected'));
  document.querySelectorAll('.chain-node').forEach(el=>el.classList.remove('selected'));

  // Highlight left row
  const lr = document.getElementById('lr-'+id);
  if (lr) {{ lr.classList.add('selected'); lr.scrollIntoView({{behavior:'smooth',block:'nearest'}}); }}

  // Highlight chain node
  const cn = document.getElementById('cn-'+id);
  if (cn) cn.classList.add('selected');

  openDrawer(id);
}}

function openDrawer(id) {{
  const f = FMAP[id]; if (!f) return;
  const c = COLORS[f.severity_label] || '#95a5a6';

  document.getElementById('d-title').textContent = f.title;

  // Meta row
  const meta = document.getElementById('d-meta');
  meta.innerHTML = '';
  const sev = document.createElement('span');
  sev.className = 'dsev';
  sev.style.cssText = `background:${{c}}22;color:${{c}};border:0.5px solid ${{c}}66`;
  sev.textContent = f.severity.toFixed(1)+' '+f.severity_label;
  meta.appendChild(sev);

  if (f.mitre_technique) {{
    const base = f.mitre_technique.includes('.') ? f.mitre_technique.split('.')[0] : f.mitre_technique;
    const ml = document.createElement('a');
    ml.href = 'https://attack.mitre.org/techniques/'+base+'/';
    ml.target = '_blank';
    ml.className = 'dmitre';
    ml.textContent = '↗ '+f.mitre_technique;
    meta.appendChild(ml);
  }}
  if (f.host) {{
    const hd = document.createElement('span');
    hd.className = 'dhost';
    hd.textContent = f.host;
    meta.appendChild(hd);
  }}

  // AI detail
  const dd = document.getElementById('d-detail');
  if (f.ai_detail) {{
    dd.textContent = f.ai_detail;
    dd.classList.remove('drawer-loading');
  }} else {{
    dd.textContent = 'Loading AI analysis… Run with --api-key to generate real-time analysis.';
    dd.classList.add('drawer-loading');
  }}

  // Remediation
  const dr = document.getElementById('d-rem');
  if (f.ai_remediation) {{
    dr.textContent = f.ai_remediation;
    dr.classList.remove('drawer-loading');
  }} else {{
    dr.textContent = 'Remediation guidance will appear after AI enrichment.';
    dr.classList.add('drawer-loading');
  }}

  // Evidence
  const evWrap = document.getElementById('d-evidence-wrap');
  const evEl = document.getElementById('d-evidence');
  if (f.evidence) {{
    evEl.textContent = f.evidence;
    evWrap.style.display = 'block';
  }} else {{
    evWrap.style.display = 'none';
  }}

  document.getElementById('drawer').classList.add('open');
}}

function closeDrawer() {{
  document.getElementById('drawer').classList.remove('open');
  document.querySelectorAll('.frow,.chain-node').forEach(el=>el.classList.remove('selected'));
  current = null;
}}

function exportHTML() {{
  const html = '<!DOCTYPE html>'+document.documentElement.outerHTML;
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([html],{{type:'text/html'}}));
  a.download = 'attack-chain-{_esc(engagement.engagement_id)}.html';
  document.body.appendChild(a); a.click();
  setTimeout(()=>{{URL.revokeObjectURL(a.href);a.remove()}},100);
}}

document.addEventListener('keydown', e=>{{ if(e.key==='Escape') closeDrawer(); }});

// Auto-select crown jewel on load
if (PRIMARY_CHAIN.length) sel(PRIMARY_CHAIN[PRIMARY_CHAIN.length-1]);
</script>
</body>
</html>"""


def render_to_file(
    engagement: Engagement,
    primary_chain: list[Finding],
    secondary_findings: list[Finding],
    chain_risk_score: float,
    output_path: str | Path,
) -> Path:
    html = render_html(engagement, primary_chain, secondary_findings, chain_risk_score)
    out = Path(output_path)
    out.write_text(html, encoding="utf-8")
    return out
