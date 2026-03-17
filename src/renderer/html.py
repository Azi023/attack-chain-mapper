"""Interactive HTML renderer — light-theme Pentera-style chain visualization.

Design: light bg (#f5f6f8), SVG chain panel, animated dashed connectors,
bottom detail drawer, dynamic layout from findings data.
Multi-chain: if multiple independent chains detected, shows a tab selector.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from src.ingestion.schema import Finding, Engagement


# ── Time helpers ─────────────────────────────────────────────────────────────

def fmt_time(seconds: int | None) -> str:
    if seconds is None:
        return ""
    if seconds < 60:
        return f"+{seconds}s"
    if seconds < 3600:
        return f"+{seconds // 60}m"
    h = seconds // 3600
    m = (seconds % 3600) // 60
    return f"+{h}h{m:02d}m" if m else f"+{h}h"


# ── Layout computation ────────────────────────────────────────────────────────

def _compute_primary_layout(
    primary_chain: list[Finding],
    all_findings: list[Finding],
) -> dict:
    """Return {finding_id: {row, col, total_cols}} for primary chain nodes.

    Row 0 = crown jewel (top of SVG), increasing rows go down to entry point.
    When multiple primary nodes share the same parent they are placed side by side.
    """
    if not primary_chain:
        return {}
    primary_ids = {f.id for f in primary_chain}
    fmap = {f.id: f for f in all_findings}
    crown_id = primary_chain[-1].id

    # BFS from crown to assign levels (0 = crown, max = entry)
    level: dict[str, int] = {crown_id: 0}
    queue = [crown_id]
    while queue:
        nid = queue.pop(0)
        node = fmap.get(nid)
        if not node:
            continue
        for pred_id in (node.enabled_by or []):
            if pred_id in primary_ids and pred_id not in level:
                level[pred_id] = level[nid] + 1
                queue.append(pred_id)

    rows_by_level: dict[int, list[str]] = {}
    for nid, lvl in level.items():
        rows_by_level.setdefault(lvl, []).append(nid)

    layout: dict[str, dict] = {}
    for lvl, nodes in rows_by_level.items():
        sorted_nodes = sorted(
            nodes,
            key=lambda nid: fmap[nid].severity if nid in fmap else 0,
            reverse=True,
        )
        for col_idx, nid in enumerate(sorted_nodes):
            layout[nid] = {"row": lvl, "col": col_idx, "total_cols": len(nodes)}
    return layout


def _compute_fork_labels(
    primary_chain: list[Finding],
    all_findings: list[Finding],
) -> dict[str, str]:
    """Return {finding_id: short_label} for findings that are fork branches.

    A fork branch is a primary node whose parent also enables another primary node.
    """
    primary_ids = {f.id for f in primary_chain}
    fmap = {f.id: f for f in all_findings}
    parent_children: dict[str, list[str]] = {}
    for f in primary_chain:
        for pred_id in (f.enabled_by or []):
            if pred_id in primary_ids:
                parent_children.setdefault(pred_id, []).append(f.id)
    flbl: dict[str, str] = {}
    for _, children in parent_children.items():
        if len(children) >= 2:
            for child_id in children:
                child = fmap.get(child_id)
                if child:
                    t = child.title
                    flbl[child_id] = t[:20] + ("\u2026" if len(t) > 20 else "")
    return flbl


# ── Findings serializer ───────────────────────────────────────────────────────

def _finding_to_js(
    f: Finding,
    primary_ids: set[str],
    crown_id: str,
    entry_id: str,
    fork_labels: dict[str, str],
    chain_idx: int = -1,
) -> dict:
    rem_list: list[str] = []
    if f.ai_remediation:
        for line in f.ai_remediation.splitlines():
            stripped = line.strip()
            if stripped:
                clean = re.sub(r"^\d+[\.\)]\s*", "", stripped)
                if clean:
                    rem_list.append(clean)
    conf = 0
    if f.ai_confidence is not None:
        conf = int(f.ai_confidence * 100)
    return {
        "id": f.id,
        "title": f.title,
        "s": round(f.severity, 1),
        "lbl": f.severity_label,
        "mitre": f.mitre_technique or "",
        "step": f.step_index,
        "time": fmt_time(f.timestamp_offset_s),
        "host": f.host or "",
        "ena": list(f.enabled_by or []),
        "crown": f.id == crown_id,
        "entry": f.id == entry_id,
        "pri": f.id in primary_ids,
        "flbl": fork_labels.get(f.id, ""),
        "analysis": f.ai_detail or "",
        "rem": rem_list,
        "ev": f.evidence or "",
        "conf": conf,
        "chain_idx": chain_idx,
    }


# ── Public API ────────────────────────────────────────────────────────────────

def render_html(chain, engagement_title: str = "Pentest Engagement") -> str:
    """
    chain: object with .findings (list[Finding]), .primary_path (list[Finding]),
           .chain_risk_score (float), and optionally .chains (list[ChainResult])
    Returns: complete self-contained HTML string.
    """
    findings: list[Finding] = chain.findings
    primary_path: list[Finding] = chain.primary_path
    risk_score: float = chain.chain_risk_score

    chains_list = getattr(chain, "chains", [])

    # If no chains data available (backward compat), create a synthetic single-chain entry
    if not chains_list:
        from src.graph.pathfinder import ChainResult
        crown_id_bc = primary_path[-1].id if primary_path else ""
        entry_id_bc = primary_path[0].id if primary_path else ""
        chains_list = [ChainResult(
            chain_index=1,
            primary_path=[f.id for f in primary_path],
            crown_jewel_id=crown_id_bc,
            entry_point_id=entry_id_bc,
            secondary_findings=[],
            chain_risk_score=risk_score,
            component_size=len(primary_path),
            label="Chain 1",
        )]

    primary_ids = {f.id for f in primary_path}
    crown_id = primary_path[-1].id if primary_path else ""
    entry_id = primary_path[0].id if primary_path else ""

    # Map finding ID → chain index (0-based, -1 if not in any chain's primary path)
    finding_chain_idx: dict[str, int] = {}
    for cr in chains_list:
        for fid in cr.primary_path:
            finding_chain_idx[fid] = cr.chain_index - 1  # 0-based

    fmap = {f.id: f for f in findings}

    # Build per-chain layout and fork-label data
    chains_tab_data = []
    for cr in chains_list:
        chain_path_findings = [fmap[fid] for fid in cr.primary_path if fid in fmap]
        chain_layout = _compute_primary_layout(chain_path_findings, findings)
        fork_lbl = _compute_fork_labels(chain_path_findings, findings)
        chains_tab_data.append({
            "index": cr.chain_index,
            "label": cr.label,
            "risk": round(cr.chain_risk_score, 2),
            "steps": len(chain_path_findings),
            "primary_ids": cr.primary_path,
            "crown_id": cr.crown_jewel_id,
            "entry_id": cr.entry_point_id,
            "layout": chain_layout,
            "fork_labels": fork_lbl,
        })

    # Chain 1 layout for NODE_LAYOUT (backward-compat placeholder still injected)
    layout = chains_tab_data[0]["layout"] if chains_tab_data else {}
    fork_labels = chains_tab_data[0]["fork_labels"] if chains_tab_data else {}

    js_findings = [
        _finding_to_js(f, primary_ids, crown_id, entry_id, fork_labels,
                       finding_chain_idx.get(f.id, -1))
        for f in findings
    ]
    findings_json = json.dumps(js_findings, ensure_ascii=False)
    layout_json = json.dumps(layout, ensure_ascii=False)
    chains_json = json.dumps(chains_tab_data, ensure_ascii=False)
    risk_str = f"{risk_score:.2f}"
    primary_len = str(len(primary_path))

    if " \u2014 " in engagement_title:
        parts = engagement_title.split(" \u2014 ", 1)
        hdr_title = parts[0]
        hdr_sub = parts[1]
    else:
        hdr_title = engagement_title
        hdr_sub = "Attack Chain"

    def esc(s: str) -> str:
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    html = _TEMPLATE
    html = html.replace("__HDR_TITLE__", esc(hdr_title))
    html = html.replace("__HDR_SUB__", esc(hdr_sub))
    html = html.replace("__RISK_STR__", risk_str)
    html = html.replace("__PRIMARY_LEN__", primary_len)
    html = html.replace("__FINDINGS_JSON__", findings_json)
    html = html.replace("__LAYOUT_JSON__", layout_json)
    html = html.replace("__CHAINS_JSON__", chains_json)
    return html


def render_to_file(
    engagement: Engagement,
    primary_chain: list[Finding],
    secondary_findings: list[Finding],
    chain_risk_score: float,
    output_path: str | Path,
) -> Path:
    """Backward-compatible wrapper: accepts old 5-arg signature, calls render_html."""
    from src.graph.pathfinder import ChainResult

    crown_id = primary_chain[-1].id if primary_chain else ""
    entry_id = primary_chain[0].id if primary_chain else ""

    syn_chain = ChainResult(
        chain_index=1,
        primary_path=[f.id for f in primary_chain],
        crown_jewel_id=crown_id,
        entry_point_id=entry_id,
        secondary_findings=[f.id for f in secondary_findings],
        chain_risk_score=chain_risk_score,
        component_size=len(primary_chain),
        label="Chain 1",
    )

    class _ChainAdapter:
        pass

    adapter = _ChainAdapter()
    adapter.findings = engagement.findings
    adapter.primary_path = primary_chain
    adapter.chain_risk_score = chain_risk_score
    adapter.chains = [syn_chain]

    title = engagement.target_name or engagement.engagement_id
    html = render_html(adapter, engagement_title=title)
    out = Path(output_path)
    out.write_text(html, encoding="utf-8")
    return out


# ── HTML template (token-replaced, no f-string escaping needed) ───────────────

_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Attack Chain &mdash; __HDR_TITLE__</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#f5f6f8;
  --surface:#ffffff;
  --surface2:#f9fafb;
  --border:#e4e7ec;
  --border2:#d0d5dd;
  --text:#101828;
  --text2:#344054;
  --muted:#667085;
  --dim:#98a2b3;
  --crit:#d92d20;
  --high:#c4320a;
  --med:#b54708;
  --low:#667085;
  --info:#98a2b3;
  --crit-bg:#fff1f0;
  --high-bg:#fff4ed;
  --med-bg:#fffaeb;
  --low-bg:#f2f4f7;
  --info-bg:#f2f4f7;
  --blue:#1d4ed8;
  --blue-bg:#eff6ff;
  --font:-apple-system,BlinkMacSystemFont,'Segoe UI','Inter',sans-serif;
  --mono:'JetBrains Mono','Cascadia Code','Fira Code',Consolas,monospace;
}
html,body{height:100%;background:var(--bg);color:var(--text);font-family:var(--font);font-size:12px;overflow:hidden;line-height:1.5}

/* HEADER */
#hdr{position:fixed;top:0;left:0;right:0;height:48px;background:var(--surface);border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;padding:0 20px;z-index:50;box-shadow:0 1px 3px rgba(0,0,0,0.06)}
.hdr-l{display:flex;align-items:center;gap:10px}
.dot{width:8px;height:8px;border-radius:50%;background:var(--crit);flex-shrink:0}
.hdr-title{font-size:13px;font-weight:600;color:var(--text)}
.hdr-sep{color:var(--border2);font-size:14px}
.hdr-sub{font-size:12px;color:var(--muted)}
.hdr-r{display:flex;align-items:center;gap:14px}
.risk-lbl{font-size:11px;color:var(--muted)}
.risk-val{font-size:18px;font-weight:700;color:var(--crit)}
.exp-btn{font-family:var(--font);font-size:11px;background:var(--surface);border:1px solid var(--border2);color:var(--text2);padding:5px 12px;border-radius:6px;cursor:pointer;font-weight:500;transition:all 0.12s}
.exp-btn:hover{border-color:var(--blue);color:var(--blue);background:var(--blue-bg)}

/* BODY */
#body{position:fixed;top:48px;left:0;right:0;bottom:0;display:flex;overflow:hidden}

/* LEFT */
#left{width:256px;flex-shrink:0;border-right:1px solid var(--border);overflow-y:auto;background:var(--surface)}
#left::-webkit-scrollbar{width:4px}
#left::-webkit-scrollbar-thumb{background:var(--border2);border-radius:2px}
.lhdr{padding:12px 16px 8px;font-size:10px;text-transform:uppercase;letter-spacing:0.08em;color:var(--muted);font-weight:600}
.frow{display:flex;align-items:stretch;cursor:pointer;border-bottom:1px solid var(--border);transition:background 0.1s;position:relative}
.frow:hover{background:#fafafa}
.frow.active{background:var(--blue-bg)}
.frow.active::before{content:'';position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--blue)}
.fbar{width:3px;flex-shrink:0}
.fscore{font-size:15px;font-weight:700;width:38px;flex-shrink:0;display:flex;align-items:center;justify-content:center;padding:0 2px}
.finfo{flex:1;min-width:0;padding:9px 10px 9px 4px}
.ftitle{font-size:11px;font-weight:500;color:var(--text);display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;margin-bottom:5px;line-height:1.4}
.fbadges{display:flex;gap:4px;flex-wrap:wrap}
.bsev{padding:1px 6px;border-radius:3px;font-size:9px;font-weight:700;color:#fff;text-transform:uppercase;letter-spacing:0.03em}
.bmitre{padding:1px 6px;border-radius:3px;font-size:9px;color:var(--muted);border:1px solid var(--border2);background:transparent;font-family:var(--mono)}
.sdiv{padding:8px 16px;font-size:10px;text-transform:uppercase;letter-spacing:0.08em;color:var(--dim);background:var(--surface2);border-bottom:1px solid var(--border);font-weight:600}
.frow.dim .ftitle{color:var(--dim)}
.frow.dim .fscore{opacity:0.35}
.frow.dim .fbar{opacity:0.25}

/* RIGHT */
#right{flex:1;display:flex;flex-direction:column;overflow:hidden;background:var(--bg)}
#right-inner{flex:1;overflow-y:auto;overflow-x:hidden;padding:20px 24px}
#right-inner::-webkit-scrollbar{width:4px}
#right-inner::-webkit-scrollbar-thumb{background:var(--border2);border-radius:2px}
#chain-hdr{font-size:10px;text-transform:uppercase;letter-spacing:0.08em;color:var(--muted);font-weight:600;margin-bottom:16px}
#chain-svg{width:100%;display:block}

/* CHAIN TABS */
#chain-tabs{display:none;gap:0;border-bottom:1px solid var(--border);background:var(--surface);overflow-x:auto;flex-shrink:0}
.chain-tab{padding:8px 16px;font-size:11px;font-weight:500;cursor:pointer;border-right:1px solid var(--border);white-space:nowrap;color:var(--muted);transition:all 0.12s}
.chain-tab:hover{background:var(--bg);color:var(--text)}
.chain-tab.active{background:var(--bg);color:var(--text);border-bottom:2px solid var(--blue)}
.chain-tab .tab-score{color:var(--crit);font-weight:700;margin-left:4px}
.cbadge{padding:1px 5px;border-radius:3px;font-size:9px;font-weight:700;color:var(--blue);border:1px solid var(--blue-bg);background:var(--blue-bg);margin-left:4px;flex-shrink:0}

/* SVG node interactions */
.nrect{transition:stroke 0.15s,filter 0.15s}
.nrect.hi{stroke:var(--blue)!important;stroke-width:1.5!important;filter:drop-shadow(0 0 5px rgba(29,78,216,0.2))}
.ngrp{cursor:pointer}
@keyframes dflow{from{stroke-dashoffset:20}to{stroke-dashoffset:0}}
.conn{fill:none;stroke-width:1.2;stroke-dasharray:5 3;animation:dflow 1.2s linear infinite}

/* DRAWER */
#dov{position:fixed;inset:0;z-index:200;pointer-events:none}
#drw{position:absolute;bottom:0;left:0;right:0;background:var(--surface);border-top:2px solid var(--border);transform:translateY(100%);transition:transform 0.22s cubic-bezier(0.4,0,0.2,1);pointer-events:all;overflow-y:auto;max-height:52vh;box-shadow:0 -4px 16px rgba(0,0,0,0.08)}
#drw.open{transform:translateY(0)}
#drw::-webkit-scrollbar{width:4px}
#drw::-webkit-scrollbar-thumb{background:var(--border2);border-radius:2px}
#dclose{position:absolute;top:12px;right:16px;width:26px;height:26px;display:flex;align-items:center;justify-content:center;background:var(--surface2);border:1px solid var(--border2);color:var(--muted);border-radius:5px;cursor:pointer;font-size:13px;z-index:1;transition:all 0.12s}
#dclose:hover{color:var(--text);border-color:var(--border2);background:var(--border)}
#dtop{display:flex;align-items:center;gap:8px;padding:14px 18px 8px;padding-right:48px}
.dsevbadge{padding:2px 8px;border-radius:3px;font-size:10px;font-weight:700;color:#fff;text-transform:uppercase;letter-spacing:0.03em;flex-shrink:0}
.dmitrelink{font-size:11px;color:var(--blue);text-decoration:none;font-family:var(--mono)}
.dmitrelink:hover{text-decoration:underline}
.dhost{margin-left:auto;font-size:10px;color:var(--muted);font-family:var(--mono);background:var(--surface2);border:1px solid var(--border);padding:2px 8px;border-radius:3px;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
#dtitle{font-size:14px;font-weight:600;color:var(--text);padding:0 18px 10px;line-height:1.3}
#dcols{display:grid;grid-template-columns:1fr 1fr;gap:20px;padding:0 18px 12px}
.dclbl{font-size:10px;text-transform:uppercase;letter-spacing:0.08em;color:var(--muted);margin-bottom:6px;font-weight:600}
.dctext{font-size:12px;color:var(--text2);line-height:1.65}
#drem{font-size:12px;color:var(--text2);line-height:1.7;padding-left:16px}
#drem li{margin-bottom:3px}
#devwrap{padding:0 18px 12px}
#devlbl{font-size:10px;text-transform:uppercase;letter-spacing:0.08em;color:var(--muted);margin-bottom:5px;font-weight:600}
#devcode{background:#0d1117;border:1px solid #30363d;border-radius:5px;padding:10px 12px;font-family:var(--mono);font-size:10px;color:#79c0ff;white-space:pre-wrap;word-break:break-all}
#confrow{display:flex;align-items:center;gap:10px;padding:0 18px 16px}
#conflbl{font-size:10px;text-transform:uppercase;letter-spacing:0.08em;color:var(--muted);white-space:nowrap;font-weight:600}
#confbg{flex:1;height:5px;background:var(--surface2);border-radius:3px;overflow:hidden;border:1px solid var(--border)}
#conffill{height:100%;background:#12b76a;border-radius:3px;transition:width 0.4s}
#confpct{font-size:11px;font-weight:600;color:#12b76a;white-space:nowrap}
</style>
</head>
<body>
<header id="hdr">
  <div class="hdr-l">
    <div class="dot"></div>
    <span class="hdr-title">__HDR_TITLE__</span>
    <span class="hdr-sep">&middot;</span>
    <span class="hdr-sub">__HDR_SUB__</span>
  </div>
  <div class="hdr-r">
    <span class="risk-lbl">Chain risk score</span>
    <span class="risk-val">__RISK_STR__</span>
    <button class="exp-btn" onclick="exportHTML()">&#8595; Export HTML</button>
  </div>
</header>
<div id="body">
  <div id="left"></div>
  <div id="right">
    <div id="chain-tabs"></div>
    <div id="right-inner">
      <div id="chain-hdr">Primary Attack Chain &mdash; __PRIMARY_LEN__ Steps</div>
      <svg id="chain-svg" xmlns="http://www.w3.org/2000/svg">
        <defs id="chain-defs">
          <marker id="arr-CRITICAL" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="5" markerHeight="5" orient="auto"><polygon points="0,0 8,4 0,8" fill="#d92d20"/></marker>
          <marker id="arr-HIGH" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="5" markerHeight="5" orient="auto"><polygon points="0,0 8,4 0,8" fill="#c4320a"/></marker>
          <marker id="arr-MEDIUM" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="5" markerHeight="5" orient="auto"><polygon points="0,0 8,4 0,8" fill="#b54708"/></marker>
          <marker id="arr-LOW" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="5" markerHeight="5" orient="auto"><polygon points="0,0 8,4 0,8" fill="#667085"/></marker>
          <marker id="arr-INFO" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="5" markerHeight="5" orient="auto"><polygon points="0,0 8,4 0,8" fill="#98a2b3"/></marker>
        </defs>
      </svg>
    </div>
  </div>
</div>
<div id="dov">
  <div id="drw">
    <div id="dclose" onclick="closeDrawer()">&#x2715;</div>
    <div id="dtop">
      <span class="dsevbadge" id="d-sev"></span>
      <a class="dmitrelink" id="d-mitre" href="#" target="_blank" rel="noopener"></a>
      <span class="dhost" id="d-host"></span>
    </div>
    <div id="dtitle"></div>
    <div id="dcols">
      <div><div class="dclbl">AI Analysis</div><div class="dctext" id="d-analysis"></div></div>
      <div><div class="dclbl">Remediation</div><ol id="drem"></ol></div>
    </div>
    <div id="devwrap">
      <div id="devlbl">Evidence</div>
      <div id="devcode"></div>
    </div>
    <div id="confrow">
      <span id="conflbl">AI Confidence</span>
      <div id="confbg"><div id="conffill"></div></div>
      <span id="confpct"></span>
    </div>
  </div>
</div>
<script>
const SEV={
  CRITICAL:{color:'#d92d20',bg:'#fff1f0',border:'#fda29b'},
  HIGH:    {color:'#c4320a',bg:'#fff4ed',border:'#f9dbaf'},
  MEDIUM:  {color:'#b54708',bg:'#fffaeb',border:'#fedf89'},
  LOW:     {color:'#667085',bg:'#f2f4f7',border:'#d0d5dd'},
  INFO:    {color:'#98a2b3',bg:'#f9fafb',border:'#e4e7ec'}
};
const F=__FINDINGS_JSON__;
const NODE_LAYOUT=__LAYOUT_JSON__;
const CHAINS=__CHAINS_JSON__;
const FM={};F.forEach(f=>FM[f.id]=f);
let AID=null;
let ACTIVE_CHAIN=0;
let ACTIVE_PRIMARY_IDS=new Set(CHAINS.length>0?CHAINS[0].primary_ids:[]);
const sc=(l)=>SEV[l]?.color||'#667085';
const fmt=(s)=>s===0?'0.0':s.toFixed(1);

function buildTabs(){
  const el=document.getElementById('chain-tabs');
  if(!el||CHAINS.length<2){if(el)el.style.display='none';return;}
  el.style.display='flex';el.innerHTML='';
  CHAINS.forEach((c,i)=>{
    const t=document.createElement('div');t.className='chain-tab'+(i===0?' active':'');
    t.onclick=()=>switchChain(i);
    const score=document.createElement('span');score.className='tab-score';score.textContent=c.risk.toFixed(2);
    t.textContent='Chain '+c.index+' ';t.appendChild(score);
    el.appendChild(t);
  });
}

function switchChain(idx){
  ACTIVE_CHAIN=idx;
  ACTIVE_PRIMARY_IDS=new Set(CHAINS[idx].primary_ids);
  document.querySelectorAll('.chain-tab').forEach((t,i)=>t.classList.toggle('active',i===idx));
  const c=CHAINS[idx];
  document.getElementById('chain-hdr').textContent=c.label+' \u2014 '+c.steps+' Steps';
  closeDrawer();
  buildSVG();
}

function buildLeft(){
  const p=document.getElementById('left');p.innerHTML='';
  if(CHAINS.length>1){
    const h=document.createElement('div');h.className='lhdr';h.textContent='All Findings ('+F.length+')';p.appendChild(h);
    const inAnyChain=F.filter(f=>f.chain_idx>=0).sort((a,b)=>a.chain_idx-b.chain_idx||b.s-a.s);
    inAnyChain.forEach(f=>p.appendChild(mkRow(f,false,f.chain_idx+1)));
    const isolated=F.filter(f=>f.chain_idx<0);
    if(isolated.length){
      const d=document.createElement('div');d.className='sdiv';d.textContent='Not in Any Chain';p.appendChild(d);
      isolated.forEach(f=>p.appendChild(mkRow(f,true,null)));
    }
  } else {
    const h=document.createElement('div');h.className='lhdr';h.textContent='All Findings ('+F.filter(x=>x.pri).length+')';p.appendChild(h);
    F.filter(f=>f.pri).forEach(f=>p.appendChild(mkRow(f,false,null)));
    const sec=F.filter(f=>!f.pri);
    if(sec.length){
      const d=document.createElement('div');d.className='sdiv';d.textContent='Not in Primary Chain';p.appendChild(d);
      sec.forEach(f=>p.appendChild(mkRow(f,true,null)));
    }
  }
}
function mkRow(f,dim,chainNum){
  const r=document.createElement('div');r.className='frow'+(dim?' dim':'');r.id='row-'+f.id;r.onclick=()=>sel(f.id);
  const bar=document.createElement('div');bar.className='fbar';bar.style.background=sc(f.lbl);
  const score=document.createElement('div');score.className='fscore';score.style.color=sc(f.lbl);score.textContent=fmt(f.s);
  const info=document.createElement('div');info.className='finfo';
  const title=document.createElement('div');title.className='ftitle';title.textContent=f.title;
  const badges=document.createElement('div');badges.className='fbadges';
  const bs=document.createElement('span');bs.className='bsev';bs.style.background=sc(f.lbl);bs.textContent=f.lbl;
  badges.appendChild(bs);
  if(f.mitre){const bm=document.createElement('span');bm.className='bmitre';bm.textContent=f.mitre;badges.appendChild(bm);}
  if(chainNum!=null){const bc=document.createElement('span');bc.className='cbadge';bc.textContent='C'+chainNum;badges.appendChild(bc);}
  info.appendChild(title);info.appendChild(badges);
  r.appendChild(bar);r.appendChild(score);r.appendChild(info);return r;
}
function sel(id){
  if(AID){const or=document.getElementById('row-'+AID);if(or)or.classList.remove('active');const on=document.getElementById('nr-'+AID);if(on)on.classList.remove('hi');}
  AID=id;
  const row=document.getElementById('row-'+id);if(row)row.classList.add('active');
  const nr=document.getElementById('nr-'+id);if(nr)nr.classList.add('hi');
  openDrawer(FM[id]);
}
function openDrawer(f){
  const sv=SEV[f.lbl]||SEV.INFO;
  const sb=document.getElementById('d-sev');sb.textContent=f.lbl;sb.style.background=sv.color;
  const ml=document.getElementById('d-mitre');
  if(f.mitre){ml.textContent='\u2197 '+f.mitre;ml.href='https://attack.mitre.org/techniques/'+f.mitre.replace('.','/');ml.style.display='';}
  else{ml.style.display='none';}
  const he=document.getElementById('d-host');he.textContent=f.host||'';he.style.display=f.host?'':'none';
  document.getElementById('dtitle').textContent=f.title;
  document.getElementById('d-analysis').textContent=f.analysis||'No AI analysis available.';
  const re=document.getElementById('drem');re.innerHTML='';
  (f.rem&&f.rem.length?f.rem:['See security advisory.']).forEach(r=>{const li=document.createElement('li');li.textContent=r;re.appendChild(li);});
  const evw=document.getElementById('devwrap');
  if(f.ev){document.getElementById('devcode').textContent=f.ev;evw.style.display='';}
  else{evw.style.display='none';}
  const pct=f.conf||0;document.getElementById('conffill').style.width=pct+'%';document.getElementById('confpct').textContent=pct+'%';
  document.getElementById('confrow').style.display=pct?'':'none';
  document.getElementById('drw').classList.add('open');
}
function closeDrawer(){
  document.getElementById('drw').classList.remove('open');
  if(AID){const or=document.getElementById('row-'+AID);if(or)or.classList.remove('active');const on=document.getElementById('nr-'+AID);if(on)on.classList.remove('hi');}AID=null;
}

function svgE(t){return document.createElementNS('http://www.w3.org/2000/svg',t)}

function buildSVG(){
  const wrap=document.getElementById('right-inner');
  const W=(wrap.clientWidth-48)||700;
  const svg=document.getElementById('chain-svg');
  svg.innerHTML='';

  // Use active chain's layout (falls back to NODE_LAYOUT for backward compat)
  const activeLayout=CHAINS.length>0?CHAINS[ACTIVE_CHAIN].layout:NODE_LAYOUT;
  const activeCrownId=CHAINS.length>0?CHAINS[ACTIVE_CHAIN].crown_id:'';
  const activeEntryId=CHAINS.length>0?CHAINS[ACTIVE_CHAIN].entry_id:'';

  const PX=16,CW=W-PX*2,NH=64,VG=52,RS=NH+VG,HG=12,TP=8;

  // Build L from active chain layout
  const L={};
  const maxRow=Object.values(activeLayout).reduce((m,n)=>Math.max(m,n.row),0);
  Object.entries(activeLayout).forEach(([id,nl])=>{
    const tc=nl.total_cols;
    const y=TP+nl.row*RS;
    const w=tc===1?CW:(CW-(tc-1)*HG)/tc;
    const x=PX+nl.col*(w+HG);
    L[id]={x,y,w,h:NH};
  });

  const TLY=TP+(maxRow+1)*RS+10;
  const SVG_H=TLY+58;
  svg.setAttribute('viewBox','0 0 '+W+' '+SVG_H);
  svg.setAttribute('height',SVG_H);

  // Preserve static defs (arrowhead markers arr-CRITICAL etc. already in HTML)
  const existingDefs=document.getElementById('chain-defs');
  if(existingDefs)svg.appendChild(existingDefs.cloneNode(true));

  // CONNECTORS — drawn before nodes so nodes render on top
  const cg=svgE('g');svg.appendChild(cg);

  function cn(id){const n=L[id];return{cx:n.x+n.w/2,top:n.y,bot:n.y+n.h}}

  function drawConn(x1,y1,x2,y2,sev,label){
    const col=SEV[sev]?.color||'#667085';
    const midY=(y1+y2)/2;
    const path=svgE('path');
    const d=(Math.abs(x1-x2)<4)
      ?('M'+x1+' '+y1+' L'+x2+' '+y2)
      :('M'+x1+' '+y1+' C'+x1+' '+midY+' '+x2+' '+midY+' '+x2+' '+y2);
    path.setAttribute('d',d);
    path.setAttribute('class','conn');
    path.setAttribute('stroke',col);
    path.setAttribute('stroke-opacity','0.6');
    path.setAttribute('marker-end','url(#arr-'+sev+')');
    cg.appendChild(path);
    if(label){
      const lx=(x1+x2)/2,ly=midY-5;
      const t=svgE('text');
      t.setAttribute('x',lx);t.setAttribute('y',ly);
      t.setAttribute('fill','#98a2b3');t.setAttribute('font-size','9');
      t.setAttribute('font-style','italic');t.setAttribute('text-anchor','middle');
      t.setAttribute('font-family',"-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif");
      t.textContent=label;cg.appendChild(t);
    }
  }

  // Get fork_labels for active chain
  const activeForkLabels=(CHAINS.length>0&&CHAINS[ACTIVE_CHAIN].fork_labels)||{};

  // Dynamic connectors: for each active primary finding, draw arrow FROM each primary parent TO it
  F.filter(f=>ACTIVE_PRIMARY_IDS.has(f.id)).forEach(f=>{
    (f.ena||[]).forEach(parentId=>{
      if(!L[parentId]||!L[f.id])return;
      const parent=cn(parentId);
      const child=cn(f.id);
      // parent is lower on screen (larger row), child is above (smaller row)
      drawConn(parent.cx,parent.top,child.cx,child.bot+2,FM[parentId].lbl,activeForkLabels[f.id]||null);
    });
  });

  // NODES
  const font="-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif";
  Object.keys(L).forEach(id=>{
    const f=FM[id],nl=L[id];if(!f||!nl)return;
    const isCrown=f.id===activeCrownId;
    const isEntry=f.id===activeEntryId;
    const sv=SEV[f.lbl]||SEV.INFO,col=sv.color;
    const g=svgE('g');g.className='ngrp';g.addEventListener('click',()=>sel(f.id));

    // Shadow
    const sh=svgE('rect');
    sh.setAttribute('x',nl.x+1);sh.setAttribute('y',nl.y+2);
    sh.setAttribute('width',nl.w);sh.setAttribute('height',nl.h);
    sh.setAttribute('rx',5);sh.setAttribute('fill','rgba(0,0,0,0.04)');
    g.appendChild(sh);

    // Background
    const bg=svgE('rect');
    bg.setAttribute('x',nl.x);bg.setAttribute('y',nl.y);
    bg.setAttribute('width',nl.w);bg.setAttribute('height',nl.h);
    bg.setAttribute('rx',5);
    bg.setAttribute('fill',isCrown?sv.bg:'#ffffff');
    bg.setAttribute('stroke',isCrown?col:sv.border);
    bg.setAttribute('stroke-width',isCrown?'1.5':'1');
    bg.setAttribute('class','nrect');bg.id='nr-'+f.id;
    g.appendChild(bg);

    // Left color bar
    const bar=svgE('rect');
    bar.setAttribute('x',nl.x+1);bar.setAttribute('y',nl.y+1);
    bar.setAttribute('width',4);bar.setAttribute('height',nl.h-2);
    bar.setAttribute('rx',3);bar.setAttribute('fill',col);
    g.appendChild(bar);

    const TX=nl.x+16,R1=nl.y+22,R2=nl.y+46;

    // Severity score + label
    const st=svgE('text');
    st.setAttribute('x',TX);st.setAttribute('y',R1);
    st.setAttribute('fill',col);st.setAttribute('font-size','11');
    st.setAttribute('font-weight','700');st.setAttribute('font-family',font);
    st.textContent=fmt(f.s)+' '+f.lbl;
    g.appendChild(st);

    // MITRE + step meta
    const approxW=fmt(f.s).length*6.8+f.lbl.length*6.8+20;
    const mt=svgE('text');
    mt.setAttribute('x',TX+approxW);mt.setAttribute('y',R1);
    mt.setAttribute('fill','#98a2b3');mt.setAttribute('font-size','10');
    mt.setAttribute('font-family',"-apple-system,sans-serif");
    mt.textContent=(f.mitre?'\u00b7 '+f.mitre:'')+(f.step!=null?' \u00b7 Step '+f.step:'');
    g.appendChild(mt);

    // Timestamp (top-right)
    if(f.time){
      const tt=svgE('text');
      tt.setAttribute('x',nl.x+nl.w-10);tt.setAttribute('y',R1);
      tt.setAttribute('fill','#c4cdd6');tt.setAttribute('font-size','10');
      tt.setAttribute('text-anchor','end');tt.setAttribute('font-family',"-apple-system,sans-serif");
      tt.textContent=f.time;g.appendChild(tt);
    }

    // Title (truncated to fit)
    const maxC=Math.floor((nl.w-52)/6.5);
    let tstr=f.title;if(tstr.length>maxC)tstr=tstr.substring(0,maxC-1)+'\u2026';
    const titT=svgE('text');
    titT.setAttribute('x',TX);titT.setAttribute('y',R2);
    titT.setAttribute('fill','#101828');titT.setAttribute('font-size','12');
    titT.setAttribute('font-weight','600');titT.setAttribute('font-family',font);
    titT.textContent=tstr;g.appendChild(titT);

    // Crown jewel badge
    if(isCrown){
      const bW=102,bH=17,bX=nl.x+nl.w-bW-10,bY=nl.y+7;
      const cbg=svgE('rect');
      cbg.setAttribute('x',bX);cbg.setAttribute('y',bY);
      cbg.setAttribute('width',bW);cbg.setAttribute('height',bH);
      cbg.setAttribute('rx',3);cbg.setAttribute('fill',sv.bg);
      cbg.setAttribute('stroke',sv.border);cbg.setAttribute('stroke-width','1');
      g.appendChild(cbg);
      const ct=svgE('text');
      ct.setAttribute('x',bX+bW/2);ct.setAttribute('y',bY+12);
      ct.setAttribute('fill',col);ct.setAttribute('font-size','9');ct.setAttribute('font-weight','700');
      ct.setAttribute('text-anchor','middle');ct.setAttribute('font-family',font);
      ct.textContent='\ud83d\udc51 CROWN JEWEL';g.appendChild(ct);
    }

    // Entry point badge
    if(isEntry){
      const bW=94,bH=17,bX=nl.x+nl.w-bW-10,bY=nl.y+7;
      const ebg=svgE('rect');
      ebg.setAttribute('x',bX);ebg.setAttribute('y',bY);
      ebg.setAttribute('width',bW);ebg.setAttribute('height',bH);
      ebg.setAttribute('rx',3);ebg.setAttribute('fill','#f2f4f7');
      ebg.setAttribute('stroke','#d0d5dd');ebg.setAttribute('stroke-width','1');
      g.appendChild(ebg);
      const et=svgE('text');
      et.setAttribute('x',bX+bW/2);et.setAttribute('y',bY+12);
      et.setAttribute('fill','#667085');et.setAttribute('font-size','9');et.setAttribute('font-weight','700');
      et.setAttribute('text-anchor','middle');et.setAttribute('font-family',font);
      et.textContent='\u26a1 ENTRY POINT';g.appendChild(et);
    }

    svg.appendChild(g);
  });

  // ATTACK TIMELINE axis
  const axY=TLY+18;
  const axl=svgE('line');
  axl.setAttribute('x1',PX+8);axl.setAttribute('y1',axY);
  axl.setAttribute('x2',PX+CW-8);axl.setAttribute('y2',axY);
  axl.setAttribute('stroke','#e4e7ec');axl.setAttribute('stroke-width','1.5');
  svg.appendChild(axl);

  const TI=F.filter(f=>ACTIVE_PRIMARY_IDS.has(f.id)&&(f.time||f.step!=null)).sort((a,b)=>(a.step||0)-(b.step||0));
  if(TI.length){
    const step=CW/(TI.length+1);
    TI.forEach((ti,i)=>{
      const x=PX+step*(i+1),col=sc(ti.lbl);
      const c=svgE('circle');
      c.setAttribute('cx',x);c.setAttribute('cy',axY);c.setAttribute('r',5);
      c.setAttribute('fill',col);c.setAttribute('stroke','#f5f6f8');c.setAttribute('stroke-width','2');
      svg.appendChild(c);
      if(ti.step!=null){
        const sl=svgE('text');
        sl.setAttribute('x',x);sl.setAttribute('y',axY-10);sl.setAttribute('fill','#98a2b3');
        sl.setAttribute('font-size','9');sl.setAttribute('text-anchor','middle');sl.setAttribute('font-family',font);
        sl.textContent='S'+ti.step;svg.appendChild(sl);
      }
      if(ti.time){
        const tl=svgE('text');
        tl.setAttribute('x',x);tl.setAttribute('y',axY+16);tl.setAttribute('fill','#c4cdd6');
        tl.setAttribute('font-size','9');tl.setAttribute('text-anchor','middle');tl.setAttribute('font-family',font);
        tl.textContent=ti.time;svg.appendChild(tl);
      }
    });
  }
  const atl=svgE('text');
  atl.setAttribute('x',PX+8);atl.setAttribute('y',axY+32);
  atl.setAttribute('fill','#d0d5dd');atl.setAttribute('font-size','9');atl.setAttribute('font-weight','700');
  atl.setAttribute('letter-spacing','0.1em');atl.setAttribute('font-family',font);
  atl.textContent='ATTACK TIMELINE';svg.appendChild(atl);
}

function exportHTML(){
  const blob=new Blob(['<!DOCTYPE html>\n'+document.documentElement.outerHTML],{type:'text/html'});
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='attack-chain.html';
  document.body.appendChild(a);a.click();document.body.removeChild(a);
}

function init(){
  buildLeft();
  buildTabs();
  // Set chain header text for active chain
  if(CHAINS.length>0){
    const c=CHAINS[0];
    document.getElementById('chain-hdr').textContent=
      (CHAINS.length>1?c.label:'Primary Attack Chain')+' \u2014 '+c.steps+' Steps';
  }
  requestAnimationFrame(()=>requestAnimationFrame(()=>{
    buildSVG();
    const crownId=CHAINS.length>0?CHAINS[0].crown_id:'';
    const crown=F.find(f=>f.id===crownId||f.crown);
    if(crown)setTimeout(()=>sel(crown.id),60);
  }));
}
window.addEventListener('load',init);
window.addEventListener('resize',()=>{buildSVG();if(AID){const n=document.getElementById('nr-'+AID);if(n)n.classList.add('hi');}});
</script>
</body>
</html>"""
