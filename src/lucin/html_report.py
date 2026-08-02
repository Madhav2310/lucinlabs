"""Generate interactive HTML security report.

Renders a self-contained, XSS-safe, light-themed report (paper canvas, ink
text, red reserved for critical/danger signal — matches the Lucin brand):
  - security-score card + severity stat grid (existing)
  - an interactive Agent Information-Flow Graph (AIFG) section, force-directed,
    with the lethal-trifecta path lit red (new)
  - collapsible finding cards, now carrying the proof-witness chain, the
    min-cut remediation, and MITRE ATLAS tags for trifecta findings (new)

The AIFG is built from ``result.agents`` via the static ``build_aifg`` adapter
in ``aifg.py``; the trifecta reachability query + min vertex cut are the same
graph algorithms the AG-TRIFECTA detector uses. Graph data is embedded as JSON
inside ``<script type="application/json">`` and read with ``JSON.parse`` — never
``innerHTML``/``eval``. The graph library is a hand-rolled canvas force
simulation, vendored inline, so the report opens fully offline (no CDN). The
graph canvas keeps a dark "instrument screen" plate — the one deliberate
inversion on an otherwise paper-and-ink report.

If the AIFG cannot be built (no agents parsed / adapter raises), the graph
section degrades to empty and the findings-only report renders — the reporter
never crashes. The reporter is a pure function ``ScanResult -> str`` (no I/O).
"""

import html
import json
from datetime import datetime

from lucin.models import ScanResult, Severity
from lucin.scoring import calculate_security_score, score_label


# MITRE ATLAS technique tags for finding types that have a clear mapping.
# "if available" — findings without a mapping simply omit the tag.
_ATLAS_MAP = {
    "AG-TRIFECTA": "AML.T0051 (Prompt Injection) / AML.T0056 (LLM Data Leakage)",
    "AG-COMP": "AML.T0051 (Prompt Injection) / AML.T0056 (LLM Data Leakage)",
    "AG-002": "AML.T0056 (LLM Data Leakage)",
    "AG-013": "AML.T0051 (Prompt Injection)",
    "AG-011": "AML.T0057 (LLM Plugin Compromise)",
    "AG-007": "AML.T0056 (LLM Data Leakage)",
    "AG-017": "AML.T0056 (LLM Data Leakage)",
    "AG-027": "AML.T0056 (LLM Data Leakage)",
}


def generate_html_report(result: ScanResult) -> str:
    """Generate a standalone HTML report with all findings + the AIFG graph."""
    score = calculate_security_score(result)
    label = score_label(score)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Build the interactive graph section first — it yields the per-agent
    # min-cut sets used to enrich trifecta finding cards. Degrades gracefully.
    graph_section, mincut_by_agent = _build_graph_section(result)

    findings_html = ""
    if result.findings:
        findings_html = '<h2 class="section-title">Findings</h2>\n'
        for finding in sorted(result.findings, key=lambda f: list(Severity).index(f.severity)):
            findings_html += _render_finding(finding, finding.severity.value, mincut_by_agent)

    return HTML_TEMPLATE.format(
        target=html.escape(result.target),
        timestamp=timestamp,
        score=score,
        score_label=label,
        score_color=_score_hex(score),
        agent_count=len(result.agents),
        tool_count=sum(len(a.tools) for a in result.agents),
        finding_count=len(result.findings),
        critical_count=result.critical_count,
        high_count=result.high_count,
        medium_count=result.medium_count,
        low_count=result.low_count,
        graph_section=graph_section,
        findings=findings_html,
        scan_ms=f"{result.scan_duration_ms:.0f}",
    )


def _render_witness(witness: list[str]) -> str:
    """Render a proof-witness chain (list of 'label: a -> b -> c' lines) as a
    highlighted arrow chain. Every token is HTML-escaped."""
    if not witness:
        return ""
    rows = ""
    for line in witness:
        line = str(line)
        if ":" in line:
            label, _, chain = line.partition(":")
        else:
            label, chain = "", line
        tokens = [t.strip() for t in chain.replace("->", "→").split("→") if t.strip()]
        chips = '<span class="wit-arrow">→</span>'.join(
            f'<span class="wit-node">{html.escape(t)}</span>' for t in tokens
        )
        label_html = (
            f'<span class="wit-label">{html.escape(label.strip())}</span>' if label.strip() else ""
        )
        rows += f'<div class="wit-row">{label_html}{chips}</div>'
    return f'<div class="witness"><strong>Proof-witness path:</strong>{rows}</div>'


def _render_finding(finding, severity_class: str, mincut_by_agent: dict) -> str:
    """Render a single finding as HTML."""
    desc = html.escape(finding.description).replace("\n", "<br>")
    attack = html.escape(finding.attack_scenario).replace("\n", "<br>") if finding.attack_scenario else ""
    fix = html.escape(finding.fix_suggestion).replace("\n", "<br>") if finding.fix_suggestion else ""

    witness_html = _render_witness(getattr(finding, "witness", []) or [])

    # Min-cut remediation for trifecta findings (matched by agent name).
    mincut_html = ""
    cut = mincut_by_agent.get(finding.agent_name) if finding.agent_name else None
    if finding.id == "AG-TRIFECTA" and cut:
        chips = "".join(f'<span class="cut-tool">{html.escape(t)}</span>' for t in cut)
        mincut_html = (
            f'<div class="mincut"><strong>Min-cut fix:</strong> restrict these '
            f'{len(cut)} tool(s) to provably break all exfiltration paths: {chips}</div>'
        )

    atlas = _ATLAS_MAP.get(finding.id, "")
    refs_html = ""
    if finding.owasp_ref or atlas:
        parts = []
        if finding.owasp_ref:
            parts.append('<span class="ref owasp">OWASP: ' + html.escape(finding.owasp_ref) + "</span>")
        if atlas:
            parts.append('<span class="ref atlas">MITRE ATLAS: ' + html.escape(atlas) + "</span>")
        refs_html = '<p class="refs">' + " ".join(parts) + "</p>"

    return f"""
    <details class="finding {severity_class}" open>
      <summary>
        <span class="badge {severity_class}">{finding.severity.value.upper()}</span>
        <span class="finding-title">{html.escape(finding.title)}</span>
        <span class="finding-id">{html.escape(finding.id)}</span>
      </summary>
      <div class="finding-body">
        {'<p><strong>Agent:</strong> ' + html.escape(finding.agent_name) + '</p>' if finding.agent_name else ''}
        {'<p><strong>Tool:</strong> ' + html.escape(finding.tool_name) + '</p>' if finding.tool_name else ''}
        <p class="description">{desc}</p>
        {witness_html}
        {'<div class="attack"><strong>Attack Scenario:</strong><br>' + attack + '</div>' if attack else ''}
        {'<p><strong>Blast Radius:</strong> ' + html.escape(finding.blast_radius) + '</p>' if finding.blast_radius else ''}
        {refs_html}
        {mincut_html}
        {'<div class="fix"><strong>Fix:</strong><br>' + fix + '</div>' if fix else ''}
        {'<p class="location"><strong>Location:</strong> ' + html.escape(finding.source_file) + (':' + str(finding.source_line) if finding.source_line else '') + '</p>' if finding.source_file else ''}
      </div>
    </details>
    """


def _score_hex(score: int) -> str:
    """Get hex color for score. Green→ink scale reserves red for real danger."""
    if score >= 90: return "#1F7A4D"
    elif score >= 70: return "#4B7A2B"
    elif score >= 50: return "#B8860B"
    elif score >= 25: return "#B85C1F"
    else: return "#D6321F"


# ---------------------------------------------------------------------------
# AIFG graph section
# ---------------------------------------------------------------------------

def _build_graph_section(result: ScanResult) -> tuple[str, dict]:
    """Build the interactive AIFG section HTML + a {agent_name: [cut tools]} map.

    Degrades gracefully: any failure (no agents, adapter raises) returns
    ("", {}) so the caller renders a findings-only report. Never raises.
    """
    try:
        from lucin.aifg import build_aifg, query_trifecta, min_tool_cut

        merged_nodes: list[dict] = []
        merged_edges: list[dict] = []
        mincut_by_agent: dict[str, list[str]] = {}

        for idx, agent in enumerate(result.agents):
            g = build_aifg(agent)
            tf_list = query_trifecta(g)

            red_nodes: set[str] = set()
            red_edges: set[tuple[str, str, str]] = set()
            for tf in tf_list:
                for path, kind in ((tf.control_path, "control"), (tf.data_path, "data")):
                    red_nodes.update(path)
                    for i in range(len(path) - 1):
                        red_edges.add((path[i], path[i + 1], kind))

            if tf_list:
                untrusted_ctrl = [
                    nid for nid, n in g.nodes.items()
                    if n.label.is_untrusted() and not n.is_llm
                ]
                egress_sinks = [nid for nid, n in g.nodes.items() if n.is_egress]
                cut = min_tool_cut(g, untrusted_ctrl, egress_sinks, {t.name for t in agent.tools})
                if cut:
                    mincut_by_agent[agent.name] = sorted(cut)

            prefix = f"a{idx}:"
            for n in g.nodes.values():
                loc = ""
                if n.tool is not None and n.tool.source_file:
                    loc = n.tool.source_file
                    if n.tool.source_line:
                        loc += f":{n.tool.source_line}"
                merged_nodes.append({
                    "id": prefix + n.node_id,
                    "name": n.node_id,
                    "agent": agent.name,
                    "integrity": n.label.integrity.name,
                    "confidentiality": n.label.confidentiality.name,
                    "is_source": n.is_source,
                    "is_sink": n.is_sink,
                    "is_egress": n.is_egress,
                    "is_untrusted_input": n.is_untrusted_input,
                    "is_llm": n.is_llm,
                    "trifecta": n.node_id in red_nodes,
                    "loc": loc,
                })
            for e in g.edges:
                merged_edges.append({
                    "src": prefix + e.src,
                    "dst": prefix + e.dst,
                    "kind": e.kind,
                    "trifecta": (e.src, e.dst, e.kind) in red_edges,
                })

        if not merged_nodes:
            return "", {}

        # Embed as JSON. Escape "<" so a tool name containing "</script>" or any
        # markup cannot break out of the <script type="application/json"> island.
        # json.dumps defaults to ensure_ascii=True, so U+2028/U+2029 (which break
        # inline scripts) are already escaped; we only neutralize "<".
        blob = json.dumps({"nodes": merged_nodes, "edges": merged_edges}).replace("<", "\\u003c")

        has_trifecta = any(n["trifecta"] for n in merged_nodes)
        note = (
            "Lethal-trifecta exfiltration path(s) highlighted in red."
            if has_trifecta else
            "No trifecta exfiltration path found. Sources, sinks and the LLM join node shown."
        )
        section = _GRAPH_SECTION.replace("__AIFG_NOTE__", html.escape(note)).replace("__AIFG_JSON__", blob)
        return section, mincut_by_agent
    except Exception:
        # Anti-slop: precision brand — degrade, never crash the reporter.
        return "", {}


# The graph section is inserted as a *value* into HTML_TEMPLATE.format(), so the
# many "{" braces in the inline JS below are literal and safe (str.format only
# processes the template's own braces, not substituted values).
_GRAPH_SECTION = """
  <h2 class="section-title">Agent Information-Flow Graph</h2>
  <p class="section-note">__AIFG_NOTE__ Click a node to inspect its IFC labels and location. Scroll to zoom, drag to pan.</p>
  <div class="aifg-shell">
    <div class="aifg-canvas-wrap">
      <canvas id="aifg-canvas"></canvas>
    </div>
    <div id="aifg-panel" class="aifg-panel">Click a node to inspect it.</div>
  </div>
  <div class="aifg-legend">
    <span class="lg"><span class="sw circle amber"></span>Untrusted input</span>
    <span class="lg"><span class="sw circle teal"></span>Data source</span>
    <span class="lg"><span class="sw diamond blue"></span>LLM</span>
    <span class="lg"><span class="sw square purple"></span>Egress sink</span>
    <span class="lg"><span class="sw square grey"></span>Tool</span>
    <span class="lg"><span class="sw ring red"></span>Trifecta path</span>
  </div>
  <script id="aifg-data" type="application/json">__AIFG_JSON__</script>
  <script>
  (function () {
    var data = JSON.parse(document.getElementById('aifg-data').textContent);
    var nodes = data.nodes || [];
    var links = data.edges || [];
    if (!nodes.length) { return; }
    var byId = {};
    nodes.forEach(function (n, i) {
      byId[n.id] = n;
      var ang = (i / nodes.length) * Math.PI * 2;
      n.x = Math.cos(ang) * 120 + (Math.random() - 0.5) * 40;
      n.y = Math.sin(ang) * 120 + (Math.random() - 0.5) * 40;
      n.vx = 0; n.vy = 0;
    });
    var edges = [];
    links.forEach(function (e) {
      if (byId[e.src] && byId[e.dst]) { edges.push(e); }
    });

    var canvas = document.getElementById('aifg-canvas');
    var ctx = canvas.getContext('2d');
    var panel = document.getElementById('aifg-panel');
    var dpr = window.devicePixelRatio || 1;
    var W = 0, H = 0;
    var view = { tx: 0, ty: 0, scale: 1 };
    var selected = null;
    var dragNode = null, panning = false, lastX = 0, lastY = 0;

    function resize() {
      W = canvas.clientWidth; H = canvas.clientHeight || 440;
      canvas.width = W * dpr; canvas.height = H * dpr;
    }
    window.addEventListener('resize', resize);
    resize();

    function nodeColor(n) {
      if (n.is_llm) return '#5B8CFF';
      if (n.is_untrusted_input) return '#E8A33D';
      if (n.is_egress || n.is_sink) return '#C77DFF';
      if (n.is_source) return '#2FBF9E';
      return '#8A8F98';
    }
    // shape: 0 = circle (sources/llm-input), 1 = square (tool/sink), 2 = diamond (llm)
    function nodeShape(n) {
      if (n.is_llm) return 2;
      if (n.is_egress || n.is_sink) return 1;
      if (n.is_source || n.is_untrusted_input) return 0;
      return 1;
    }

    function physics() {
      var i, j, a, b, dx, dy, d2, d, f;
      for (i = 0; i < nodes.length; i++) {
        a = nodes[i];
        a.fx = 0; a.fy = 0;
      }
      // repulsion
      for (i = 0; i < nodes.length; i++) {
        a = nodes[i];
        for (j = i + 1; j < nodes.length; j++) {
          b = nodes[j];
          dx = a.x - b.x; dy = a.y - b.y;
          d2 = dx * dx + dy * dy + 0.01;
          f = 2600 / d2;
          d = Math.sqrt(d2);
          var ux = dx / d, uy = dy / d;
          a.fx += ux * f; a.fy += uy * f;
          b.fx -= ux * f; b.fy -= uy * f;
        }
      }
      // springs
      for (i = 0; i < edges.length; i++) {
        a = byId[edges[i].src]; b = byId[edges[i].dst];
        dx = b.x - a.x; dy = b.y - a.y;
        d = Math.sqrt(dx * dx + dy * dy) + 0.01;
        f = (d - 90) * 0.02;
        var vx = (dx / d) * f, vy = (dy / d) * f;
        a.fx += vx; a.fy += vy;
        b.fx -= vx; b.fy -= vy;
      }
      // centering + integrate
      for (i = 0; i < nodes.length; i++) {
        a = nodes[i];
        a.fx -= a.x * 0.008; a.fy -= a.y * 0.008;
        if (a === dragNode) { a.vx = 0; a.vy = 0; continue; }
        a.vx = (a.vx + a.fx) * 0.82;
        a.vy = (a.vy + a.fy) * 0.82;
        a.x += a.vx; a.y += a.vy;
      }
    }

    function toScreen(n) {
      return {
        x: W / 2 + view.tx + n.x * view.scale,
        y: H / 2 + view.ty + n.y * view.scale
      };
    }
    function toWorld(px, py) {
      return {
        x: (px - W / 2 - view.tx) / view.scale,
        y: (py - H / 2 - view.ty) / view.scale
      };
    }

    function draw(t) {
      var pulse = 0.5 + 0.5 * Math.sin(t / 350);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, W, H);
      // edges
      for (var i = 0; i < edges.length; i++) {
        var e = edges[i];
        var a = toScreen(byId[e.src]), b = toScreen(byId[e.dst]);
        ctx.beginPath();
        ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y);
        if (e.trifecta) {
          ctx.strokeStyle = 'rgba(214,50,31,' + (0.6 + 0.4 * pulse) + ')';
          ctx.lineWidth = 2.5;
        } else {
          ctx.strokeStyle = e.kind === 'control' ? 'rgba(138,143,152,0.4)' : 'rgba(180,185,192,0.45)';
          ctx.lineWidth = 1;
        }
        ctx.stroke();
      }
      // nodes
      for (var k = 0; k < nodes.length; k++) {
        var n = nodes[k];
        var p = toScreen(n);
        var r = 9 * Math.min(view.scale, 1.6);
        var sh = nodeShape(n);
        if (n.trifecta) {
          ctx.beginPath();
          ctx.arc(p.x, p.y, r + 5 + 2 * pulse, 0, Math.PI * 2);
          ctx.strokeStyle = 'rgba(214,50,31,' + (0.45 + 0.5 * pulse) + ')';
          ctx.lineWidth = 2.5; ctx.stroke();
        }
        ctx.beginPath();
        ctx.fillStyle = nodeColor(n);
        if (sh === 0) {
          ctx.arc(p.x, p.y, r, 0, Math.PI * 2);
        } else if (sh === 2) {
          ctx.moveTo(p.x, p.y - r); ctx.lineTo(p.x + r, p.y);
          ctx.lineTo(p.x, p.y + r); ctx.lineTo(p.x - r, p.y); ctx.closePath();
        } else {
          ctx.rect(p.x - r, p.y - r, 2 * r, 2 * r);
        }
        ctx.fill();
        if (n === selected) {
          ctx.strokeStyle = '#F4F5F6'; ctx.lineWidth = 2; ctx.stroke();
        }
        ctx.fillStyle = '#C7CAD1';
        ctx.font = '11px "IBM Plex Mono", ui-monospace, SFMono-Regular, Menlo, monospace';
        ctx.textAlign = 'center';
        ctx.fillText(n.name, p.x, p.y + r + 12);
      }
    }

    var running = true, start = null;
    function loop(t) {
      if (start === null) start = t;
      physics();
      draw(t - start);
      if (running) requestAnimationFrame(loop);
    }
    requestAnimationFrame(loop);

    function pick(px, py) {
      var best = null, bd = 18;
      for (var i = 0; i < nodes.length; i++) {
        var p = toScreen(nodes[i]);
        var d = Math.hypot(p.x - px, p.y - py);
        if (d < bd) { bd = d; best = nodes[i]; }
      }
      return best;
    }

    function showPanel(n) {
      if (!n) { panel.innerHTML = 'Click a node to inspect it.'; return; }
      var esc = function (s) {
        return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
      };
      var kinds = [];
      if (n.is_untrusted_input) kinds.push('untrusted-input');
      if (n.is_source) kinds.push('source');
      if (n.is_sink) kinds.push('sink');
      if (n.is_egress) kinds.push('egress');
      if (n.is_llm) kinds.push('llm');
      panel.innerHTML =
        '<div class="pn-title">' + esc(n.name) + (n.trifecta ? ' <span class="pn-red">TRIFECTA</span>' : '') + '</div>' +
        '<div class="pn-row"><span>Agent</span><b>' + esc(n.agent) + '</b></div>' +
        '<div class="pn-row"><span>Kind</span><b>' + esc(kinds.join(', ') || 'tool') + '</b></div>' +
        '<div class="pn-row"><span>Integrity</span><b>' + esc(n.integrity) + '</b></div>' +
        '<div class="pn-row"><span>Confidentiality</span><b>' + esc(n.confidentiality) + '</b></div>' +
        '<div class="pn-row"><span>Location</span><b>' + esc(n.loc || 'n/a') + '</b></div>';
    }

    canvas.addEventListener('mousedown', function (ev) {
      var r = canvas.getBoundingClientRect();
      var px = ev.clientX - r.left, py = ev.clientY - r.top;
      var n = pick(px, py);
      if (n) { dragNode = n; selected = n; showPanel(n); }
      else { panning = true; lastX = px; lastY = py; }
    });
    window.addEventListener('mousemove', function (ev) {
      var r = canvas.getBoundingClientRect();
      var px = ev.clientX - r.left, py = ev.clientY - r.top;
      if (dragNode) {
        var w = toWorld(px, py);
        dragNode.x = w.x; dragNode.y = w.y;
      } else if (panning) {
        view.tx += px - lastX; view.ty += py - lastY;
        lastX = px; lastY = py;
      }
    });
    window.addEventListener('mouseup', function () { dragNode = null; panning = false; });
    canvas.addEventListener('wheel', function (ev) {
      ev.preventDefault();
      var f = ev.deltaY < 0 ? 1.1 : 0.9;
      view.scale = Math.max(0.3, Math.min(3, view.scale * f));
    }, { passive: false });
  })();
  </script>
"""


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Lucin Security Report</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: 'IBM Plex Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #FAFAF8; color: #141414; line-height: 1.6; padding: 2.5rem 2rem; }}
  .container {{ max-width: 960px; margin: 0 auto; }}
  h1 {{ font-family: 'Space Grotesk', sans-serif; font-weight: 700; font-size: 1.9rem; letter-spacing: -.02em; margin-bottom: 0.4rem; }}
  .section-title {{ font-family: 'Space Grotesk', sans-serif; font-weight: 700; font-size: 1.2rem; margin: 2.4rem 0 0.6rem; letter-spacing: -.01em; }}
  .section-note {{ color: #6C7076; font-size: 0.85rem; margin-bottom: 1rem; }}
  .subtitle {{ color: #6C7076; margin-bottom: 2rem; font-family: 'IBM Plex Mono', monospace; font-size: 0.85rem; }}
  .score-card {{ background: #fff; border-radius: 6px; padding: 2rem; margin-bottom: 2rem; text-align: center; border: 2px solid #141414; }}
  .score-number {{ font-family: 'Space Grotesk', sans-serif; font-size: 4rem; font-weight: 700; color: {score_color}; font-variant-numeric: tabular-nums; }}
  .score-label {{ font-size: 1.05rem; color: #3D4147; margin-top: 0.2rem; }}
  .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 0; margin-bottom: 2rem; border-top: 2px solid #141414; border-bottom: 2px solid #141414; }}
  .stat {{ background: #fff; padding: 1.1rem 0.5rem; text-align: center; border-right: 1px solid #D7D9DC; }}
  .stat:last-child {{ border-right: none; }}
  .stat-number {{ font-family: 'Space Grotesk', sans-serif; font-size: 1.6rem; font-weight: 700; }}
  .stat-label {{ font-size: 0.78rem; color: #6C7076; margin-top: 0.2rem; }}
  .finding {{ background: #fff; border-radius: 6px; margin-bottom: 1rem; border: 1.5px solid #141414; overflow: hidden; }}
  .finding summary {{ padding: 1rem 1.2rem; cursor: pointer; display: flex; align-items: center; gap: 0.75rem; list-style: none; }}
  .finding summary::-webkit-details-marker {{ display: none; }}
  .finding summary:hover {{ background: #F1F0EC; }}
  .finding-body {{ padding: 1rem 1.5rem 1.3rem; border-top: 1.5px solid #141414; }}
  .finding-body p {{ margin-bottom: 0.5rem; }}
  .finding-title {{ font-weight: 600; flex: 1; }}
  .finding-id {{ color: #6C7076; font-size: 0.82rem; font-family: 'IBM Plex Mono', monospace; }}
  .badge {{ padding: 3px 9px; border-radius: 3px; font-size: 0.68rem; font-weight: 700; text-transform: uppercase; font-family: 'IBM Plex Mono', monospace; letter-spacing: .03em; }}
  .badge.critical {{ background: #D6321F; color: #fff; }}
  .badge.high {{ background: #141414; color: #fff; }}
  .badge.medium {{ background: #E9E7E1; color: #3D4147; border: 1px solid #C7C4BC; }}
  .badge.low {{ background: #fff; color: #6C7076; border: 1px solid #D7D9DC; }}
  .description {{ color: #3D4147; }}
  .attack {{ background: #F6EFE9; padding: 0.85rem 1rem; border-radius: 4px; margin: 0.6rem 0; border-left: 3px solid #B85C1F; }}
  .fix {{ background: #EEF3EC; padding: 0.85rem 1rem; border-radius: 4px; margin: 0.6rem 0; border-left: 3px solid #2F7A4D; }}
  .location {{ color: #6C7076; font-size: 0.85rem; font-family: 'IBM Plex Mono', monospace; }}
  .witness {{ background: #FBECE9; padding: 0.85rem 1rem; border-radius: 4px; margin: 0.6rem 0; border-left: 3px solid #D6321F; }}
  .wit-row {{ display: flex; flex-wrap: wrap; align-items: center; gap: 0.35rem; margin-top: 0.4rem; }}
  .wit-label {{ color: #6C7076; font-size: 0.75rem; margin-right: 0.4rem; }}
  .wit-node {{ background: #141414; color: #FAFAF8; padding: 2px 7px; border-radius: 3px; font-family: 'IBM Plex Mono', monospace; font-size: 0.78rem; }}
  .wit-arrow {{ color: #D6321F; }}
  .mincut {{ background: #EAF0FB; padding: 0.85rem 1rem; border-radius: 4px; margin: 0.6rem 0; border-left: 3px solid #1D4ED8; }}
  .cut-tool {{ background: #1D4ED8; color: #fff; padding: 2px 7px; border-radius: 3px; font-family: 'IBM Plex Mono', monospace; font-size: 0.78rem; margin: 0 0.2rem; }}
  .refs {{ display: flex; flex-wrap: wrap; gap: 0.5rem; }}
  .ref {{ font-size: 0.72rem; padding: 2px 8px; border-radius: 3px; font-family: 'IBM Plex Mono', monospace; }}
  .ref.owasp {{ background: #EAF0FB; color: #1D4ED8; }}
  .ref.atlas {{ background: #F1E9F9; color: #7C3FBF; }}
  .aifg-shell {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1rem; }}
  .aifg-canvas-wrap {{ flex: 1 1 560px; background: #141414; border: 2px solid #141414; border-radius: 8px; }}
  #aifg-canvas {{ width: 100%; height: 440px; display: block; }}
  .aifg-panel {{ flex: 0 0 240px; background: #fff; border: 1.5px solid #141414; border-radius: 8px; padding: 1rem; font-size: 0.85rem; color: #6C7076; }}
  .pn-title {{ font-family: 'IBM Plex Mono', monospace; color: #141414; font-weight: 600; margin-bottom: 0.6rem; word-break: break-all; }}
  .pn-red {{ color: #D6321F; font-size: 0.7rem; }}
  .pn-row {{ display: flex; justify-content: space-between; gap: 0.5rem; padding: 0.15rem 0; }}
  .pn-row b {{ color: #141414; font-family: 'IBM Plex Mono', monospace; text-align: right; word-break: break-all; }}
  .aifg-legend {{ display: flex; flex-wrap: wrap; gap: 1rem; margin-bottom: 2rem; font-size: 0.8rem; color: #6C7076; }}
  .aifg-legend .lg {{ display: inline-flex; align-items: center; gap: 0.35rem; }}
  .sw {{ display: inline-block; width: 12px; height: 12px; }}
  .sw.circle {{ border-radius: 50%; }}
  .sw.diamond {{ transform: rotate(45deg); }}
  .sw.ring {{ border-radius: 50%; background: transparent; border: 2px solid #D6321F; }}
  .sw.amber {{ background: #E8A33D; }}
  .sw.teal {{ background: #2FBF9E; }}
  .sw.blue {{ background: #5B8CFF; }}
  .sw.purple {{ background: #C77DFF; }}
  .sw.grey {{ background: #8A8F98; }}
  .footer {{ margin-top: 2.5rem; text-align: center; color: #6C7076; font-size: 0.85rem; border-top: 1px solid #D7D9DC; padding-top: 1.5rem; }}
  .footer a {{ color: #D6321F; text-decoration: none; }}
  .footer a:hover {{ color: #A82415; }}
</style>
</head>
<body>
<div class="container">
  <h1>Lucin Security Report</h1>
  <p class="subtitle">Target: {target} | Generated: {timestamp}</p>

  <div class="score-card">
    <div class="score-number">{score}/100</div>
    <div class="score-label">{score_label}</div>
  </div>

  <div class="stats">
    <div class="stat"><div class="stat-number" style="color: #D6321F">{critical_count}</div><div class="stat-label">Critical</div></div>
    <div class="stat"><div class="stat-number" style="color: #B85C1F">{high_count}</div><div class="stat-label">High</div></div>
    <div class="stat"><div class="stat-number" style="color: #B8860B">{medium_count}</div><div class="stat-label">Medium</div></div>
    <div class="stat"><div class="stat-number" style="color: #6C7076">{low_count}</div><div class="stat-label">Low</div></div>
    <div class="stat"><div class="stat-number">{agent_count}</div><div class="stat-label">Agents</div></div>
    <div class="stat"><div class="stat-number">{tool_count}</div><div class="stat-label">Tools</div></div>
  </div>

  {graph_section}

  {findings}

  <div class="footer">
    <p>Generated by Lucin v0.1.0 in {scan_ms}ms | <a href="https://github.com/Madhav2310/lucinlabs">github.com/Madhav2310/lucinlabs</a></p>
  </div>
</div>
</body>
</html>"""
