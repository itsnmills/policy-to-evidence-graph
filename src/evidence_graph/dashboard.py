from __future__ import annotations

import json
from pathlib import Path


def _escape_json_for_html(payload: object) -> str:
    rendered = json.dumps(payload, ensure_ascii=False)
    return rendered.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")


def _set_private_permissions(path: Path) -> None:
    try:
        path.chmod(0o600)
    except Exception:
        pass


def write_dashboard(outdir: Path, payload: dict) -> None:
    outdir.mkdir(parents=True, exist_ok=True)

    payload_path = outdir / "dashboard_data.json"
    payload_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    _set_private_permissions(payload_path)

    escaped_payload = _escape_json_for_html(payload)
    index_html = f'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Policy-to-Evidence Dashboard</title>
  <style>
    :root {{
      --bg: #f1f5f9;
      --panel: #ffffff;
      --text: #0f172a;
      --subtle: #334155;
      --line: #cbd5e1;
      --success: #16a34a;
      --warn: #ca8a04;
      --danger: #dc2626;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Inter, system-ui, -apple-system, sans-serif;
      background: linear-gradient(140deg, #f8fafc, var(--bg));
      color: var(--text);
      padding: 1rem;
    }}
    .container {{
      max-width: 1200px;
      margin: 0 auto;
      display: grid;
      gap: 1rem;
    }}
    .card {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 1rem;
      box-shadow: 0 8px 24px rgb(15 23 42 / 6%);
    }}
    .header {{
      display: flex;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 0.5rem;
      align-items: center;
    }}
    .tiles {{
      display: flex;
      flex-wrap: wrap;
      gap: 0.75rem;
    }}
    .tile {{
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 0.65rem 0.75rem;
      background: #f8fafc;
      min-width: 125px;
    }}
    .tile strong {{
      display: block;
      font-size: 1.1rem;
      margin-bottom: 0.2rem;
    }}
    .muted {{ color: var(--subtle); font-size: 0.92rem; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{
      border-bottom: 1px solid #e2e8f0;
      text-align: left;
      font-size: 0.9rem;
      padding: 0.45rem;
      vertical-align: top;
    }}
    th {{ color: #0f172a; font-weight: 700; background: #f8fafc; }}
    .status {{ font-weight: 700; }}
    .state-ready {{ color: var(--success); }}
    .state-partial {{ color: var(--warn); }}
    .state-stale {{ color: #ea580c; }}
    .state-missing {{ color: var(--danger); }}
    .trend {{
      white-space: pre-wrap;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      background: #0f172a;
      color: #e2e8f0;
      padding: 0.8rem;
      border-radius: 10px;
      overflow: auto;
    }}
    .list {{ margin: 0; padding-left: 1.1rem; }}
    .list li {{ margin-bottom: 0.35rem; }}
    .badge {{
      padding: 0.15rem 0.45rem;
      border-radius: 999px;
      color: #fff;
      font-size: 0.72rem;
      white-space: nowrap;
    }}
    .badge-ready {{ background: #15803d; }}
    .badge-partial {{ background: #ca8a04; }}
    .badge-stale {{ background: #ea580c; }}
    .badge-missing {{ background: #dc2626; }}
    .badge-other {{ background: #334155; }}
    footer {{ font-size: 0.8rem; color: var(--subtle); text-align: center; padding: 0.5rem 0.25rem 0.25rem; }}
    @media (max-width: 720px) {{
      .container {{ gap: 0.75rem; }}
      .card {{ padding: 0.8rem; }}
      table {{ font-size: 0.8rem; }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <section class="card">
      <div class="header">
        <h1>Policy-to-Evidence Dashboard</h1>
        <p class="muted" id="metadata"></p>
      </div>
      <p class="muted">Local dashboard generated from your latest evidence packet. No network calls are required.</p>
      <div class="tiles" id="tiles"></div>
    </section>

    <section class="card">
      <h2>Priority actions</h2>
      <ol class="list" id="gaps"></ol>
    </section>

    <section class="card">
      <h2>Control matrix snapshot</h2>
      <div id="matrix"></div>
    </section>

    <section class="card">
      <h2>Input sources</h2>
      <div id="input-sources"></div>
    </section>

    <section class="card">
      <h2>Integrity and trend summary</h2>
      <p class="muted" id="manifest"></p>
      <pre id="trend" class="trend"></pre>
    </section>

    <footer>Evidence graph output is generated from local files in <code>out/</code> only.</footer>
  </div>

<script id="ptg-data" type="application/json">{escaped_payload}</script>
<script>
function badgeClass(state) {{
  const value = String(state || 'other').toLowerCase();
  if (value === 'ready') return 'badge-ready';
  if (value === 'partial') return 'badge-partial';
  if (value === 'stale') return 'badge-stale';
  if (value === 'missing') return 'badge-missing';
  return 'badge-other';
}}

(function() {{
  const raw = document.getElementById('ptg-data').textContent;
  const data = raw ? JSON.parse(raw) : {{}};

  const metadata = document.getElementById('metadata');
  metadata.textContent = `${{data.project || 'Practice'}} generated ${{data.generated_at || ''}}`;

  const tiles = document.getElementById('tiles');
  const stateCounts = data.state_counts || {{}};
  const order = ['ready', 'partial', 'stale', 'missing', 'unknown'];
  for (const state of order) {{
    const count = Number(stateCounts[state] || 0);
    const tile = document.createElement('div');
    tile.className = 'tile';
    tile.innerHTML = `<strong>${{count}}</strong><span class="muted">${{state}}</span>`;
    tiles.appendChild(tile);
  }}

  const manifest = data.integrity_manifest || null;
  const manifestEl = document.getElementById('manifest');
  if (manifest) {{
    manifestEl.textContent = `Integrity files: ${{manifest.file_count || 0}}, refreshed ${{manifest.generated_at || 'unknown'}}`;
  }} else {{
    manifestEl.textContent = 'No integrity manifest detected in this payload.';
  }}

  const gaps = document.getElementById('gaps');
  (data.gaps || []).slice(0, 10).forEach((item) => {{
    const li = document.createElement('li');
    const badge = `<span class="badge ${{badgeClass(item.state)}}">${{item.state}}</span>`;
    li.innerHTML = `${{badge}} <strong>${{item.control_id}}</strong> — ${{item.owner || 'Needs assignment'}} (due ${{item.due_in_days || 'n/a'}} days)`;
    gaps.appendChild(li);
  }});
  if (!((data.gaps || []).length)) {{
    const li = document.createElement('li');
    li.textContent = 'No blocking action items.';
    gaps.appendChild(li);
  }}

  const matrixRows = data.matrix_rows || [];
  const matrix = document.createElement('table');
  const header = matrix.createTHead().insertRow();
  ['Control', 'State', 'Score', 'Evidence', 'Owner'].forEach((h) => {{
    const th = document.createElement('th');
    th.textContent = h;
    header.appendChild(th);
  }});
  const body = matrix.createTBody();
  matrixRows.slice(0, 24).forEach((row) => {{
    const tr = body.insertRow();
    const state = String(row.state || 'unknown');
    tr.insertCell().textContent = row.control_id || '';
    const stateCell = tr.insertCell();
    const badge = document.createElement('span');
    badge.className = `badge ${{badgeClass(state)}}`;
    badge.textContent = state;
    stateCell.appendChild(badge);
    tr.insertCell().textContent = String(row.readiness_score || '');
    tr.insertCell().textContent = String(row.evidence_count || 0);
    tr.insertCell().textContent = row.owner || '';
  }});
  document.getElementById('matrix').appendChild(matrix);

  document.getElementById('trend').textContent = JSON.stringify(data.trend || {{}}, null, 2);

  const sourcesRoot = document.getElementById('input-sources');
  const sources = data.input_sources || [];
  if (!sources.length) {{
    sourcesRoot.textContent = 'No input manifest available.';
  }} else {{
    const sourceTable = document.createElement('table');
    const sourceHeader = sourceTable.createTHead().insertRow();
    ['Source', 'Type', 'Rows', 'SHA-256', 'Exists'].forEach((h) => {{
      const th = document.createElement('th');
      th.textContent = h;
      sourceHeader.appendChild(th);
    }});
    const sourceBody = sourceTable.createTBody();
    sources.forEach((row) => {{
      const tr = sourceBody.insertRow();
      tr.insertCell().textContent = row.relative_path || '';
      tr.insertCell().textContent = row.source_type || '';
      tr.insertCell().textContent = String(row.records || 0);
      tr.insertCell().textContent = row.sha256 || 'n/a';
      const exists = String(row.exists || '').toLowerCase() === 'true' || String(row.exists || '').toLowerCase() === '1';
      tr.insertCell().textContent = exists ? 'yes' : 'no';
    }});
    sourcesRoot.appendChild(sourceTable);
  }}
}})();
</script>
</body>
</html>'''

    index_path = outdir / "index.html"
    index_path.write_text(index_html, encoding="utf-8")
    _set_private_permissions(index_path)
