'use strict';

const versionTagEl2 = document.getElementById('versionTag');
if (versionTagEl2) versionTagEl2.textContent = `v${chrome.runtime.getManifest().version}`;

function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

const state = { A: null, B: null };

function scanOne(domain) {
  return new Promise(resolve => {
    let settled = false;
    const port = chrome.runtime.connect({ name: 'scan' });
    const done = (status, data) => {
      if (settled) return;
      settled = true;
      try { port.disconnect(); } catch {}
      resolve({ status, data });
    };
    port.onMessage.addListener(msg => {
      if (msg.type === 'result') done('done', msg.data);
      else if (msg.type === 'error') done('error', { message: msg.message });
    });
    port.onDisconnect.addListener(() => done('error', { message: 'Disconnected' }));
    setTimeout(() => done('error', { message: 'Timeout' }), 60000);
    port.postMessage({ action: 'scan', domain, forceRefresh: false });
  });
}

function renderCol(col, result) {
  const el = document.getElementById(`result${col}`);
  const order = Object.keys(PROVIDER_META);
  const detected = order.filter(id => result.providers?.[id]?.verdict?.detected)
    .sort((a, b) => (result.providers[b].verdict.score || 0) - (result.providers[a].verdict.score || 0));

  if (!detected.length) {
    el.innerHTML = '<div style="color:var(--text-faint);font-size:11.5px;padding:8px 0;font-style:italic">No providers detected</div>';
    return;
  }
  el.innerHTML = detected.map(id => {
    const pv = result.providers[id];
    const color = PROVIDER_META[id]?.color || 'var(--accent)';
    return `<div class="col-result-row hit" style="border-left:3px solid ${esc(color)}">
      <span>${esc(PROVIDER_META[id]?.name || id)}</span>
      <span class="pct">${pv.verdict.score}%</span>
    </div>`;
  }).join('');
}

function renderSummary() {
  const sum = document.getElementById('compareSummary');
  if (!state.A || !state.B) { sum.hidden = true; return; }

  const order = Object.keys(PROVIDER_META);
  const dA = new Set(order.filter(id => state.A.providers?.[id]?.verdict?.detected));
  const dB = new Set(order.filter(id => state.B.providers?.[id]?.verdict?.detected));
  const shared = order.filter(id => dA.has(id) && dB.has(id));
  const onlyA  = order.filter(id => dA.has(id) && !dB.has(id));
  const onlyB  = order.filter(id => !dA.has(id) && dB.has(id));
  const name = id => esc(PROVIDER_META[id]?.name || id);

  const chips = (ids, cls) => ids.length
    ? ids.map(id => `<span class="summary-chip ${cls}">${name(id)}</span>`).join('')
    : '<span class="summary-empty">—</span>';

  document.getElementById('chipsShared').innerHTML = chips(shared, 'shared');
  document.getElementById('chipsOnlyA').innerHTML  = chips(onlyA, 'only-a');
  document.getElementById('chipsOnlyB').innerHTML  = chips(onlyB, 'only-b');
  sum.hidden = false;
}

function getHistory(domain) {
  return new Promise(resolve => {
    chrome.runtime.sendMessage({ action: 'getSnapshotHistory', domain }, res => resolve(res?.snapshots || []));
  });
}

// ── History trend chart: same hand-built SVG approach as the Timeline
// view's sparkline (popup.js), reused here for the two-domain comparison
// case — one line per domain, detected-provider count as the Y value
// rather than a single provider's score, since comparing 26 individual
// per-provider lines across 2 domains at once would be unreadable.
async function renderCompareTrend() {
  const wrap = document.getElementById('compareTrend');
  const chartEl = document.getElementById('compareTrendChart');
  if (!state.A || !state.B) { wrap.hidden = true; return; }

  const domA = document.getElementById('domainA').value.trim().toLowerCase();
  const domB = document.getElementById('domainB').value.trim().toLowerCase();
  const [histA, histB] = await Promise.all([getHistory(domA), getHistory(domB)]);

  if (histA.length < 2 && histB.length < 2) { wrap.hidden = true; return; } // nothing to trend yet

  const countDetected = snap => Object.values(snap.result?.providers || {}).filter(v => v?.verdict?.detected).length;
  const seriesA = [...histA].reverse().map(s => ({ ts: s.ts, n: countDetected(s) }));
  const seriesB = [...histB].reverse().map(s => ({ ts: s.ts, n: countDetected(s) }));
  const allTs = [...seriesA, ...seriesB].map(p => p.ts);
  const minTs = Math.min(...allTs), maxTs = Math.max(...allTs);
  const maxN  = Math.max(1, ...seriesA.map(p => p.n), ...seriesB.map(p => p.n));

  const W = 600, H = 140, padL = 24, padR = 10, padT = 10, padB = 20;
  const plotW = W - padL - padR, plotH = H - padT - padB;
  const xFor = ts => padL + (maxTs === minTs ? plotW / 2 : ((ts - minTs) / (maxTs - minTs)) * plotW);
  const yFor = n => padT + plotH - (n / maxN) * plotH;

  const gridLines = Array.from({ length: 5 }, (_, i) => Math.round((maxN / 4) * i)).map(v =>
    `<line x1="${padL}" y1="${yFor(v)}" x2="${W - padR}" y2="${yFor(v)}" stroke="var(--border)" stroke-width="1" stroke-dasharray="2,3"/>
     <text x="2" y="${yFor(v) + 3}" font-size="8" fill="var(--text-faint)">${v}</text>`
  ).join('');

  const lineFor = (series, color, label) => {
    if (series.length < 2) return '';
    const pathD = series.map((p, i) => `${i === 0 ? 'M' : 'L'}${xFor(p.ts).toFixed(1)},${yFor(p.n).toFixed(1)}`).join(' ');
    const dots = series.map(p =>
      `<circle cx="${xFor(p.ts).toFixed(1)}" cy="${yFor(p.n).toFixed(1)}" r="2.5" fill="${color}">
         <title>${esc(label)}: ${p.n} detected on ${new Date(p.ts).toLocaleString()}</title>
       </circle>`
    ).join('');
    return `<path d="${pathD}" fill="none" stroke="${color}" stroke-width="1.75" opacity="0.9"/>${dots}`;
  };

  chartEl.innerHTML = `
    <svg viewBox="0 0 ${W} ${H}" width="100%" height="${H}" role="img" aria-label="Detected provider count over time, domain A versus domain B">
      ${gridLines}
      ${lineFor(seriesA, '#1ed4ff', domA)}
      ${lineFor(seriesB, '#f0555a', domB)}
    </svg>
    <div style="display:flex;gap:14px;padding:4px 0 6px;font-size:9.5px;color:var(--text-dim)">
      <span><span style="width:8px;height:8px;border-radius:50%;background:#1ed4ff;display:inline-block;margin-right:4px"></span>${esc(domA)}</span>
      <span><span style="width:8px;height:8px;border-radius:50%;background:#f0555a;display:inline-block;margin-right:4px"></span>${esc(domB)}</span>
    </div>`;
  wrap.hidden = false;
}

document.querySelectorAll('.scan-col-btn').forEach(btn => {
  btn.addEventListener('click', async () => {
    const col = btn.dataset.col;
    const input = document.getElementById(`domain${col}`);
    const domain = input.value.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
    if (!domain) { input.focus(); return; }

    const resultEl = document.getElementById(`result${col}`);
    btn.disabled = true;
    btn.textContent = `Scanning ${col}…`;
    resultEl.innerHTML = '<div style="color:var(--text-faint);font-size:11.5px;padding:8px 0">Scanning…</div>';
    state[col] = null;
    document.getElementById('compareSummary').hidden = true;
    document.getElementById('compareTrend').hidden = true;

    const { status, data } = await scanOne(domain);
    btn.disabled = false;
    btn.textContent = `Scan ${col}`;

    if (status === 'error') {
      resultEl.innerHTML = `<div style="color:var(--red);font-size:11.5px;padding:8px 0">Failed: ${esc(data?.message || 'error')}</div>`;
      return;
    }
    state[col] = data;
    renderCol(col, data);
    renderSummary();
    renderCompareTrend();
  });
});
