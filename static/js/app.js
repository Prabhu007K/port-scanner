const form = document.getElementById('scan-form');
const results = document.getElementById('results');
const progressSection = document.getElementById('progress-section');
const btn = document.getElementById('scan-btn');
const portsSelect = document.getElementById('ports');
const customWrap = document.getElementById('custom-ports-wrap');

let lastScanData = null;
const HISTORY_KEY = 'portscan-history-v1';

portsSelect.addEventListener('change', () => {
  customWrap.classList.toggle('hidden', portsSelect.value !== 'custom');
});

document.querySelectorAll('.btn-preset').forEach(b => {
  b.addEventListener('click', () => {
    document.getElementById('target').value = b.dataset.target;
  });
});

form.addEventListener('submit', async e => {
  e.preventDefault();
  const target = document.getElementById('target').value.trim();
  let ports = portsSelect.value;
  if (ports === 'custom') {
    ports = document.getElementById('custom-ports').value.trim();
    if (!ports) {
      alert('Enter custom ports (e.g. 22,80,443 or 8000-8100)');
      return;
    }
  }

  btn.disabled = true;
  btn.textContent = 'Scanning…';
  btn.classList.add('scanning');
  results.hidden = true;
  progressSection.classList.remove('hidden');
  setProgress(0, 1, 0, 0);

  const body = {
    target,
    ports,
    scan_type: document.getElementById('scan-type').value,
    timeout: parseFloat(document.getElementById('timeout').value),
    ping_first: document.getElementById('ping-first').checked,
    include_udp: document.getElementById('include-udp').checked,
    consent: document.getElementById('consent').checked,
  };

  const openPorts = [];

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      const err = await res.json();
      alert(err.error || 'Scan failed');
      resetBtn();
      progressSection.classList.add('hidden');
      return;
    }

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';

      for (const line of lines) {
        if (!line.trim()) continue;
        const evt = JSON.parse(line);
        handleEvent(evt, openPorts);
      }
    }
  } catch (err) {
    alert('Scan error: ' + err.message);
  }

  resetBtn();
});

function handleEvent(evt, openPorts) {
  if (evt.type === 'start') {
    document.getElementById('progress-text').textContent = `Scanning ${evt.target} (${evt.ip})…`;
  }
  if (evt.type === 'ping') {
    document.getElementById('progress-detail').textContent = evt.message;
  }
  if (evt.type === 'warn') {
    document.getElementById('progress-detail').textContent = evt.message;
  }
  if (evt.type === 'progress') {
    setProgress(evt.scanned, evt.total, evt.found, evt.elapsed);
  }
  if (evt.type === 'found') {
    openPorts.push(evt.port);
    renderLiveResults(openPorts);
  }
  if (evt.type === 'done') {
    lastScanData = evt;
    progressSection.classList.add('hidden');
    renderResults(evt);
    saveHistory(evt);
    loadHistory();
  }
}

function setProgress(scanned, total, found, elapsed) {
  const pct = total ? Math.round((scanned / total) * 100) : 0;
  document.getElementById('progress-bar').style.width = pct + '%';
  document.getElementById('elapsed-text').textContent = (elapsed || 0).toFixed(1) + 's';
  document.getElementById('progress-detail').textContent =
    `${scanned} / ${total} ports · ${found} open · ${pct}%`;
}

function resetBtn() {
  btn.disabled = false;
  btn.textContent = 'Start scan';
  btn.classList.remove('scanning');
}

function renderLiveResults(openPorts) {
  results.hidden = false;
  document.getElementById('summary').innerHTML =
    `<span class="mono">Live:</span> ${openPorts.length} open port(s) found so far…`;
  renderTable(openPorts);
}

function renderResults(data) {
  results.hidden = false;
  document.getElementById('summary').innerHTML =
    `<strong>${esc(data.target)}</strong> (${esc(data.ip)}) — scanned <strong>${data.scanned}</strong> probes in <strong>${data.elapsed}s</strong>, found <strong>${data.open.length}</strong> open`;
  renderTable(data.open);
  renderHeatmap(data.open);
}

function renderTable(rows) {
  document.getElementById('result-body').innerHTML = rows.length
    ? rows.map(r => `<tr>
        <td>${r.port}</td>
        <td>${esc(r.protocol || 'tcp')}</td>
        <td>${esc(r.state)}</td>
        <td>${esc(r.service)}</td>
        <td><span class="badge-risk ${r.risk || 'low'}">${esc(r.risk || 'low')}</span></td>
        <td class="mono">${r.rtt_ms != null ? r.rtt_ms + ' ms' : '—'}</td>
        <td class="banner-cell">${esc(r.banner)}</td>
      </tr>`).join('')
    : '<tr><td colspan="7" style="text-align:center;color:var(--muted)">No open ports found</td></tr>';
}

function renderHeatmap(openPorts) {
  const wrap = document.getElementById('heatmap-wrap');
  const grid = document.getElementById('heatmap');
  const openSet = new Set(openPorts.filter(p => p.port <= 1024).map(p => p.port));

  wrap.classList.remove('hidden');
  grid.innerHTML = '';
  for (let p = 1; p <= 1024; p++) {
    const cell = document.createElement('div');
    cell.className = 'heat-cell' + (openSet.has(p) ? ' open' : '');
    cell.title = openSet.has(p) ? `Port ${p} OPEN` : `Port ${p}`;
    grid.appendChild(cell);
  }
}

function saveHistory(data) {
  let hist = [];
  try { hist = JSON.parse(sessionStorage.getItem(HISTORY_KEY) || '[]'); } catch { /* */ }
  hist.unshift({
    time: new Date().toLocaleString(),
    target: data.target,
    ip: data.ip,
    openCount: data.open.length,
    elapsed: data.elapsed,
    open: data.open,
  });
  hist = hist.slice(0, 5);
  sessionStorage.setItem(HISTORY_KEY, JSON.stringify(hist));
}

function loadHistory() {
  let hist = [];
  try { hist = JSON.parse(sessionStorage.getItem(HISTORY_KEY) || '[]'); } catch { /* */ }
  const ul = document.getElementById('history-list');
  if (!hist.length) {
    ul.innerHTML = '<li class="history-empty">No scans yet</li>';
    return;
  }
  ul.innerHTML = hist.map((h, i) =>
    `<li data-idx="${i}">${esc(h.time)} · ${esc(h.target)} (${esc(h.ip)}) — ${h.openCount} open · ${h.elapsed}s</li>`
  ).join('');

  ul.querySelectorAll('li[data-idx]').forEach(li => {
    li.addEventListener('click', () => {
      const h = hist[+li.dataset.idx];
      lastScanData = { target: h.target, ip: h.ip, scanned: 0, open: h.open, elapsed: h.elapsed };
      renderResults(lastScanData);
      results.scrollIntoView({ behavior: 'smooth' });
    });
  });
}

document.getElementById('export-json').addEventListener('click', () => {
  if (!lastScanData) return alert('Run a scan first');
  download(JSON.stringify(lastScanData, null, 2), 'scan-results.json', 'application/json');
});

document.getElementById('export-csv').addEventListener('click', () => {
  if (!lastScanData?.open?.length) return alert('No open ports to export');
  const header = 'port,protocol,state,service,risk,rtt_ms,banner\n';
  const rows = lastScanData.open.map(r =>
    [r.port, r.protocol, r.state, r.service, r.risk, r.rtt_ms, `"${(r.banner || '').replace(/"/g, '""')}"`].join(',')
  ).join('\n');
  download(header + rows, 'scan-results.csv', 'text/csv');
});

document.getElementById('copy-table').addEventListener('click', async () => {
  if (!lastScanData?.open?.length) return alert('No results');
  const text = lastScanData.open.map(r =>
    `${r.port}\t${r.protocol}\t${r.service}\t${r.risk}\t${r.banner}`
  ).join('\n');
  try {
    await navigator.clipboard.writeText('Port\tProto\tService\tRisk\tBanner\n' + text);
    alert('Copied to clipboard');
  } catch {
    alert('Copy failed');
  }
});

function download(content, name, type) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([content], { type }));
  a.download = name;
  a.click();
  URL.revokeObjectURL(a.href);
}

function esc(s) {
  const d = document.createElement('div');
  d.textContent = s ?? '';
  return d.innerHTML;
}

loadHistory();
