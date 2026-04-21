/* app.js - SQL Injection Detector Frontend Logic */

const API_BASE = 'http://localhost:5000';

// ─── DOM refs ────────────────────────────────────────────────────────────────
const dropZone      = document.getElementById('drop-zone');
const fileInput     = document.getElementById('file-input');
const browseBtn     = document.getElementById('browse-btn');
const clearBtn      = document.getElementById('clear-btn');
const filePreview   = document.getElementById('file-preview');
const fileNameEl    = document.getElementById('file-name');
const fileSizeEl    = document.getElementById('file-size');
const analyzeBtn    = document.getElementById('analyze-btn');
const btnText       = analyzeBtn.querySelector('.btn-text');
const btnSpinner    = analyzeBtn.querySelector('.btn-spinner');

const resultsSection = document.getElementById('results-section');
const errorCard     = document.getElementById('error-card');
const errorMsg      = document.getElementById('error-msg');
const summaryBar    = document.getElementById('summary-bar');
const vulnSection   = document.getElementById('vuln-section');
const vulnList      = document.getElementById('vuln-list');
const symbolSection = document.getElementById('symbol-section');
const symbolBody    = document.getElementById('symbol-body');
const symbolWrap    = document.getElementById('symbol-table-wrap');
const toggleSymbol  = document.getElementById('toggle-symbol-btn');
const statsSection  = document.getElementById('stats-section');
const statsGrid     = document.getElementById('stats-grid');
const dashboardSection = document.getElementById('dashboard-section');

let chartSeverity = null;
let chartTaint = null;
let chartSinks = null;

const fixesSection  = document.getElementById('fixes-section');
const fixesList     = document.getElementById('fixes-list');
const downloadFixedBtn = document.getElementById('download-fixed-btn');
const exportJsonBtn = document.getElementById('export-json-btn');
const mlInfo        = document.getElementById('ml-info');
const mlModelType   = document.getElementById('ml-model-type');
const mlCapabilities = document.getElementById('ml-capabilities');
const comparisonSection = document.getElementById('comparison-section');
const codeOriginalContent = document.getElementById('code-original-content');
const codeFixedContent = document.getElementById('code-fixed-content');
const diffOriginalContent = document.getElementById('diff-original-content');
const diffFixedContent = document.getElementById('diff-fixed-content');

let selectedFile = null;
let currentFilter = 'all';
let currentAnalysisData = null;

// ─── File selection ───────────────────────────────────────────────────────────
browseBtn.addEventListener('click', () => fileInput.click());

dropZone.addEventListener('click', (e) => {
  if (e.target !== browseBtn) fileInput.click();
});

fileInput.addEventListener('change', () => {
  if (fileInput.files[0]) setFile(fileInput.files[0]);
});

clearBtn.addEventListener('click', (e) => {
  e.stopPropagation();
  clearFile();
});

// Drag and drop
dropZone.addEventListener('dragover', (e) => {
  e.preventDefault();
  dropZone.classList.add('drag-over');
});

dropZone.addEventListener('dragleave', () => {
  dropZone.classList.remove('drag-over');
});

dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropZone.classList.remove('drag-over');
  const file = e.dataTransfer.files[0];
  if (file) setFile(file);
});

function setFile(file) {
  if (!file.name.endsWith('.py')) {
    showToast('Only .py files are supported.', 'error');
    return;
  }
  selectedFile = file;
  fileNameEl.textContent = file.name;
  fileSizeEl.textContent = formatSize(file.size);
  filePreview.hidden = false;
  analyzeBtn.disabled = false;
}

function clearFile() {
  selectedFile = null;
  fileInput.value = '';
  filePreview.hidden = true;
  analyzeBtn.disabled = true;
  hideResults();
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

// ─── Analyze ─────────────────────────────────────────────────────────────────
analyzeBtn.addEventListener('click', async () => {
  if (!selectedFile) return;
  await runAnalysis();
});

async function runAnalysis() {
  setLoading(true);
  hideResults();

  const formData = new FormData();
  formData.append('file', selectedFile);

  try {
    const res = await fetch(`${API_BASE}/analyze`, {
      method: 'POST',
      body: formData,
    });

    const data = await res.json();

    if (!data.success) {
      showError(data.error + (data.traceback ? '\n\n' + data.traceback : ''));
    } else {
      renderResults(data);
    }
  } catch (err) {
    showError(`Could not reach the analysis server.\n\nMake sure app.py is running:\n  python app.py\n\nError: ${err.message}`);
  } finally {
    setLoading(false);
  }
}

function setLoading(on) {
  analyzeBtn.disabled = on;
  btnText.hidden = on;
  btnSpinner.hidden = !on;
}

// ─── Results rendering ────────────────────────────────────────────────────────
function hideResults() {
  resultsSection.hidden = true;
  errorCard.hidden = true;
  summaryBar.hidden = true;
  vulnSection.hidden = true;
  symbolSection.hidden = true;
  statsSection.hidden = true;
  fixesSection.hidden = true;
  comparisonSection.hidden = true;
  if (dashboardSection) dashboardSection.hidden = true;
}

function showError(msg) {
  resultsSection.hidden = false;
  errorCard.hidden = false;
  errorMsg.textContent = msg;
  resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function renderResults(data) {
  currentAnalysisData = data;
  resultsSection.hidden = false;
  errorCard.hidden = true; // always ensure error card is hidden on success

  // Summary bar
  summaryBar.hidden = false;
  document.getElementById('sc-total-val').textContent  = data.summary.total_vulnerabilities;
  document.getElementById('sc-high-val').textContent   = data.summary.high_severity;
  document.getElementById('sc-medium-val').textContent = data.summary.medium_severity;
  document.getElementById('sc-filtered-val').textContent = data.summary.filtered;

  // add animate-in
  summaryBar.querySelectorAll('.summary-card').forEach((c, i) => {
    c.style.animationDelay = `${i * 60}ms`;
    c.classList.add('animate-in');
  });

  // Vulnerabilities
  if (data.vulnerabilities && data.vulnerabilities.length > 0) {
    vulnSection.hidden = false;
    renderVulnList(data.vulnerabilities);
  }

  // AI-Generated Fixes
  if (data.ml_fixes && data.ml_fixes.length > 0) {
    fixesSection.hidden = false;
    renderFixesList(data.ml_fixes);
    
    // Show ML model info
    if (data.ml_model_info) {
      mlInfo.hidden = false;
      mlModelType.textContent = data.ml_model_info.type || 'ML-Based Code Analyzer';
      mlCapabilities.textContent = data.ml_model_info.capabilities || 'Handles any code pattern';
    }
  } else if (data.fixes && data.fixes.length > 0) {
    fixesSection.hidden = false;
    renderFixesList(data.fixes);
  }

  // Code Comparison
  if (data.source_code && (data.ml_fixed_code || data.fixed_code)) {
    comparisonSection.hidden = false;
    const fixedCode = data.ml_fixed_code || data.fixed_code;
    renderCodeComparison(data.source_code, fixedCode);
  }

  // Symbol table
  symbolSection.hidden = false;
  renderSymbolTable(data.symbol_table || {});

  // Stats
  if (data.stats && Object.keys(data.stats).length > 0) {
    statsSection.hidden = false;
    renderStats(data.stats);
  }

  // Visual Dashboard (charts)
  renderDashboard(data);

  resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ─── Vulnerability cards ──────────────────────────────────────────────────────
function renderVulnList(vulns) {
  vulnList.innerHTML = '';
  vulns.forEach((v, idx) => {
    const card = createVulnCard(v, idx);
    vulnList.appendChild(card);
  });
}

function createVulnCard(v, idx) {
  const sev = (v.severity || 'LOW').toLowerCase();
  const card = document.createElement('div');
  card.className = `vuln-card vuln-card--${sev} animate-in`;
  card.style.animationDelay = `${idx * 50}ms`;
  card.dataset.severity = v.severity;

  card.innerHTML = `
    <div class="vuln-header">
      <span class="sev-badge sev-badge--${sev}">${v.severity}</span>
      <span class="vuln-id">${v.id}</span>
      <span class="vuln-rule">${escHtml(v.rule_violated)}</span>
      <span class="vuln-line">Line ${v.line}</span>
      <svg class="vuln-chevron" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <polyline points="6 9 12 15 18 9"/>
      </svg>
    </div>
    <div class="vuln-body">
      <div class="desc-box">${escHtml(v.description || '')}</div>
      <div class="detail-grid">
        <div class="detail-item">
          <div class="detail-label">Variable</div>
          <div class="detail-value">${escHtml(v.variable)}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Sink</div>
          <div class="detail-value">${escHtml(v.sink)}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Construction</div>
          <div class="detail-value">${escHtml(v.construction)}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Line</div>
          <div class="detail-value">${v.line}</div>
        </div>
      </div>
      <div class="fix-box">
        <div class="fix-label">✦ Suggested Fix</div>
        <div class="fix-text">${escHtml(v.suggested_fix || '')}</div>
      </div>
    </div>
  `;

  card.querySelector('.vuln-header').addEventListener('click', () => {
    card.classList.toggle('expanded');
  });

  return card;
}

// ─── Filter pills ─────────────────────────────────────────────────────────────
document.getElementById('filter-pills').addEventListener('click', (e) => {
  const pill = e.target.closest('.pill');
  if (!pill) return;

  document.querySelectorAll('.pill').forEach(p => p.classList.remove('pill--active'));
  pill.classList.add('pill--active');
  currentFilter = pill.dataset.filter;
  applyFilter();
});

function applyFilter() {
  document.querySelectorAll('.vuln-card').forEach(card => {
    if (currentFilter === 'all' || card.dataset.severity === currentFilter) {
      card.classList.remove('hidden');
    } else {
      card.classList.add('hidden');
    }
  });
}

// ─── Symbol table ─────────────────────────────────────────────────────────────
function renderSymbolTable(symbolMap) {
  symbolBody.innerHTML = '';
  const entries = Object.entries(symbolMap);
  if (entries.length === 0) {
    symbolBody.innerHTML = '<tr><td colspan="2" style="color:var(--text-muted);text-align:center;padding:20px">No variables tracked</td></tr>';
    return;
  }

  entries.sort(([, a], [, b]) => {
    const order = { TAINTED: 0, UNKNOWN: 1, SANITIZED: 2, UNTAINTED: 3 };
    return (order[a] ?? 9) - (order[b] ?? 9);
  });

  entries.forEach(([varName, state]) => {
    const stateStr = (typeof state === 'string' ? state : state.value || String(state)).toUpperCase();
    const cls = taintClass(stateStr);
    const row = document.createElement('tr');
    row.innerHTML = `
      <td>${escHtml(varName)}</td>
      <td><span class="taint-badge taint-badge--${cls}">${stateStr}</span></td>
    `;
    symbolBody.appendChild(row);
  });
}

function taintClass(state) {
  switch (state) {
    case 'TAINTED':   return 'tainted';
    case 'UNTAINTED': return 'untainted';
    case 'SANITIZED': return 'sanitized';
    default:          return 'unknown';
  }
}

// Collapse / expand symbol table
let symbolCollapsed = false;
toggleSymbol.addEventListener('click', () => {
  symbolCollapsed = !symbolCollapsed;
  symbolWrap.classList.toggle('collapsed', symbolCollapsed);
  toggleSymbol.textContent = symbolCollapsed ? 'Expand' : 'Collapse';
});

// ─── Stats ───────────────────────────────────────────────────────────────────
function renderStats(stats) {
  statsGrid.innerHTML = '';
  Object.entries(stats).forEach(([key, val]) => {
    const item = document.createElement('div');
    item.className = 'stat-item animate-in';
    item.innerHTML = `
      <div class="stat-key">${escHtml(key.replace(/_/g, ' '))}</div>
      <div class="stat-val">${escHtml(String(val))}</div>
    `;
    statsGrid.appendChild(item);
  });
}

// ─── Helpers ─────────────────────────────────────────────────────────────────
function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function showToast(msg, type = 'info') {
  // Simple inline toast
  const t = document.createElement('div');
  const bgColor = type === 'error' ? '#fef2f2' : type === 'success' ? '#d1fae5' : '#eff6ff';
  const textColor = type === 'error' ? '#dc2626' : type === 'success' ? '#059669' : '#2563eb';
  const borderColor = type === 'error' ? '#fecaca' : type === 'success' ? '#a7f3d0' : '#bfdbfe';
  
  t.style.cssText = `
    position:fixed;bottom:24px;right:24px;z-index:999;
    background:${bgColor};
    color:${textColor};
    border:1px solid ${borderColor};
    padding:12px 20px;border-radius:10px;font-size:.88rem;font-weight:600;
    box-shadow:0 4px 16px rgba(0,0,0,.1);animation:fadeSlideUp .3s ease;
  `;
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 3500);
}


// ─── AI Fixes rendering ───────────────────────────────────────────────────────
function renderFixesList(fixes) {
  fixesList.innerHTML = '';
  fixes.forEach((fix, idx) => {
    const card = createFixCard(fix, idx);
    fixesList.appendChild(card);
  });
}

function createFixCard(fix, idx) {
  const card = document.createElement('div');
  card.className = 'fix-card animate-in';
  card.style.animationDelay = `${idx * 50}ms`;

  // Check if this is ML fix with additional info
  const mlTechnique = fix.ml_technique ? `<div class="ml-technique">🧠 ML Technique: ${escHtml(fix.ml_technique)}</div>` : '';
  const confidence = fix.confidence ? `<div class="ml-confidence">📊 Confidence: ${(fix.confidence * 100).toFixed(0)}%</div>` : '';

  card.innerHTML = `
    <div class="fix-header">
      <span class="fix-title">Line ${fix.line} - ${escHtml(fix.vulnerability_id)}</span>
      <span class="fix-badge">✓ Fixed</span>
    </div>
    <div class="fix-comparison">
      <div class="fix-code-block">
        <div class="fix-code-label">❌ Original (Vulnerable)</div>
        <code>${escHtml(fix.original)}</code>
      </div>
      <div class="fix-code-block">
        <div class="fix-code-label">✅ Fixed (Secure)</div>
        <code>${escHtml(fix.fixed)}</code>
      </div>
    </div>
    ${mlTechnique}
    ${confidence}
    <div class="fix-explanation">
      <strong>🤖 AI Explanation:</strong> ${escHtml(fix.explanation)}
    </div>
  `;

  return card;
}

// ─── Code Comparison ──────────────────────────────────────────────────────────
function renderCodeComparison(originalCode, fixedCode) {
  codeOriginalContent.textContent = originalCode;
  codeFixedContent.textContent = fixedCode;
  diffOriginalContent.textContent = originalCode;
  diffFixedContent.textContent = fixedCode;
}

// Tab switching for code comparison
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const tab = btn.dataset.tab;
    
    // Update active tab
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('tab-btn--active'));
    btn.classList.add('tab-btn--active');
    
    // Show corresponding panel
    document.getElementById('code-original').hidden = tab !== 'original';
    document.getElementById('code-fixed').hidden = tab !== 'fixed';
    document.getElementById('code-diff').hidden = tab !== 'diff';
  });
});

// Download fixed code
downloadFixedBtn.addEventListener('click', () => {
  if (!currentAnalysisData) {
    showToast('No analysis data available', 'error');
    return;
  }
  
  const fixedCode = currentAnalysisData.ml_fixed_code || currentAnalysisData.fixed_code;
  if (!fixedCode) {
    showToast('No fixed code available', 'error');
    return;
  }

  const blob = new Blob([fixedCode], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `fixed_${currentAnalysisData.filename}`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  
  showToast('Fixed code downloaded successfully!', 'success');
});

// Export full report as JSON
exportJsonBtn.addEventListener('click', () => {
  if (!currentAnalysisData) {
    showToast('No analysis data available', 'error');
    return;
  }

  const report = {
    filename: currentAnalysisData.filename,
    timestamp: new Date().toISOString(),
    summary: currentAnalysisData.summary,
    vulnerabilities: currentAnalysisData.vulnerabilities,
    fixes: currentAnalysisData.fixes,
    symbol_table: currentAnalysisData.symbol_table,
    stats: currentAnalysisData.stats
  };

  const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `report_${currentAnalysisData.filename.replace('.py', '')}_${Date.now()}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  
  showToast('Report exported successfully!', 'success');
});


// ─── Visual Dashboard (Chart.js) ─────────────────────────────────────────────
function renderDashboard(data) {
  if (typeof Chart === 'undefined' || !dashboardSection) return;
  dashboardSection.hidden = false;

  const summary = data.summary || {};
  const vulns   = Array.isArray(data.vulnerabilities) ? data.vulnerabilities : [];
  const symbols = data.symbol_table || {};

  // Shared options
  const baseFont = { family: "'Inter', sans-serif", size: 12 };
  const palette = {
    high:      '#dc2626',
    medium:    '#ea580c',
    filtered:  '#94a3b8',
    tainted:   '#dc2626',
    untainted: '#059669',
    sanitized: '#0891b2',
    unknown:   '#6b7280',
    bar:       '#2563eb',
  };

  // ── 1. Severity doughnut ───────────────────────────────────────────────
  const sevHigh     = Number(summary.high_severity   || 0);
  const sevMedium   = Number(summary.medium_severity || 0);
  const sevFiltered = Number(summary.filtered        || 0);

  if (chartSeverity) chartSeverity.destroy();
  chartSeverity = new Chart(document.getElementById('chart-severity'), {
    type: 'doughnut',
    data: {
      labels: ['High severity', 'Medium severity', 'Filtered out'],
      datasets: [{
        data: [sevHigh, sevMedium, sevFiltered],
        backgroundColor: [palette.high, palette.medium, palette.filtered],
        borderColor: '#ffffff',
        borderWidth: 3,
        hoverOffset: 8,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '62%',
      plugins: {
        legend: { position: 'bottom', labels: { font: baseFont, padding: 14, usePointStyle: true } },
        tooltip: {
          callbacks: {
            label: (ctx) => `${ctx.label}: ${ctx.parsed} ${ctx.parsed === 1 ? 'issue' : 'issues'}`,
          },
        },
      },
    },
  });

  // ── 2. Taint state pie ─────────────────────────────────────────────────
  const taintCounts = { TAINTED: 0, UNTAINTED: 0, SANITIZED: 0, UNKNOWN: 0 };
  Object.values(symbols).forEach((s) => {
    const key = (typeof s === 'string' ? s : (s && s.value) || String(s)).toUpperCase();
    if (taintCounts.hasOwnProperty(key)) taintCounts[key]++;
    else taintCounts.UNKNOWN++;
  });

  if (chartTaint) chartTaint.destroy();
  chartTaint = new Chart(document.getElementById('chart-taint'), {
    type: 'doughnut',
    data: {
      labels: ['Tainted (risky)', 'Safe', 'Sanitized (cleaned)', 'Unknown'],
      datasets: [{
        data: [taintCounts.TAINTED, taintCounts.UNTAINTED, taintCounts.SANITIZED, taintCounts.UNKNOWN],
        backgroundColor: [palette.tainted, palette.untainted, palette.sanitized, palette.unknown],
        borderColor: '#ffffff',
        borderWidth: 3,
        hoverOffset: 8,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '62%',
      plugins: {
        legend: { position: 'bottom', labels: { font: baseFont, padding: 14, usePointStyle: true } },
        tooltip: {
          callbacks: {
            label: (ctx) => `${ctx.label}: ${ctx.parsed} ${ctx.parsed === 1 ? 'variable' : 'variables'}`,
          },
        },
      },
    },
  });

  // ── 3. Sinks bar chart ─────────────────────────────────────────────────
  const sinkCounts = {};
  vulns.forEach((v) => {
    const sink = (v && v.sink) ? String(v.sink) : '(unknown)';
    sinkCounts[sink] = (sinkCounts[sink] || 0) + 1;
  });
  const sinkLabels = Object.keys(sinkCounts);
  const sinkData   = sinkLabels.map((k) => sinkCounts[k]);

  if (chartSinks) chartSinks.destroy();
  chartSinks = new Chart(document.getElementById('chart-sinks'), {
    type: 'bar',
    data: {
      labels: sinkLabels.length ? sinkLabels : ['No issues 🎉'],
      datasets: [{
        label: 'Issues found',
        data: sinkLabels.length ? sinkData : [0],
        backgroundColor: palette.bar,
        borderRadius: 8,
        maxBarThickness: 48,
      }],
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: (ctx) => ` ${ctx.parsed.x} ${ctx.parsed.x === 1 ? 'issue' : 'issues'}`,
          },
        },
      },
      scales: {
        x: {
          beginAtZero: true,
          ticks: { precision: 0, font: baseFont, color: '#475569' },
          grid: { color: 'rgba(148, 163, 184, 0.2)' },
        },
        y: {
          ticks: { font: baseFont, color: '#0f172a' },
          grid: { display: false },
        },
      },
    },
  });
}
