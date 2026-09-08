const state = {
  analysisId: null,
  report: null,
  selectedFingerprint: null
};

const els = {
  snapshotFile: document.getElementById('snapshotFile'),
  analyzeButton: document.getElementById('analyzeButton'),
  message: document.getElementById('message'),
  workspace: document.getElementById('workspace'),
  summaryGrid: document.getElementById('summaryGrid'),
  snapshotId: document.getElementById('snapshotId'),
  snapshotCompleted: document.getElementById('snapshotCompleted'),
  rulePack: document.getElementById('rulePack'),
  findingSearch: document.getElementById('findingSearch'),
  severityFilter: document.getElementById('severityFilter'),
  findingCount: document.getElementById('findingCount'),
  findingList: document.getElementById('findingList'),
  findingDetail: document.getElementById('findingDetail'),
  coverageBody: document.getElementById('coverageBody'),
  unknownList: document.getElementById('unknownList'),
  exportJson: document.getElementById('exportJson'),
  exportHtml: document.getElementById('exportHtml'),
  hostStatus: document.getElementById('hostStatus')
};

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function formatDate(value) {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function severityRank(severity) {
  return { Critical: 5, High: 4, Medium: 3, Low: 2, Informational: 1 }[severity] ?? 0;
}

function severityClass(severity) {
  return `severity-${String(severity ?? 'unknown').toLowerCase()}`;
}

function setMessage(text, kind = '') {
  els.message.textContent = text;
  els.message.className = `message ${kind}`.trim();
}

async function loadStatus() {
  try {
    const response = await fetch('/api/status', { cache: 'no-store' });
    if (!response.ok) return;
    const status = await response.json();
    els.hostStatus.textContent = `${status.mode} · ${status.bind}`;
  } catch {
    els.hostStatus.textContent = 'Local UI';
  }
}

async function analyzeSelectedSnapshot() {
  const file = els.snapshotFile.files?.[0];
  if (!file) {
    setMessage('Choose a .dogad snapshot first.', 'error');
    return;
  }
  if (!file.name.toLowerCase().endsWith('.dogad')) {
    setMessage('The selected file must use the .dogad extension.', 'error');
    return;
  }

  els.analyzeButton.disabled = true;
  setMessage(`Analyzing ${file.name}…`, 'working');

  try {
    const response = await fetch('/api/analyze', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/octet-stream',
        'X-Dogfighter-Filename': file.name
      },
      body: file
    });

    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.code || payload.error || 'analysis-failed');
    }

    state.analysisId = payload.analysisId;
    state.report = payload.report;
    state.selectedFingerprint = payload.report.findings?.[0]?.fingerprint ?? null;
    renderReport();
    setMessage(`Analysis complete: ${payload.report.findings.length} findings.`, 'success');
  } catch (error) {
    state.analysisId = null;
    state.report = null;
    setMessage(`Analysis failed: ${error.message}`, 'error');
  } finally {
    els.analyzeButton.disabled = false;
  }
}

function renderReport() {
  const report = state.report;
  if (!report) return;

  els.workspace.classList.remove('hidden');
  els.snapshotId.textContent = report.snapshotId;
  els.snapshotCompleted.textContent = formatDate(report.snapshotCompletedAt);
  els.rulePack.textContent = `${report.rulePackId} ${report.rulePackVersion}`;

  renderSummary(report);
  renderFindings();
  renderCoverage(report.coverage ?? []);
  renderUnknowns(report.evaluations ?? []);
}

function renderSummary(report) {
  const counts = new Map();
  for (const finding of report.findings ?? []) {
    counts.set(finding.severity, (counts.get(finding.severity) ?? 0) + 1);
  }
  const notVerified = (report.evaluations ?? []).filter(item => item.outcome === 'NotVerified').length;

  const cards = [
    ['Completion', report.completion, report.completion === 'Complete' ? 'ok' : 'warn'],
    ['Critical', counts.get('Critical') ?? 0, 'critical'],
    ['High', counts.get('High') ?? 0, 'high'],
    ['Medium', counts.get('Medium') ?? 0, 'medium'],
    ['Low', counts.get('Low') ?? 0, 'low'],
    ['Not verified', notVerified, notVerified === 0 ? 'ok' : 'warn']
  ];

  els.summaryGrid.innerHTML = cards.map(([label, value, tone]) => `
    <article class="summary-card ${tone}">
      <span>${escapeHtml(label)}</span>
      <strong>${escapeHtml(value)}</strong>
    </article>
  `).join('');
}

function filteredFindings() {
  const findings = [...(state.report?.findings ?? [])]
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || a.title.localeCompare(b.title));
  const severity = els.severityFilter.value;
  const query = els.findingSearch.value.trim().toLowerCase();

  return findings.filter(finding => {
    if (severity !== 'all' && finding.severity !== severity) return false;
    if (!query) return true;
    const objectText = (finding.affectedObjects ?? [])
      .flatMap(object => [object.displayName, object.distinguishedName, object.stableId])
      .filter(Boolean)
      .join(' ');
    return `${finding.ruleId} ${finding.title} ${finding.description} ${objectText}`.toLowerCase().includes(query);
  });
}

function renderFindings() {
  const findings = filteredFindings();
  els.findingCount.textContent = `${findings.length} shown`;

  if (findings.length === 0) {
    els.findingList.innerHTML = '<div class="empty-state">No findings match the current filters.</div>';
    els.findingDetail.innerHTML = '<div class="empty-state">Select another filter or search term.</div>';
    return;
  }

  if (!findings.some(item => item.fingerprint === state.selectedFingerprint)) {
    state.selectedFingerprint = findings[0].fingerprint;
  }

  els.findingList.innerHTML = findings.map(finding => {
    const selected = finding.fingerprint === state.selectedFingerprint ? 'selected' : '';
    const subject = finding.affectedObjects?.[0]?.displayName
      || finding.affectedObjects?.[0]?.distinguishedName
      || finding.affectedObjects?.[0]?.stableId
      || 'Snapshot scope';
    return `
      <button class="finding-row ${selected}" data-fingerprint="${escapeHtml(finding.fingerprint)}" type="button">
        <span class="severity-badge ${severityClass(finding.severity)}">${escapeHtml(finding.severity)}</span>
        <span class="finding-row-main">
          <strong>${escapeHtml(finding.title)}</strong>
          <small>${escapeHtml(finding.ruleId)} · ${escapeHtml(subject)}</small>
        </span>
      </button>
    `;
  }).join('');

  for (const button of els.findingList.querySelectorAll('[data-fingerprint]')) {
    button.addEventListener('click', () => {
      state.selectedFingerprint = button.dataset.fingerprint;
      renderFindings();
    });
  }

  const selected = findings.find(item => item.fingerprint === state.selectedFingerprint) ?? findings[0];
  renderFindingDetail(selected);
}

function renderFindingDetail(finding) {
  const objects = (finding.affectedObjects ?? []).map(object => `
    <li>
      <strong>${escapeHtml(object.displayName || object.stableId)}</strong>
      ${object.distinguishedName ? `<code>${escapeHtml(object.distinguishedName)}</code>` : ''}
      <small>${escapeHtml(object.kind)} · ${escapeHtml(object.stableId)}</small>
    </li>
  `).join('') || '<li>Snapshot scope</li>';

  const evidence = (finding.evidence ?? []).map(item => `
    <tr>
      <td><code>${escapeHtml(item.path)}</code><small>${escapeHtml(item.factId || '')}</small></td>
      <td>${escapeHtml(item.value ?? '—')}</td>
      <td>${escapeHtml(item.source)}<small>${escapeHtml(item.collectorId)} ${escapeHtml(item.collectorVersion)}<br>${escapeHtml(formatDate(item.observedAt))}</small></td>
    </tr>
  `).join('') || '<tr><td colspan="3">No evidence rows attached.</td></tr>';

  els.findingDetail.innerHTML = `
    <div class="detail-heading">
      <span class="severity-badge ${severityClass(finding.severity)}">${escapeHtml(finding.severity)}</span>
      <div>
        <h2>${escapeHtml(finding.title)}</h2>
        <code>${escapeHtml(finding.ruleId)}</code>
      </div>
    </div>
    <div class="detail-meta">
      <span>Status <strong>${escapeHtml(finding.status)}</strong></span>
      <span>Confidence <strong>${escapeHtml(finding.confidence)}</strong></span>
      <span>Validation <strong>${escapeHtml(finding.validationStatus)}</strong></span>
    </div>
    <h3>Description</h3>
    <p>${escapeHtml(finding.description)}</p>
    <h3>Risk</h3>
    <p>${escapeHtml(finding.risk)}</p>
    <h3>Remediation</h3>
    <p>${escapeHtml(finding.remediation)}</p>
    <h3>Affected objects</h3>
    <ul class="object-list">${objects}</ul>
    <h3>Evidence</h3>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Fact/path</th><th>Value</th><th>Provenance</th></tr></thead>
        <tbody>${evidence}</tbody>
      </table>
    </div>
    <details class="fingerprint"><summary>Fingerprint</summary><code>${escapeHtml(finding.fingerprint)}</code></details>
  `;
}

function renderCoverage(coverage) {
  els.coverageBody.innerHTML = coverage.map(item => {
    const issues = (item.issues ?? []).map(issue => issue.code ?? issue).join(', ');
    return `
      <tr>
        <td><code>${escapeHtml(item.capabilityId)}</code><small>${escapeHtml(item.collectorId ?? '')}</small></td>
        <td><span class="status-pill status-${String(item.status).toLowerCase()}">${escapeHtml(item.status)}</span></td>
        <td>${escapeHtml(item.contractVersion ?? '—')}</td>
        <td>${escapeHtml(item.observedItemCount ?? '—')}</td>
        <td>${escapeHtml(issues || '—')}</td>
      </tr>
    `;
  }).join('');
}

function renderUnknowns(evaluations) {
  const unknowns = evaluations.filter(item => item.outcome === 'NotVerified' || item.outcome === 'Error');
  if (unknowns.length === 0) {
    els.unknownList.innerHTML = '<div class="empty-state">No NotVerified or Error evaluations.</div>';
    return;
  }

  els.unknownList.innerHTML = unknowns.map(item => {
    const subject = item.subject?.displayName || item.subject?.distinguishedName || item.subject?.stableId || 'Snapshot scope';
    const gaps = (item.missingData ?? []).map(gap => `
      <li><code>${escapeHtml(gap.path)}</code> — ${escapeHtml(gap.code)} <small>${escapeHtml(gap.capabilityId)}</small></li>
    `).join('');
    return `
      <details class="unknown-row">
        <summary><strong>${escapeHtml(item.ruleId)}</strong> · ${escapeHtml(subject)} · ${escapeHtml(item.outcome)}</summary>
        <p>${escapeHtml(item.message)}</p>
        ${gaps ? `<ul>${gaps}</ul>` : ''}
      </details>
    `;
  }).join('');
}

function activateTab(name) {
  for (const button of document.querySelectorAll('.tab')) {
    button.classList.toggle('active', button.dataset.tab === name);
  }
  for (const page of document.querySelectorAll('.tab-page')) {
    page.classList.toggle('active', page.id === `tab-${name}`);
  }
}

function exportAnalysis(format) {
  if (!state.analysisId) return;
  window.location.href = `/api/analyses/${state.analysisId}/${format}`;
}

els.analyzeButton.addEventListener('click', analyzeSelectedSnapshot);
els.findingSearch.addEventListener('input', renderFindings);
els.severityFilter.addEventListener('change', renderFindings);
els.exportJson.addEventListener('click', () => exportAnalysis('json'));
els.exportHtml.addEventListener('click', () => exportAnalysis('html'));
for (const button of document.querySelectorAll('.tab')) {
  button.addEventListener('click', () => activateTab(button.dataset.tab));
}

loadStatus();
