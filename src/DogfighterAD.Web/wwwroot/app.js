const state = {
  analysisId: null,
  report: null,
  selectedFingerprint: null,
  assessmentId: null,
  pollTimer: null
};

const els = {
  assessmentForm: document.getElementById('assessmentForm'),
  assessmentTarget: document.getElementById('assessmentTarget'),
  assessmentProfile: document.getElementById('assessmentProfile'),
  authenticationMode: document.getElementById('authenticationMode'),
  explicitCredentialFields: document.getElementById('explicitCredentialFields'),
  assessmentUsername: document.getElementById('assessmentUsername'),
  assessmentPassword: document.getElementById('assessmentPassword'),
  ldapAuthMode: document.getElementById('ldapAuthMode'),
  useLdaps: document.getElementById('useLdaps'),
  ldapPort: document.getElementById('ldapPort'),
  sysvolAuthorities: document.getElementById('sysvolAuthorities'),
  startAssessment: document.getElementById('startAssessment'),
  cancelAssessment: document.getElementById('cancelAssessment'),
  assessmentProgressPanel: document.getElementById('assessmentProgressPanel'),
  assessmentState: document.getElementById('assessmentState'),
  assessmentMeta: document.getElementById('assessmentMeta'),
  assessmentMessage: document.getElementById('assessmentMessage'),
  collectorProgress: document.getElementById('collectorProgress'),
  snapshotDownload: document.getElementById('snapshotDownload'),
  snapshotFile: document.getElementById('snapshotFile'),
  analyzeButton: document.getElementById('analyzeButton'),
  importMessage: document.getElementById('importMessage'),
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

function setImportMessage(text, kind = '') {
  els.importMessage.textContent = text;
  els.importMessage.className = `message ${kind}`.trim();
}

function setAssessmentMessage(text, kind = '') {
  els.assessmentMessage.textContent = text;
  els.assessmentMessage.className = `message ${kind}`.trim();
}

function updateAuthenticationFields() {
  const explicit = els.authenticationMode.value === 'explicit';
  els.explicitCredentialFields.classList.toggle('hidden', !explicit);
  els.assessmentUsername.required = explicit;
  els.assessmentPassword.required = explicit;
  if (!explicit && els.ldapAuthMode.value === 'ntlm') els.ldapAuthMode.value = 'negotiate';
  els.ldapAuthMode.querySelector('option[value="ntlm"]').disabled = !explicit;
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

async function startAssessment(event) {
  event.preventDefault();
  const target = els.assessmentTarget.value.trim();
  if (!target) {
    setAssessmentMessage('Enter a target DC or domain.', 'error');
    return;
  }

  const explicit = els.authenticationMode.value === 'explicit';
  if (explicit && (!els.assessmentUsername.value.trim() || !els.assessmentPassword.value)) {
    setAssessmentMessage('Explicit authentication requires username and password.', 'error');
    return;
  }

  const parsedPort = els.ldapPort.value ? Number.parseInt(els.ldapPort.value, 10) : null;
  if (parsedPort !== null && (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535)) {
    setAssessmentMessage('LDAP port must be between 1 and 65535.', 'error');
    return;
  }

  const payload = {
    target,
    profile: els.assessmentProfile.value,
    authentication: els.authenticationMode.value,
    username: explicit ? els.assessmentUsername.value.trim() : null,
    password: explicit ? els.assessmentPassword.value : null,
    ldapAuth: els.ldapAuthMode.value,
    useLdaps: els.useLdaps.checked,
    ldapPort: parsedPort,
    sysvolAuthorities: els.sysvolAuthorities.value.split(',').map(value => value.trim()).filter(Boolean)
  };

  const requestBody = JSON.stringify(payload);
  payload.password = null;
  els.assessmentPassword.value = '';
  els.startAssessment.disabled = true;
  els.cancelAssessment.classList.add('hidden');
  els.assessmentProgressPanel.classList.remove('hidden');
  els.snapshotDownload.classList.add('hidden');
  els.collectorProgress.innerHTML = '';
  els.assessmentState.textContent = 'Starting assessment…';
  els.assessmentMeta.textContent = `${target} · ${els.assessmentProfile.value}`;
  setAssessmentMessage('Creating local assessment session…', 'working');

  try {
    const response = await fetch('/api/assessments', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: requestBody
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'assessment-start-failed');

    state.assessmentId = result.assessmentId;
    els.cancelAssessment.classList.remove('hidden');
    setAssessmentMessage('Collection started. Progress updates appear below.', 'working');
    scheduleAssessmentPoll(0);
  } catch (error) {
    state.assessmentId = null;
    els.startAssessment.disabled = false;
    setAssessmentMessage(`Could not start assessment: ${error.message}`, 'error');
  }
}

function scheduleAssessmentPoll(delay = 750) {
  if (state.pollTimer) clearTimeout(state.pollTimer);
  state.pollTimer = setTimeout(pollAssessment, delay);
}

async function pollAssessment() {
  if (!state.assessmentId) return;
  try {
    const response = await fetch(`/api/assessments/${state.assessmentId}`, { cache: 'no-store' });
    const status = await response.json();
    if (!response.ok) throw new Error(status.error || 'assessment-status-failed');
    renderAssessmentStatus(status);

    if (status.state === 'complete') {
      state.pollTimer = null;
      els.startAssessment.disabled = false;
      els.cancelAssessment.classList.add('hidden');
      await loadAssessmentAnalysis(status);
      return;
    }
    if (status.state === 'failed' || status.state === 'canceled') {
      state.pollTimer = null;
      els.startAssessment.disabled = false;
      els.cancelAssessment.classList.add('hidden');
      return;
    }
    scheduleAssessmentPoll();
  } catch (error) {
    setAssessmentMessage(`Assessment status error: ${error.message}`, 'error');
    scheduleAssessmentPoll(1500);
  }
}

function renderAssessmentStatus(status) {
  const labels = {
    queued: 'Queued',
    collecting: 'Collecting Active Directory',
    analyzing: 'Analyzing snapshot',
    complete: 'Assessment complete',
    failed: 'Assessment failed',
    canceled: 'Assessment canceled'
  };
  els.assessmentState.textContent = labels[status.state] || status.state;
  const snapshotText = status.snapshotStatus ? ` · snapshot ${status.snapshotStatus}` : '';
  els.assessmentMeta.textContent = `${status.target} · ${status.profile}${snapshotText}`;

  if (status.snapshotPath) {
    els.snapshotDownload.href = `/api/assessments/${status.assessmentId}/snapshot`;
    els.snapshotDownload.classList.remove('hidden');
  }

  if (status.state === 'failed') {
    setAssessmentMessage(`Assessment failed: ${status.error || 'unknown error'}`, 'error');
  } else if (status.state === 'canceled') {
    setAssessmentMessage('Assessment canceled. A verified snapshot remains available only if collection had already finished.', 'error');
  } else if (status.state === 'analyzing') {
    setAssessmentMessage('Snapshot saved and verified. Running the offline Rule Engine…', 'working');
  } else if (status.state === 'complete') {
    setAssessmentMessage(`Assessment complete. Snapshot saved at ${status.snapshotPath || 'local assessment storage'}.`, 'success');
  }

  renderCollectorProgress(status.progress ?? []);
}

function renderCollectorProgress(progress) {
  if (progress.length === 0) {
    els.collectorProgress.innerHTML = '<div class="empty-progress">Waiting for collector progress…</div>';
    return;
  }
  els.collectorProgress.innerHTML = progress.map(item => `
    <div class="collector-row">
      <span class="collector-state state-${String(item.state).toLowerCase()}">${escapeHtml(item.state)}</span>
      <strong>${escapeHtml(item.collectorId)}</strong>
      <small>${item.elapsed ? `elapsed ${escapeHtml(item.elapsed)}` : ''}${item.issueCode ? ` · ${escapeHtml(item.issueCode)}` : ''}</small>
    </div>
  `).join('');
}

async function loadAssessmentAnalysis(status) {
  if (!status.analysisId) {
    setAssessmentMessage('Collection completed but the analysis ID is missing.', 'error');
    return;
  }
  const response = await fetch(`/api/analyses/${status.analysisId}`, { cache: 'no-store' });
  const report = await response.json();
  if (!response.ok) {
    setAssessmentMessage('Analysis completed but the report could not be loaded.', 'error');
    return;
  }
  state.analysisId = status.analysisId;
  state.report = report;
  state.selectedFingerprint = report.findings?.[0]?.fingerprint ?? null;
  renderReport();
  setAssessmentMessage(`Assessment complete: ${report.findings.length} findings.`, 'success');
  window.scrollTo({ top: els.workspace.offsetTop - 80, behavior: 'smooth' });
}

async function cancelAssessment() {
  if (!state.assessmentId) return;
  els.cancelAssessment.disabled = true;
  try {
    const response = await fetch(`/api/assessments/${state.assessmentId}/cancel`, { method: 'POST' });
    if (!response.ok && response.status !== 409) {
      const result = await response.json();
      throw new Error(result.error || 'cancel-failed');
    }
    setAssessmentMessage('Cancellation requested…', 'working');
    scheduleAssessmentPoll(0);
  } catch (error) {
    setAssessmentMessage(`Could not cancel assessment: ${error.message}`, 'error');
  } finally {
    els.cancelAssessment.disabled = false;
  }
}

async function analyzeSelectedSnapshot() {
  const file = els.snapshotFile.files?.[0];
  if (!file) {
    setImportMessage('Choose a .dogad snapshot first.', 'error');
    return;
  }
  if (!file.name.toLowerCase().endsWith('.dogad')) {
    setImportMessage('The selected file must use the .dogad extension.', 'error');
    return;
  }

  els.analyzeButton.disabled = true;
  setImportMessage(`Analyzing ${file.name}…`, 'working');

  try {
    const response = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream', 'X-Dogfighter-Filename': file.name },
      body: file
    });

    const payload = await response.json();
    if (!response.ok) throw new Error(payload.code || payload.error || 'analysis-failed');

    state.analysisId = payload.analysisId;
    state.report = payload.report;
    state.selectedFingerprint = payload.report.findings?.[0]?.fingerprint ?? null;
    renderReport();
    setImportMessage(`Analysis complete: ${payload.report.findings.length} findings.`, 'success');
  } catch (error) {
    state.analysisId = null;
    state.report = null;
    setImportMessage(`Analysis failed: ${error.message}`, 'error');
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
  for (const finding of report.findings ?? []) counts.set(finding.severity, (counts.get(finding.severity) ?? 0) + 1);
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
    <article class="summary-card ${tone}"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></article>
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
  if (!findings.some(item => item.fingerprint === state.selectedFingerprint)) state.selectedFingerprint = findings[0].fingerprint;
  els.findingList.innerHTML = findings.map(finding => {
    const selected = finding.fingerprint === state.selectedFingerprint ? 'selected' : '';
    const subject = finding.affectedObjects?.[0]?.displayName || finding.affectedObjects?.[0]?.distinguishedName || finding.affectedObjects?.[0]?.stableId || 'Snapshot scope';
    return `
      <button class="finding-row ${selected}" data-fingerprint="${escapeHtml(finding.fingerprint)}" type="button">
        <span class="severity-badge ${severityClass(finding.severity)}">${escapeHtml(finding.severity)}</span>
        <span class="finding-row-main"><strong>${escapeHtml(finding.title)}</strong><small>${escapeHtml(finding.ruleId)} · ${escapeHtml(subject)}</small></span>
      </button>`;
  }).join('');
  for (const button of els.findingList.querySelectorAll('[data-fingerprint]')) {
    button.addEventListener('click', () => { state.selectedFingerprint = button.dataset.fingerprint; renderFindings(); });
  }
  renderFindingDetail(findings.find(item => item.fingerprint === state.selectedFingerprint) ?? findings[0]);
}

function renderFindingDetail(finding) {
  const objects = (finding.affectedObjects ?? []).map(object => `
    <li><strong>${escapeHtml(object.displayName || object.stableId)}</strong>${object.distinguishedName ? `<code>${escapeHtml(object.distinguishedName)}</code>` : ''}<small>${escapeHtml(object.kind)} · ${escapeHtml(object.stableId)}</small></li>
  `).join('') || '<li>Snapshot scope</li>';
  const evidence = (finding.evidence ?? []).map(item => `
    <tr><td><code>${escapeHtml(item.path)}</code><small>${escapeHtml(item.factId || '')}</small></td><td>${escapeHtml(item.value ?? '—')}</td><td>${escapeHtml(item.source)}<small>${escapeHtml(item.collectorId)} ${escapeHtml(item.collectorVersion)}<br>${escapeHtml(formatDate(item.observedAt))}</small></td></tr>
  `).join('') || '<tr><td colspan="3">No evidence rows attached.</td></tr>';
  els.findingDetail.innerHTML = `
    <div class="detail-heading"><span class="severity-badge ${severityClass(finding.severity)}">${escapeHtml(finding.severity)}</span><div><h2>${escapeHtml(finding.title)}</h2><code>${escapeHtml(finding.ruleId)}</code></div></div>
    <div class="detail-meta"><span>Status <strong>${escapeHtml(finding.status)}</strong></span><span>Confidence <strong>${escapeHtml(finding.confidence)}</strong></span><span>Validation <strong>${escapeHtml(finding.validationStatus)}</strong></span></div>
    <h3>Description</h3><p>${escapeHtml(finding.description)}</p><h3>Risk</h3><p>${escapeHtml(finding.risk)}</p><h3>Remediation</h3><p>${escapeHtml(finding.remediation)}</p>
    <h3>Affected objects</h3><ul class="object-list">${objects}</ul><h3>Evidence</h3><div class="table-wrap"><table><thead><tr><th>Fact/path</th><th>Value</th><th>Provenance</th></tr></thead><tbody>${evidence}</tbody></table></div>
    <details class="fingerprint"><summary>Fingerprint</summary><code>${escapeHtml(finding.fingerprint)}</code></details>`;
}

function renderCoverage(coverage) {
  els.coverageBody.innerHTML = coverage.map(item => {
    const issues = (item.issues ?? []).map(issue => issue.code ?? issue).join(', ');
    return `<tr><td><code>${escapeHtml(item.capabilityId)}</code><small>${escapeHtml(item.collectorId ?? '')}</small></td><td><span class="status-pill status-${String(item.status).toLowerCase()}">${escapeHtml(item.status)}</span></td><td>${escapeHtml(item.contractVersion ?? '—')}</td><td>${escapeHtml(item.observedItemCount ?? '—')}</td><td>${escapeHtml(issues || '—')}</td></tr>`;
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
    const gaps = (item.missingData ?? []).map(gap => `<li><code>${escapeHtml(gap.path)}</code> — ${escapeHtml(gap.code)} <small>${escapeHtml(gap.capabilityId)}</small></li>`).join('');
    return `<details class="unknown-row"><summary><strong>${escapeHtml(item.ruleId)}</strong> · ${escapeHtml(subject)} · ${escapeHtml(item.outcome)}</summary><p>${escapeHtml(item.message)}</p>${gaps ? `<ul>${gaps}</ul>` : ''}</details>`;
  }).join('');
}

function activateTab(name) {
  for (const button of document.querySelectorAll('.tab')) button.classList.toggle('active', button.dataset.tab === name);
  for (const page of document.querySelectorAll('.tab-page')) page.classList.toggle('active', page.id === `tab-${name}`);
}

function exportAnalysis(format) {
  if (state.analysisId) window.location.href = `/api/analyses/${state.analysisId}/${format}`;
}

els.assessmentForm.addEventListener('submit', startAssessment);
els.authenticationMode.addEventListener('change', updateAuthenticationFields);
els.cancelAssessment.addEventListener('click', cancelAssessment);
els.analyzeButton.addEventListener('click', analyzeSelectedSnapshot);
els.findingSearch.addEventListener('input', renderFindings);
els.severityFilter.addEventListener('change', renderFindings);
els.exportJson.addEventListener('click', () => exportAnalysis('json'));
els.exportHtml.addEventListener('click', () => exportAnalysis('html'));
for (const button of document.querySelectorAll('.tab')) button.addEventListener('click', () => activateTab(button.dataset.tab));

updateAuthenticationFields();
loadStatus();
