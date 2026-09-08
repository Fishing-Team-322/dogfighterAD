const state = {
  analysisId: null,
  report: null,
  selectedFingerprint: null,
  assessmentId: null,
  pollTimer: null
};

const uiState = { section: 'overview', technicalSection: 'coverage', evidencePage: 0 };

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
  statusFilter: document.getElementById('statusFilter'),
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
  return `severity-${cssToken(severity ?? 'unknown')}`;
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
      <span class="collector-state state-${cssToken(item.state)}">${escapeHtml(item.state)}</span>
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
  // The workspace route is selected by renderReport; collection remains in Import / Assessment.
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
    resetAnalysisView();
    setImportMessage(`Analysis failed: ${error.message}`, 'error');
  } finally {
    els.analyzeButton.disabled = false;
  }
}

function renderReport() {
  const report = state.report;
  if (!report) return;
  // Only view state is changed here. Report data is not modified or re-evaluated.
  setWorkspaceAvailable(true);
  els.snapshotId.textContent = report.snapshotId;
  els.snapshotCompleted.textContent = formatDate(report.snapshotCompletedAt);
  els.rulePack.textContent = `${report.rulePackId} ${report.rulePackVersion}`;
  document.getElementById('headerContext').textContent = `Snapshot ${String(report.snapshotId).slice(0, 8)}`;
  document.getElementById('sessionLabel').textContent = String(report.snapshotId);
  document.getElementById('sessionLabel').classList.add('mono');
  document.getElementById('sessionCompletion').textContent = `Analysis ${report.completion} · ${formatDate(report.snapshotCompletedAt)}`;
  document.getElementById('analysisCompletion').innerHTML = statusBadge(report.completion, 'Analysis');
  const badge = document.getElementById('navFindingCount');
  badge.textContent = (report.findings ?? []).length;
  badge.classList.remove('hidden');
  const selectedStatus = els.statusFilter.value;
  const statuses = [...new Set((report.findings ?? []).map(item => item.status))].sort();
  els.statusFilter.innerHTML = '<option value="all">All statuses</option>' + statuses.map(value => `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`).join('');
  els.statusFilter.value = statuses.includes(selectedStatus) ? selectedStatus : 'all';
  renderSummary(report);
  renderFindings();
  renderCoverage(report.coverage ?? []);
  renderUnknowns(report.evaluations ?? []);
  uiState.evidencePage = 0;
  document.getElementById('evidenceSearch').value = '';
  document.getElementById('evidenceBody').replaceChildren();
  document.getElementById('findingLayout').classList.remove('detail-open');
  if (typeof certificateServicesState !== 'undefined') resetCertificateServices();
  activateTab('overview', { focus: true });
}

function renderSummary(report) {
  renderDashboard(report, null);
}

function renderDashboard(report, summary) {
  const counts = new Map();
  for (const finding of report.findings ?? []) counts.set(finding.severity, (counts.get(finding.severity) ?? 0) + 1);
  const notVerified = (report.evaluations ?? []).filter(item => item.outcome === 'NotVerified' || item.outcome === 'Error').length;
  // Posture and priority copy come exclusively from the server presentation endpoint.
  const cards = ['Critical', 'High', 'Medium', 'Low', 'Informational'].map(label =>
    [label, summary && label !== 'Informational' ? summary[label.toLowerCase()] ?? 0 : counts.get(label) ?? 0, label.toLowerCase()]);
  cards.push(['Not verified / Errors', summary?.notVerified ?? notVerified, 'warn']);
  els.summaryGrid.innerHTML = `
    <article class="summary-card posture"><span>Overall posture</span><strong>${escapeHtml(summary?.overallPosture ?? 'Presentation unavailable')}</strong><div class="posture-context"><p>${summary ? 'From the server-generated assessment summary.' : 'No posture is inferred without the presentation response.'}</p>${statusBadge(report.completion, 'Analysis')}<p class="boundary-note">No findings emitted does not establish that the directory is secure.</p></div></article>
    <article class="summary-card priorities"><span>Top priorities</span>${summary?.topPriorities?.length ? `<ol>${summary.topPriorities.map(item => `<li>${escapeHtml(item)}</li>`).join('')}</ol>` : `<p class="muted">${summary ? 'No finding priorities emitted.' : 'Server presentation is not available. Inspect the original findings below.'}</p>`}</article>
    ${cards.map(([label, value, tone]) => `<article class="summary-card ${tone}"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></article>`).join('')}`;
  const top = [...(report.findings ?? [])].sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || a.title.localeCompare(b.title)).slice(0, 5);
  document.getElementById('overviewFindings').innerHTML = top.length ? top.map(finding => {
    const item = typeof presentationFor === 'function' ? presentationFor(finding.fingerprint) : null;
    return `<button type="button" class="overview-row" data-open-finding="${escapeHtml(finding.fingerprint)}"><span class="severity-badge ${severityClass(finding.severity)}">${escapeHtml(finding.severity)}</span><span><strong>${escapeHtml(item?.customerTitle || finding.title)}</strong><small>${escapeHtml(finding.status)} · ${escapeHtml(item?.affectedObject?.displayName || findingSubject(finding))}</small></span><span aria-hidden="true">→</span></button>`;
  }).join('') : '<p class="empty-state compact">No findings emitted. Review coverage and unverified checks before drawing conclusions.</p>';
  const coverage = report.coverage ?? [];
  const incomplete = coverage.filter(item => item.status !== 'Complete' && item.status !== 'NotApplicable');
  const rows = [
    ['Capabilities in report', coverage.length], ['Partial / failed / other coverage', incomplete.length],
    ['Not verified evaluations', (report.evaluations ?? []).filter(item => item.outcome === 'NotVerified').length],
    ['Rule errors', (report.evaluations ?? []).filter(item => item.outcome === 'Error').length]
  ];
  document.getElementById('overviewCoverage').innerHTML = rows.map(([label, value]) => `<div class="coverage-stat"><span>${escapeHtml(label)}</span><strong>${value}</strong></div>`).join('');
}

function filteredFindings() {
  const findings = [...(state.report?.findings ?? [])]
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || a.title.localeCompare(b.title));
  const severity = els.severityFilter.value;
  const query = els.findingSearch.value.trim().toLowerCase();
  return findings.filter(finding => {
    if (severity !== 'all' && finding.severity !== severity) return false;
    if (els.statusFilter.value !== 'all' && finding.status !== els.statusFilter.value) return false;
    if (!query) return true;
    const objectText = (finding.affectedObjects ?? [])
      .flatMap(object => [object.displayName, object.distinguishedName, object.stableId])
      .filter(Boolean)
      .join(' ');
    const view = typeof presentationFor === 'function' ? presentationFor(finding.fingerprint) : null;
    return `${finding.ruleId} ${finding.title} ${finding.description} ${objectText} ${view?.customerTitle ?? ''} ${view?.summary ?? ''} ${(view?.keyEvidence ?? []).map(item => item.headline).join(' ')}`.toLowerCase().includes(query);
  });
}

function renderFindings() {
  renderFindingRows();
}

function renderFindingRows() {
  const findings = filteredFindings();
  els.findingCount.textContent = `${findings.length} / ${state.report?.findings?.length ?? 0} findings`;
  const focusedFingerprint = document.activeElement?.dataset?.fingerprint;
  const scrollTop = els.findingList.scrollTop;
  if (findings.length === 0) {
    els.findingList.innerHTML = '<div class="empty-state">No findings match the current filters.</div>';
    els.findingDetail.innerHTML = '<div class="empty-state">Select another filter or search term.</div>';
    document.getElementById('findingLayout').classList.remove('detail-open');
    return;
  }
  if (!findings.some(item => item.fingerprint === state.selectedFingerprint)) state.selectedFingerprint = findings[0].fingerprint;
  els.findingList.innerHTML = findings.map(finding => {
    const item = typeof presentationFor === 'function' ? presentationFor(finding.fingerprint) : null;
    const selected = finding.fingerprint === state.selectedFingerprint;
    const subject = item?.affectedObject?.displayName || findingSubject(finding);
    const reason = item?.keyEvidence?.[0]?.headline || item?.summary || finding.description;
    return `<button class="finding-row ${selected ? 'selected' : ''}" data-fingerprint="${escapeHtml(finding.fingerprint)}" type="button" aria-pressed="${selected}" aria-controls="findingDetail">
      <span class="finding-row-top"><span class="severity-badge ${severityClass(finding.severity)}">${escapeHtml(finding.severity)}</span>${statusBadge(finding.status)}<code>${escapeHtml(finding.ruleId)}</code></span>
      <span class="finding-row-main"><strong>${escapeHtml(item?.customerTitle || finding.title)}</strong><small>${escapeHtml(subject)}</small><span class="finding-key-reason">${escapeHtml(reason)}</span></span></button>`;
  }).join('');
  for (const button of els.findingList.querySelectorAll('[data-fingerprint]')) {
    button.addEventListener('click', () => {
      state.selectedFingerprint = button.dataset.fingerprint;
      if (typeof findingPresentationState !== 'undefined') findingPresentationState.mode = 'overview';
      renderFindings();
      document.getElementById('findingLayout').classList.add('detail-open');
      els.findingDetail.closest('.finding-detail-panel').scrollTop = 0;
      if (window.matchMedia('(max-width: 1000px)').matches) {
        els.findingDetail.focus({ preventScroll: true });
        els.findingDetail.scrollIntoView({ block: 'start' });
      }
    });
    if (button.dataset.fingerprint === focusedFingerprint) button.focus({ preventScroll: true });
  }
  els.findingList.scrollTop = scrollTop;
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
    <details class="disclosure"><summary>Affected objects (${(finding.affectedObjects ?? []).length})</summary><ul class="object-list">${objects}</ul></details><h3>Raw evidence</h3><div class="table-wrap"><table><thead><tr><th>Fact/path</th><th>Value</th><th>Provenance</th></tr></thead><tbody>${evidence}</tbody></table></div>
    <details class="fingerprint"><summary>Fingerprint</summary><code>${escapeHtml(finding.fingerprint)}</code></details>`;
}

function renderCoverage(coverage) {
  els.coverageBody.innerHTML = coverage.map(item => {
    const issues = (item.issues ?? []).map(issue => issue.code ?? issue).join(', ');
    return `<tr><td><code>${escapeHtml(item.capabilityId)}</code><small>${escapeHtml(item.collectorId ?? '')}</small></td><td><span class="status-pill status-${cssToken(item.status)}">${escapeHtml(item.status)}</span></td><td>${escapeHtml(item.contractVersion ?? '—')}</td><td>${escapeHtml(item.observedItemCount ?? '—')}</td><td>${escapeHtml(issues || '—')}</td></tr>`;
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

function activateTab(name, options = {}) {
  if (name === 'coverage' || name === 'unknowns' || name === 'evidence') {
    activateTechnicalSection(name);
    name = 'technical';
  }
  const sections = {
    overview: ['Overview', 'Security posture and priorities from the current snapshot.', 'Assessment'],
    findings: ['Findings', 'Review emitted findings, affected objects and their supporting evidence.', 'Analysis'],
    'certificate-services': ['Certificate Services', 'Enterprise CAs, certificate templates and directory-derived findings.', 'AD CS'],
    technical: ['Technical / Evidence', 'Collection coverage, unverified checks and original finding evidence.', 'Verification'],
    import: ['Import / Assessment', 'Collect a new snapshot or analyze an existing .dogad file locally.', 'Workflow']
  };
  if (!Object.hasOwn(sections, name)) name = 'overview';
  uiState.section = name;
  for (const button of document.querySelectorAll('.main-nav [data-tab]')) {
    const active = button.dataset.tab === name;
    button.classList.toggle('active', active);
    if (active) button.setAttribute('aria-current', 'page'); else button.removeAttribute('aria-current');
  }
  for (const page of document.querySelectorAll('.workspace > .tab-page')) page.classList.toggle('active', page.id === `tab-${name}`);
  const [title, description, context] = sections[name];
  document.getElementById('pageTitle').textContent = title;
  document.getElementById('pageDescription').textContent = description;
  document.getElementById('sectionContext').textContent = context;
  document.title = `${title} · DogfighterAD`;
  if (!options.fromHash && location.hash !== `#${name}`) history.pushState(null, '', `#${name}`);
  closeNavigation(false);
  if (options.focus) document.getElementById('pageTitle').focus({ preventScroll: true });
  if (name === 'technical' && uiState.technicalSection === 'evidence') renderEvidenceIndex();
  if (name === 'certificate-services' && typeof loadCertificateServices === 'function') void loadCertificateServices();
}

function activateTechnicalSection(name) {
  if (!['coverage', 'unknowns', 'evidence'].includes(name)) name = 'coverage';
  uiState.technicalSection = name;
  if (name === 'evidence') renderEvidenceIndex();
  for (const button of document.querySelectorAll('[data-technical]')) {
    const selected = button.dataset.technical === name;
    button.classList.toggle('active', selected);
    button.setAttribute('aria-selected', String(selected));
    button.tabIndex = selected ? 0 : -1;
  }
  for (const page of document.querySelectorAll('.technical-page')) page.classList.toggle('active', page.id === `tab-${name}`);
}

function cssToken(value) { return String(value ?? 'unknown').toLowerCase().replace(/[^a-z0-9-]/g, ''); }
function statusBadge(value, prefix = '') {
  return `<span class="status-pill status-${cssToken(value)}">${escapeHtml(prefix ? `${prefix}: ${value}` : value ?? 'Not provided')}</span>`;
}
function findingSubject(finding) {
  const object = finding.affectedObjects?.[0];
  return object?.displayName || object?.distinguishedName || object?.stableId || 'Snapshot scope';
}

function setWorkspaceAvailable(available) {
  for (const node of document.querySelectorAll('[data-report-content]')) node.classList.toggle('hidden', !available);
  for (const node of document.querySelectorAll('[data-report-empty]')) node.classList.toggle('hidden', available);
  document.getElementById('analysisCompletion').classList.toggle('hidden', !available);
  els.exportJson.disabled = !available;
  els.exportHtml.disabled = !available;
}

function resetAnalysisView() {
  setWorkspaceAvailable(false);
  state.selectedFingerprint = null;
  document.getElementById('headerContext').textContent = 'No snapshot selected';
  document.getElementById('sessionLabel').textContent = 'No snapshot loaded';
  document.getElementById('sessionLabel').classList.remove('mono');
  document.getElementById('sessionCompletion').textContent = 'Import or start an assessment.';
  document.getElementById('navFindingCount').classList.add('hidden');
  els.findingList.replaceChildren();
  els.findingDetail.replaceChildren();
  if (typeof findingPresentationState !== 'undefined') {
    findingPresentationState.analysisId = null;
    findingPresentationState.view = null;
  }
  if (typeof resetCertificateServices === 'function') resetCertificateServices();
}

function openFinding(fingerprint, mode = 'overview') {
  const finding = state.report?.findings?.find(item => item.fingerprint === fingerprint);
  if (!finding) return;
  els.findingSearch.value = '';
  els.severityFilter.value = 'all';
  els.statusFilter.value = 'all';
  state.selectedFingerprint = fingerprint;
  if (typeof findingPresentationState !== 'undefined') findingPresentationState.mode = mode;
  activateTab('findings');
  renderFindings();
  document.getElementById('findingLayout').classList.add('detail-open');
  els.findingDetail.closest('.finding-detail-panel').scrollTop = 0;
  els.findingDetail.focus({ preventScroll: true });
  els.findingDetail.scrollIntoView({ block: 'nearest' });
}

function renderEvidenceIndex() {
  const query = document.getElementById('evidenceSearch').value.trim().toLowerCase();
  const pageSize = 100;
  const offset = uiState.evidencePage * pageSize;
  const visible = [];
  let total = 0;
  let matches = 0;
  // A bounded DOM view: don't eagerly duplicate every evidence row on import.
  for (const finding of state.report?.findings ?? []) {
    for (const item of finding.evidence ?? []) {
      total++;
      if (query && !`${finding.ruleId} ${item.path} ${item.factId ?? ''} ${item.value ?? ''} ${item.source ?? ''} ${item.collectorId ?? ''}`.toLowerCase().includes(query)) continue;
      if (matches >= offset && visible.length < pageSize) visible.push({ finding, item });
      matches++;
    }
  }
  const pages = Math.max(1, Math.ceil(matches / pageSize));
  if (uiState.evidencePage >= pages) { uiState.evidencePage = pages - 1; renderEvidenceIndex(); return; }
  document.getElementById('evidenceCount').textContent = `${matches} / ${total} attached facts`;
  document.getElementById('evidencePage').textContent = `Page ${uiState.evidencePage + 1} of ${pages}`;
  document.getElementById('evidencePrevious').disabled = uiState.evidencePage === 0;
  document.getElementById('evidenceNext').disabled = uiState.evidencePage + 1 >= pages;
  document.getElementById('evidenceBody').innerHTML = visible.length ? visible.map(({ finding, item }) => `<tr><td><code>${escapeHtml(finding.ruleId)}</code><code>${escapeHtml(item.path)}</code><small class="mono">${escapeHtml(item.factId)}</small></td><td><code>${escapeHtml(item.value ?? '—')}</code></td><td>${escapeHtml(item.source)}<small class="mono">${escapeHtml(item.collectorId)} ${escapeHtml(item.collectorVersion)}</small><small>${escapeHtml(formatDate(item.observedAt))}</small></td><td><button class="text-button" type="button" data-open-finding="${escapeHtml(finding.fingerprint)}" data-open-mode="technical">Inspect →</button></td></tr>`).join('') : '<tr><td colspan="4">No attached evidence matches this view.</td></tr>';
}

// A tablist uses roving focus; navigation itself remains ordinary buttons.
function bindTabKeys(nav, selector) {
  if (!nav) return;
  nav.addEventListener('keydown', event => {
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
    const buttons = [...nav.querySelectorAll(selector)];
    const current = buttons.indexOf(document.activeElement);
    if (current < 0) return;
    event.preventDefault();
    const index = event.key === 'Home' ? 0 : event.key === 'End' ? buttons.length - 1 : (current + (event.key === 'ArrowRight' ? 1 : -1) + buttons.length) % buttons.length;
    buttons[index].click();
    buttons[index].focus();
  });
}

function openNavigation() {
  const sidebar = document.getElementById('sidebar');
  sidebar.classList.add('navigation-open');
  sidebar.setAttribute('role', 'dialog');
  sidebar.setAttribute('aria-modal', 'true');
  document.body.classList.add('navigation-open');
  document.getElementById('navigationBackdrop').hidden = false;
  document.getElementById('openNavigation').setAttribute('aria-expanded', 'true');
  document.getElementById('mainShell').inert = true;
  sidebar.querySelector('[aria-current="page"]').focus();
}
function closeNavigation(restoreFocus = true) {
  const sidebar = document.getElementById('sidebar');
  const wasOpen = sidebar.classList.contains('navigation-open');
  sidebar.classList.remove('navigation-open');
  sidebar.removeAttribute('role');
  sidebar.removeAttribute('aria-modal');
  document.body.classList.remove('navigation-open');
  document.getElementById('navigationBackdrop').hidden = true;
  document.getElementById('mainShell').inert = false;
  document.getElementById('openNavigation').setAttribute('aria-expanded', 'false');
  if (wasOpen && restoreFocus) document.getElementById('openNavigation').focus();
}

function exportAnalysis(format) {
  if (state.analysisId) window.location.href = `/api/analyses/${state.analysisId}/${format}`;
}

els.assessmentForm.addEventListener('submit', startAssessment);
els.authenticationMode.addEventListener('change', updateAuthenticationFields);
els.cancelAssessment.addEventListener('click', cancelAssessment);
els.analyzeButton.addEventListener('click', analyzeSelectedSnapshot);
els.findingSearch.addEventListener('input', () => renderFindings());
els.severityFilter.addEventListener('change', () => renderFindings());
els.exportJson.addEventListener('click', () => exportAnalysis('json'));
els.exportHtml.addEventListener('click', () => exportAnalysis('html'));
for (const button of document.querySelectorAll('.main-nav .tab')) button.addEventListener('click', () => activateTab(button.dataset.tab, { focus: true }));

els.statusFilter.addEventListener('change', () => renderFindings());
document.getElementById('clearFindingFilters').addEventListener('click', () => {
  els.findingSearch.value = ''; els.severityFilter.value = 'all'; els.statusFilter.value = 'all'; renderFindings();
});
document.getElementById('evidenceSearch').addEventListener('input', () => { uiState.evidencePage = 0; renderEvidenceIndex(); });
document.getElementById('evidencePrevious').addEventListener('click', () => { uiState.evidencePage--; renderEvidenceIndex(); });
document.getElementById('evidenceNext').addEventListener('click', () => { uiState.evidencePage++; renderEvidenceIndex(); });
document.getElementById('backToFindings').addEventListener('click', () => {
  document.getElementById('findingLayout').classList.remove('detail-open');
  els.findingList.querySelector('.selected')?.focus();
});
document.addEventListener('click', event => {
  const route = event.target.closest('[data-route]');
  if (route) activateTab(route.dataset.route, { focus: true });
  const finding = event.target.closest('[data-open-finding]');
  if (finding) openFinding(finding.dataset.openFinding, finding.dataset.openMode || 'overview');
});
for (const button of document.querySelectorAll('[data-technical]')) button.addEventListener('click', () => activateTechnicalSection(button.dataset.technical));
bindTabKeys(document.getElementById('technicalNav'), '[data-technical]');
document.getElementById('openNavigation').addEventListener('click', openNavigation);
document.getElementById('closeNavigation').addEventListener('click', () => closeNavigation());
document.getElementById('navigationBackdrop').addEventListener('click', () => closeNavigation());
document.getElementById('sidebar').addEventListener('keydown', event => {
  if (!document.body.classList.contains('navigation-open')) return;
  if (event.key === 'Escape') { event.preventDefault(); closeNavigation(); }
  if (event.key === 'Tab') {
    const items = [...document.getElementById('sidebar').querySelectorAll('button, a[href]')].filter(item => item.getClientRects().length && !item.disabled);
    if (event.shiftKey && document.activeElement === items[0]) { event.preventDefault(); items.at(-1).focus(); }
    else if (!event.shiftKey && document.activeElement === items.at(-1)) { event.preventDefault(); items[0].focus(); }
  }
});
window.matchMedia('(max-width: 760px)').addEventListener('change', event => {
  if (!event.matches) { closeNavigation(false); }
  else if (document.getElementById('sidebar').contains(document.activeElement)) document.getElementById('openNavigation').focus();
});
window.addEventListener('hashchange', () => activateTab(location.hash.slice(1), { fromHash: true, focus: true }));
activateTechnicalSection('coverage');
activateTab(location.hash.slice(1) || 'overview', { fromHash: true });
updateAuthenticationFields();
loadStatus();
