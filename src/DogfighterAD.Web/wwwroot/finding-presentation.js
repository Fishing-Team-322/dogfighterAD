const findingPresentationState = {
  analysisId: null,
  view: null,
  mode: 'overview',
  loading: false
};

const baseRenderReport = renderReport;
const baseRenderSummary = renderSummary;
const baseRenderFindings = renderFindings;
const baseRenderFindingDetail = renderFindingDetail;
const baseRenderUnknowns = renderUnknowns;
const baseRenderCertificateServices = renderCertificateServices;
const baseCsRenderTemplates = csRenderTemplates;
const baseCsRenderAuthorities = csRenderAuthorities;
const baseCsRenderFindings = csRenderFindings;

function presentationFor(fingerprint) {
  return (findingPresentationState.view?.findings ?? []).find(item => item.fingerprint === fingerprint) ?? null;
}

function friendlyPrincipal(sid) {
  if (sid === 'S-1-1-0') return 'Everyone';
  if (sid === 'S-1-5-11') return 'Authenticated Users';
  if (sid === 'S-1-5-32-545') return 'Users';
  if (String(sid ?? '').endsWith('-513')) return 'Domain Users';
  return sid || 'Unknown principal';
}

function friendlyRight(right) {
  return {
    GenericAll: 'Full control',
    GenericWrite: 'Can modify this object',
    WriteDacl: 'Can change permissions',
    WriteOwner: 'Can take ownership',
    WriteProperty: 'Can modify object properties',
    Enroll: 'Can request certificates',
    AutoEnroll: 'Can automatically enroll'
  }[right] || right;
}

function presentationModeSwitch() {
  return `<div class="finding-mode-switch" role="group" aria-label="Finding view mode">
    <button type="button" class="secondary ${findingPresentationState.mode === 'overview' ? 'active' : ''}" data-finding-mode="overview">Overview</button>
    <button type="button" class="secondary ${findingPresentationState.mode === 'technical' ? 'active' : ''}" data-finding-mode="technical">Technical</button>
  </div>`;
}

function bindFindingModeSwitch(finding) {
  for (const button of els.findingDetail.querySelectorAll('[data-finding-mode]')) {
    button.addEventListener('click', () => {
      findingPresentationState.mode = button.dataset.findingMode;
      renderFindingDetail(finding);
    });
  }
  for (const button of els.findingDetail.querySelectorAll('[data-show-technical]')) {
    button.addEventListener('click', () => {
      findingPresentationState.mode = 'technical';
      renderFindingDetail(finding);
    });
  }
}

function renderConditionList(conditions) {
  if (!conditions?.length) return '';
  return `<section class="condition-section"><h3>Why this finding was triggered</h3><div class="condition-list">${conditions.map(item => {
    const css = item.state === 'NotVerified' ? 'condition-not-verified' : 'condition-met';
    const mark = item.state === 'NotVerified' ? '?' : '✓';
    return `<div class="condition-row ${css}"><span class="condition-mark">${mark}</span><div><strong>${escapeHtml(item.label)}</strong>${item.detail ? `<small>${escapeHtml(item.detail)}</small>` : ''}</div><span class="condition-value">${escapeHtml(item.value)}</span></div>`;
  }).join('')}</div></section>`;
}

function renderKeyEvidence(items) {
  if (!items?.length) return '';
  return `<h3>Key evidence</h3><div class="key-evidence-list">${items.map(item => `
    <article class="key-evidence-card">
      <span class="evidence-label">Key</span>
      <strong>${escapeHtml(item.headline)}</strong>
      ${item.principal ? `<span>${escapeHtml(item.principal)}</span>` : ''}
      ${item.right ? `<span class="key-right">${escapeHtml(item.right)}</span>` : ''}
      ${item.technicalPrincipal ? `<small>SID: ${escapeHtml(item.technicalPrincipal)}</small>` : ''}
      ${item.technicalRight ? `<small>Technical right: ${escapeHtml(item.technicalRight)}</small>` : ''}
      ${item.sourcePath ? `<code>${escapeHtml(item.sourcePath)}</code>` : ''}
    </article>`).join('')}</div>
    <button type="button" class="secondary view-raw-evidence" data-show-technical>View raw evidence</button>`;
}

function renderPresentationEvidence(title, items, context = false) {
  if (!items?.length) return '';
  return `<details class="supporting-evidence"><summary>${escapeHtml(title)}</summary><ul class="presentation-evidence-list ${context ? 'context' : ''}">${items.map(item => `
    <li><strong>${escapeHtml(item.headline)}</strong>${item.value !== null && item.value !== undefined ? `<span>${escapeHtml(item.value)}</span>` : ''}${item.sourcePath ? `<small>${escapeHtml(item.sourcePath)}</small>` : ''}</li>`).join('')}</ul></details>`;
}

function renderCustomerFindingDetail(finding, presentation) {
  els.findingDetail.innerHTML = `
    ${presentationModeSwitch()}
    <div class="detail-heading customer-detail-heading"><span class="severity-badge ${severityClass(presentation.severity)}">${escapeHtml(presentation.severity)}</span><div><span class="eyebrow">${escapeHtml(presentation.affectedObject.type)}</span><h2>${escapeHtml(presentation.customerTitle)}</h2><small class="technical-secondary">${escapeHtml(presentation.ruleId)}</small></div></div>
    <div class="detail-meta"><span>Status <strong>${escapeHtml(presentation.customerStatus)}</strong></span><span>Affected <strong>${escapeHtml(presentation.affectedObject.displayName)}</strong></span><span>Confidence <strong>${escapeHtml(presentation.confidence)}</strong></span></div>
    ${presentation.statusBoundary ? `<div class="status-boundary"><strong>${escapeHtml(presentation.customerStatus)}</strong><span>${escapeHtml(presentation.statusBoundary)}</span></div>` : ''}
    <p>${escapeHtml(presentation.summary)}</p>
    ${renderConditionList(presentation.conditions)}
    ${renderKeyEvidence(presentation.keyEvidence)}
    ${renderPresentationEvidence('Supporting evidence', presentation.supportingEvidence)}
    ${renderPresentationEvidence('Context evidence', presentation.contextEvidence, true)}
    <h3>Impact</h3><p>${escapeHtml(presentation.impact)}</p>
    <h3>Recommended action</h3><p>${escapeHtml(presentation.recommendation)}</p>
    <h3>Affected object</h3><div class="customer-object-summary"><strong>${escapeHtml(presentation.affectedObject.displayName)}</strong><small>${escapeHtml(presentation.affectedObject.type)}</small></div>`;
  bindFindingModeSwitch(finding);
}

async function loadFindingPresentation(force = false) {
  if (!state.analysisId || !state.report) {
    findingPresentationState.analysisId = null;
    findingPresentationState.view = null;
    return;
  }
  if (!force && findingPresentationState.analysisId === state.analysisId && findingPresentationState.view) return;
  if (findingPresentationState.loading) return;

  findingPresentationState.loading = true;
  try {
    const response = await fetch(`/api/analyses/${state.analysisId}/presentation`, { cache: 'no-store' });
    const view = await response.json();
    if (!response.ok) throw new Error(view.error || 'presentation-load-failed');
    findingPresentationState.analysisId = state.analysisId;
    findingPresentationState.view = view;
    findingPresentationState.mode = 'overview';
    renderSummary(state.report);
    renderFindings();
    renderUnknowns(state.report.evaluations ?? []);
    if (certificateServicesState.view) renderCertificateServices();
  } catch (error) {
    console.warn('Customer presentation unavailable; retaining technical report view.', error);
    findingPresentationState.analysisId = state.analysisId;
    findingPresentationState.view = null;
  } finally {
    findingPresentationState.loading = false;
  }
}

renderReport = function () {
  baseRenderReport();
  void loadFindingPresentation();
};

renderSummary = function (report) {
  const summary = findingPresentationState.analysisId === state.analysisId
    ? findingPresentationState.view?.summary : null;
  if (!summary) {
    baseRenderSummary(report);
    return;
  }

  const priorities = (summary.topPriorities ?? []).map(item => `<li>${escapeHtml(item)}</li>`).join('');
  const cards = [
    ['Overall posture', summary.overallPosture, 'posture'],
    ['Critical', summary.critical ?? 0, 'critical'],
    ['High', summary.high ?? 0, 'high'],
    ['Medium', summary.medium ?? 0, 'medium'],
    ['Low', summary.low ?? 0, 'low'],
    ['Not verified', summary.notVerified ?? 0, (summary.notVerified ?? 0) === 0 ? 'ok' : 'warn']
  ];
  els.summaryGrid.innerHTML = cards.map(([label, value, tone]) => `
    <article class="summary-card ${tone}"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></article>`).join('') +
    `<article class="summary-card priorities"><span>Top priorities</span>${priorities ? `<ol>${priorities}</ol>` : '<strong>No finding priorities emitted</strong>'}</article>`;
};

renderFindings = function () {
  const view = findingPresentationState.analysisId === state.analysisId ? findingPresentationState.view : null;
  if (!view) {
    baseRenderFindings();
    return;
  }

  const findings = filteredFindings();
  els.findingCount.textContent = `${findings.length} shown`;
  if (findings.length === 0) {
    els.findingList.innerHTML = '<div class="empty-state">No findings match the current filters.</div>';
    els.findingDetail.innerHTML = '<div class="empty-state">Select another filter or search term.</div>';
    return;
  }
  if (!findings.some(item => item.fingerprint === state.selectedFingerprint)) state.selectedFingerprint = findings[0].fingerprint;

  els.findingList.innerHTML = findings.map(finding => {
    const item = presentationFor(finding.fingerprint);
    const selected = finding.fingerprint === state.selectedFingerprint ? 'selected' : '';
    const subject = item?.affectedObject?.displayName || finding.affectedObjects?.[0]?.displayName || 'Snapshot scope';
    const keyReason = item?.keyEvidence?.[0]?.headline || item?.summary || finding.description;
    return `<button class="finding-row customer-finding-row ${selected}" data-fingerprint="${escapeHtml(finding.fingerprint)}" type="button">
      <span class="severity-badge ${severityClass(finding.severity)}">${escapeHtml(finding.severity)}</span>
      <span class="finding-row-main"><strong>${escapeHtml(item?.customerTitle || finding.title)}</strong><span class="finding-key-reason">${escapeHtml(keyReason)}</span><small>${escapeHtml(item?.customerStatus || finding.status)} · ${escapeHtml(subject)}</small><small class="technical-secondary">${escapeHtml(finding.ruleId)}</small></span>
    </button>`;
  }).join('');

  for (const button of els.findingList.querySelectorAll('[data-fingerprint]')) {
    button.addEventListener('click', () => {
      state.selectedFingerprint = button.dataset.fingerprint;
      findingPresentationState.mode = 'overview';
      renderFindings();
    });
  }
  renderFindingDetail(findings.find(item => item.fingerprint === state.selectedFingerprint) ?? findings[0]);
};

renderFindingDetail = function (finding) {
  const presentation = presentationFor(finding.fingerprint);
  if (!presentation) {
    baseRenderFindingDetail(finding);
    return;
  }
  if (findingPresentationState.mode === 'technical') {
    baseRenderFindingDetail(finding);
    els.findingDetail.insertAdjacentHTML('afterbegin', presentationModeSwitch());
    bindFindingModeSwitch(finding);
    return;
  }
  renderCustomerFindingDetail(finding, presentation);
};

renderUnknowns = function (evaluations) {
  const items = findingPresentationState.analysisId === state.analysisId
    ? findingPresentationState.view?.notVerified : null;
  if (!items) {
    baseRenderUnknowns(evaluations);
    return;
  }
  if (items.length === 0) {
    els.unknownList.innerHTML = '<div class="empty-state">No NotVerified or Error evaluations.</div>';
    return;
  }
  els.unknownList.innerHTML = items.map(item => `
    <details class="unknown-row customer-notverified">
      <summary><strong>${escapeHtml(item.status)}</strong> · ${escapeHtml(item.customerTitle)} · ${escapeHtml(item.subject)}</summary>
      <p>${escapeHtml(item.reason)}</p>
      <p class="notverified-caution">${escapeHtml(item.caution)}</p>
      ${(item.missingEvidence ?? []).length ? `<div class="missing-evidence"><strong>Missing evidence</strong><ul>${item.missingEvidence.map(value => `<li>${escapeHtml(value)}</li>`).join('')}</ul></div>` : ''}
      <small class="technical-secondary">${escapeHtml(item.ruleId)} · ${escapeHtml(item.technicalOutcome)}</small>
    </details>`).join('');
};

csRenderAces = function (aces) {
  if (!aces?.length) return '<div class="empty-state compact">No direct ACE rows in the normalized DACL.</div>';
  return `<div class="table-wrap"><table><thead><tr><th>Trustee</th><th>Type</th><th>Rights</th><th>Technical scope</th></tr></thead><tbody>${aces.map(ace => `
    <tr>
      <td><strong>${escapeHtml(friendlyPrincipal(ace.trusteeSid))}</strong><small>SID: ${escapeHtml(ace.trusteeSid)}</small></td>
      <td>${escapeHtml(ace.accessType)}${ace.isInherited ? '<small>inherited</small>' : '<small>direct</small>'}</td>
      <td><div class="cs-tags">${(ace.rights ?? []).map(right => `<span class="friendly-right"><strong>${escapeHtml(friendlyRight(right))}</strong><small>${escapeHtml(right)}</small></span>`).join('') || '<span class="muted">No mapped milestone right</span>'}</div></td>
      <td><code>${escapeHtml(ace.objectType || 'all / unscoped')}</code><small>${escapeHtml(ace.accessMask)} · flags ${escapeHtml(ace.aceFlags)}</small></td>
    </tr>`).join('')}</tbody></table></div>`;
};

function csPresentationFindingsFor(stableId) {
  return (findingPresentationState.view?.findings ?? []).filter(item => item.affectedObject?.stableId === stableId);
}

function csCustomerObjectSummary(stableId, safeText) {
  const findings = [...csPresentationFindingsFor(stableId)].sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
  if (!findings.length) return `<section class="customer-object-summary safe-inventory"><span class="eyebrow">Customer summary</span><h3>No risk finding emitted for this object</h3><p>${escapeHtml(safeText)}</p></section>`;
  const finding = findings[0];
  return `<section class="customer-object-summary"><span class="eyebrow">Customer summary</span><h3>${escapeHtml(finding.customerTitle)}</h3><div class="detail-meta"><span>Risk level <strong>${escapeHtml(finding.severity)}</strong></span><span>Status <strong>${escapeHtml(finding.customerStatus)}</strong></span></div><p>${escapeHtml(finding.summary)}</p>${finding.statusBoundary ? `<p class="notverified-caution">${escapeHtml(finding.statusBoundary)}</p>` : ''}${renderConditionList(finding.conditions)}${renderKeyEvidence(finding.keyEvidence)}<h4>Recommended action</h4><p>${escapeHtml(finding.recommendation)}</p></section>`;
}

renderCertificateServices = function () {
  baseRenderCertificateServices();
  const view = certificateServicesState.view;
  const presentation = findingPresentationState.view;
  if (!view || !presentation || !view.available) return;

  certificateServicesEls.summary.innerHTML = [
    ['Enterprise CAs', view.authorities?.length ?? 0],
    ['Certificate templates', view.templates?.length ?? 0],
    ['Templates requiring attention', new Set((presentation.findings ?? []).filter(item => item.affectedObject?.type === 'Certificate Template').map(item => item.affectedObject.stableId)).size],
    ['High-risk configurations', (presentation.findings ?? []).filter(item => item.severity === 'High' || item.severity === 'Critical').length]
  ].map(([label, value]) => `<article class="summary-card"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></article>`).join('');

  document.querySelector('.cs-attention')?.remove();
  const attention = (presentation.findings ?? [])
    .filter(item => item.affectedObject?.type === 'Certificate Template')
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity))
    .slice(0, 6);
  if (attention.length) {
    certificateServicesEls.summary.insertAdjacentHTML('afterend', `<section class="cs-attention"><div class="cs-attention-heading"><div><span class="eyebrow">Templates requiring attention</span><h3>Key reasons</h3></div><span class="muted">Safe templates remain available under Templates.</span></div><div class="attention-grid">${attention.map(item => `<button type="button" class="attention-card" data-attention-template="${escapeHtml(item.affectedObject.stableId)}"><span class="severity-badge ${severityClass(item.severity)}">${escapeHtml(item.severity)}</span><strong>${escapeHtml(item.affectedObject.displayName)}</strong><span>${escapeHtml(item.customerTitle)}</span><small>${escapeHtml(item.keyEvidence?.[0]?.headline || item.summary)}</small></button>`).join('')}</div></section>`);
    for (const button of document.querySelectorAll('[data-attention-template]')) {
      button.addEventListener('click', () => {
        certificateServicesState.selectedTemplate = button.dataset.attentionTemplate;
        csActivateSection('templates');
      });
    }
  }
};

csRenderTemplates = function () {
  baseCsRenderTemplates();
  const detail = certificateServicesEls.templates.querySelector('.cs-detail');
  if (!detail || !certificateServicesState.selectedTemplate || !findingPresentationState.view) return;
  detail.querySelector('.customer-object-summary')?.remove();
  const heading = detail.querySelector('.detail-heading');
  heading?.insertAdjacentHTML('afterend', csCustomerObjectSummary(
    certificateServicesState.selectedTemplate,
    'The template remains visible as inventory. No customer-facing risk description is added when the Rule Engine emitted no finding.'));
  for (const button of detail.querySelectorAll('[data-show-technical]')) button.addEventListener('click', () => activateTab('findings'));
};

csRenderAuthorities = function () {
  baseCsRenderAuthorities();
  const detail = certificateServicesEls.authorities.querySelector('.cs-detail');
  if (!detail || !certificateServicesState.selectedAuthority || !findingPresentationState.view) return;
  detail.querySelector('.customer-object-summary')?.remove();
  const heading = detail.querySelector('.detail-heading');
  heading?.insertAdjacentHTML('afterend', csCustomerObjectSummary(
    certificateServicesState.selectedAuthority,
    'No CA directory risk finding was emitted for this object. Runtime CA security is not inferred from that absence.'));
};

csRenderFindings = function () {
  const findings = [...(findingPresentationState.view?.findings ?? [])]
    .filter(item => String(item.ruleId ?? '').startsWith('ADCS.'))
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || a.ruleId.localeCompare(b.ruleId));
  if (!findingPresentationState.view) {
    baseCsRenderFindings();
    return;
  }
  if (!findings.length) {
    certificateServicesEls.findings.innerHTML = '<section class="panel empty-state">No AD CS findings were emitted. Safe inventory remains available under CAs and Templates.</section>';
    return;
  }
  certificateServicesEls.findings.innerHTML = `<section class="panel"><h2>AD CS findings</h2><p class="muted">Customer-facing explanations are shown first; directory-derived Potential boundaries are preserved.</p><div class="unknown-list">${findings.map(item => `<details class="unknown-row"><summary><span class="severity-badge ${severityClass(item.severity)}">${escapeHtml(item.severity)}</span> <strong>${escapeHtml(item.customerTitle)}</strong> · ${escapeHtml(item.affectedObject.displayName)}</summary><p>${escapeHtml(item.summary)}</p>${item.statusBoundary ? `<p class="notverified-caution">${escapeHtml(item.statusBoundary)}</p>` : ''}${renderKeyEvidence(item.keyEvidence)}<p><strong>Recommended action:</strong> ${escapeHtml(item.recommendation)}</p><small class="technical-secondary">${escapeHtml(item.ruleId)}</small></details>`).join('')}</div></section>`;
};
