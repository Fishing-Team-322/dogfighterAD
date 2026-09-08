const findingPresentationState = {
  analysisId: null,
  view: null,
  mode: 'overview',
  loading: null
};

const baseRenderReport = renderReport;
const baseRenderFindingDetail = renderFindingDetail;
const baseRenderUnknowns = renderUnknowns;
const baseCsRenderTemplates = csRenderTemplates;
const baseCsRenderAuthorities = csRenderAuthorities;
const baseCsRenderFindings = csRenderFindings;

function presentationFor(fingerprint) {
  if (findingPresentationState.analysisId !== state.analysisId) return null;
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
    <button type="button" class="secondary ${findingPresentationState.mode === 'overview' ? 'active' : ''}" data-finding-mode="overview" aria-pressed="${findingPresentationState.mode === 'overview'}">Overview</button>
    <button type="button" class="secondary ${findingPresentationState.mode === 'technical' ? 'active' : ''}" data-finding-mode="technical" aria-pressed="${findingPresentationState.mode === 'technical'}">Technical</button>
  </div>`;
}

function bindFindingModeSwitch(finding) {
  for (const button of els.findingDetail.querySelectorAll('[data-finding-mode]')) {
    button.addEventListener('click', () => {
      findingPresentationState.mode = button.dataset.findingMode;
      renderFindingDetail(finding);
      els.findingDetail.closest('.finding-detail-panel').scrollTop = 0;
      els.findingDetail.querySelector(`[data-finding-mode="${findingPresentationState.mode}"]`)?.focus({ preventScroll: true });
    });
  }
  for (const button of els.findingDetail.querySelectorAll('[data-show-technical]')) {
    button.addEventListener('click', () => {
      findingPresentationState.mode = 'technical';
      renderFindingDetail(finding);
      els.findingDetail.closest('.finding-detail-panel').scrollTop = 0;
      els.findingDetail.querySelector('[data-finding-mode="technical"]')?.focus({ preventScroll: true });
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

function renderKeyEvidence(items, fingerprint = null) {
  if (!items?.length) return '';
  return `<h3>Key evidence</h3><div class="key-evidence-list">${items.map(item => `
    <article class="key-evidence-card">
      <strong>${escapeHtml(item.headline)}</strong>
      ${item.principal ? `<span>${escapeHtml(item.principal)}</span>` : ''}
      ${item.right ? `<span class="key-right">${escapeHtml(item.right)}</span>` : ''}
      ${item.value !== null && item.value !== undefined ? `<code>${escapeHtml(item.value)}</code>` : ''}
      ${item.technicalPrincipal || item.technicalRight || item.sourcePath ? `<details class="key-evidence-source"><summary>Source details</summary>${item.technicalPrincipal ? `<small>SID: <code>${escapeHtml(item.technicalPrincipal)}</code></small>` : ''}${item.technicalRight ? `<small>Technical right: <code>${escapeHtml(item.technicalRight)}</code></small>` : ''}${item.sourcePath ? `<code>${escapeHtml(item.sourcePath)}</code>` : ''}</details>` : ''}
    </article>`).join('')}</div>
    <button type="button" class="text-button view-raw-evidence" ${fingerprint ? `data-open-finding="${escapeHtml(fingerprint)}" data-open-mode="technical"` : 'data-show-technical'}>View raw evidence →</button>`;
}

function renderPresentationEvidence(title, items, context = false) {
  if (!items?.length) return '';
  return `<details class="supporting-evidence"><summary>${escapeHtml(title)}</summary><ul class="presentation-evidence-list ${context ? 'context' : ''}">${items.map(item => `
    <li><strong>${escapeHtml(item.headline)}</strong>${item.value !== null && item.value !== undefined ? `<span>${escapeHtml(item.value)}</span>` : ''}${item.sourcePath ? `<small>${escapeHtml(item.sourcePath)}</small>` : ''}</li>`).join('')}</ul></details>`;
}

function renderCustomerFindingDetail(finding, presentation) {
  els.findingDetail.innerHTML = `
    ${presentationModeSwitch()}
    <div class="detail-heading customer-detail-heading"><div><span class="eyebrow">${escapeHtml(presentation.affectedObject.type)}</span><h2>${escapeHtml(presentation.customerTitle)}</h2><code class="technical-secondary">${escapeHtml(presentation.ruleId)}</code></div></div>
    <div class="detail-meta"><span class="severity-badge ${severityClass(presentation.severity)}">${escapeHtml(presentation.severity)}</span>${statusBadge(finding.status)}<span>Confidence <strong>${escapeHtml(presentation.confidence)}</strong></span></div>
    <div class="customer-object-summary"><span class="label">Affected object</span><strong>${escapeHtml(presentation.affectedObject.displayName)}</strong><small>${escapeHtml(presentation.affectedObject.type)}</small></div>
    ${presentation.statusBoundary ? `<div class="status-boundary"><strong>${escapeHtml(presentation.customerStatus)}</strong><span>${escapeHtml(presentation.statusBoundary)}</span></div>` : ''}
    <h3>Summary</h3><p>${escapeHtml(presentation.summary)}</p>
    <h3>Impact</h3><p>${escapeHtml(presentation.impact)}</p>
    <section class="recommended-action"><h3>Recommended action</h3><p>${escapeHtml(presentation.recommendation)}</p></section>
    ${renderConditionList(presentation.conditions)}
    ${renderKeyEvidence(presentation.keyEvidence)}
    ${renderPresentationEvidence('Supporting evidence', presentation.supportingEvidence)}
    ${renderPresentationEvidence('Context evidence', presentation.contextEvidence, true)}`;
  bindFindingModeSwitch(finding);
}

async function loadFindingPresentation(force = false) {
  if (!state.analysisId || !state.report) {
    findingPresentationState.analysisId = null;
    findingPresentationState.view = null;
    return;
  }
  const analysisId = state.analysisId;
  if (!force && findingPresentationState.analysisId === analysisId && findingPresentationState.view) return;
  if (!force && findingPresentationState.loading === analysisId) return;
  findingPresentationState.loading = analysisId;
  const notice = document.getElementById('presentationNotice');
  notice.textContent = 'Loading the server-generated Overview presentation. The original technical report is available.';
  notice.classList.remove('hidden');
  try {
    const response = await fetch(`/api/analyses/${analysisId}/presentation`, { cache: 'no-store' });
    const view = await response.json();
    if (state.analysisId !== analysisId) return;
    if (!response.ok) throw new Error(view.error || 'presentation-load-failed');
    findingPresentationState.analysisId = analysisId;
    findingPresentationState.view = view;
    notice.classList.add('hidden');
    renderSummary(state.report);
    renderFindings();
    renderUnknowns(state.report.evaluations ?? []);
    if (certificateServicesState.analysisId === analysisId && certificateServicesState.view) renderCertificateServices();
  } catch {
    if (state.analysisId !== analysisId) return;
    findingPresentationState.analysisId = analysisId;
    findingPresentationState.view = null;
    notice.innerHTML = 'Overview presentation is unavailable. Showing the original technical findings; no interpretation has been generated in the browser. <button type="button" class="text-button" id="retryPresentation">Retry</button>';
    notice.querySelector('button').addEventListener('click', () => loadFindingPresentation(true));
    renderSummary(state.report);
    renderFindings();
  } finally {
    if (findingPresentationState.loading === analysisId) findingPresentationState.loading = null;
  }
}

renderReport = function () {
  if (findingPresentationState.analysisId !== state.analysisId) {
    findingPresentationState.view = null;
    findingPresentationState.mode = 'overview';
  }
  baseRenderReport();
  void loadFindingPresentation();
};

renderSummary = function (report) {
  const summary = findingPresentationState.analysisId === state.analysisId ? findingPresentationState.view?.summary : null;
  renderDashboard(report, summary);
};

renderFindings = function () { renderFindingRows(); };

renderFindingDetail = function (finding) {
  const presentation = presentationFor(finding.fingerprint);
  if (!presentation) {
    baseRenderFindingDetail(finding);
    els.findingDetail.insertAdjacentHTML('afterbegin', '<div class="technical-fallback">Technical report · Overview presentation unavailable</div>');
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
  const raw = document.createElement('details'); raw.className = 'disclosure';
  raw.innerHTML = '<summary>Original evaluation data</summary><pre></pre>';
  raw.querySelector('pre').textContent = JSON.stringify(evaluations.filter(item => item.outcome === 'NotVerified' || item.outcome === 'Error'), null, 2);
  els.unknownList.appendChild(raw);
};

csRenderAces = function (aces) {
  if (!aces?.length) return '<div class="empty-state compact">No direct ACE rows in the normalized DACL.</div>';
  return `<div class="table-wrap"><table><thead><tr><th>Trustee</th><th>Type</th><th>Rights</th><th>Technical scope</th></tr></thead><tbody>${aces.map(ace => `
    <tr>
      <td><strong>${escapeHtml(friendlyPrincipal(ace.trusteeSid))}</strong><small>SID: <code>${escapeHtml(ace.trusteeSid)}</code></small></td>
      <td>${escapeHtml(ace.accessType)}${ace.isInherited ? '<small>inherited</small>' : '<small>direct</small>'}</td>
      <td><div class="cs-tags">${(ace.rights ?? []).map(right => `<span class="friendly-right"><strong>${escapeHtml(friendlyRight(right))}</strong><small>${escapeHtml(right)}</small></span>`).join('') || '<span class="muted">No mapped milestone right</span>'}</div></td>
      <td><code>${escapeHtml(ace.objectType || 'all / unscoped')}</code><small>${escapeHtml(ace.accessMask)} · flags ${escapeHtml(ace.aceFlags)}</small></td>
    </tr>`).join('')}</tbody></table></div>`;
};

function csPresentationFindingsFor(stableId) {
  if (findingPresentationState.analysisId !== state.analysisId) return [];
  return (findingPresentationState.view?.findings ?? []).filter(item => item.affectedObject?.stableId === stableId);
}

function csCustomerObjectSummary(stableId, safeText) {
  const findings = [...csPresentationFindingsFor(stableId)].sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
  if (!findings.length) return `<section class="customer-object-summary safe-inventory"><span class="eyebrow">Finding overview</span><h3>No risk finding emitted for this object</h3><p>${escapeHtml(safeText)}</p></section>`;
  const finding = findings[0];
  return `<section class="customer-object-summary"><span class="eyebrow">Finding overview</span><h3>${escapeHtml(finding.customerTitle)}</h3><div class="detail-meta"><span>Risk level <strong>${escapeHtml(finding.severity)}</strong></span><span>Status <strong>${escapeHtml(finding.customerStatus)}</strong></span></div><p>${escapeHtml(finding.summary)}</p>${finding.statusBoundary ? `<p class="notverified-caution">${escapeHtml(finding.statusBoundary)}</p>` : ''}<h4>Recommended action</h4><p>${escapeHtml(finding.recommendation)}</p><button type="button" class="text-button" data-open-finding="${escapeHtml(finding.fingerprint)}">Open finding →</button><details class="disclosure"><summary>Conditions &amp; key evidence</summary>${renderConditionList(finding.conditions)}${renderKeyEvidence(finding.keyEvidence, finding.fingerprint)}</details></section>`;
}

csRenderTemplates = function () {
  baseCsRenderTemplates();
  const detail = csTemplateContainer().querySelector('.cs-detail');
  if (!detail || !certificateServicesState.selectedTemplate || !findingPresentationState.view || findingPresentationState.analysisId !== state.analysisId) return;
  detail.querySelector('.customer-object-summary')?.remove();
  const anchor = detail.querySelector(':scope > .detail-meta') || detail.querySelector('.detail-heading');
  anchor?.insertAdjacentHTML('afterend', csCustomerObjectSummary(
    certificateServicesState.selectedTemplate,
    'The template remains visible as inventory. No customer-facing risk description is added when the Rule Engine emitted no finding.'));

};

csRenderAuthorities = function () {
  baseCsRenderAuthorities();
  const detail = certificateServicesEls.authorities.querySelector('.cs-detail');
  if (!detail || !certificateServicesState.selectedAuthority || !findingPresentationState.view || findingPresentationState.analysisId !== state.analysisId) return;
  detail.querySelector('.customer-object-summary')?.remove();
  const anchor = detail.querySelector(':scope > .detail-meta') || detail.querySelector('.detail-heading');
  anchor?.insertAdjacentHTML('afterend', csCustomerObjectSummary(
    certificateServicesState.selectedAuthority,
    'No CA directory risk finding was emitted for this object. Runtime CA security is not inferred from that absence.'));
};

csRenderFindings = function () {
  const findings = [...(findingPresentationState.view?.findings ?? [])]
    .filter(item => String(item.ruleId ?? '').startsWith('ADCS.'))
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || a.ruleId.localeCompare(b.ruleId));
  if (!findingPresentationState.view || findingPresentationState.analysisId !== state.analysisId) {
    baseCsRenderFindings();
    return;
  }
  if (!findings.length) {
    certificateServicesEls.findings.innerHTML = '<section class="panel empty-state">No AD CS findings were emitted. All inventory remains available under CAs and All templates. No clean verdict is inferred.</section>';
    return;
  }
  certificateServicesEls.findings.innerHTML = `<section class="panel"><h2>AD CS findings</h2><p class="muted">Customer-facing explanations are shown first; directory-derived Potential boundaries are preserved.</p><div class="unknown-list">${findings.map(item => `<details class="unknown-row"><summary><span class="severity-badge ${severityClass(item.severity)}">${escapeHtml(item.severity)}</span> <strong>${escapeHtml(item.customerTitle)}</strong> · ${escapeHtml(item.affectedObject.displayName)} · ${escapeHtml(item.customerStatus)}</summary><p>${escapeHtml(item.summary)}</p>${item.statusBoundary ? `<p class="notverified-caution">${escapeHtml(item.statusBoundary)}</p>` : ''}${renderKeyEvidence(item.keyEvidence, item.fingerprint)}<p><strong>Recommended action:</strong> ${escapeHtml(item.recommendation)}</p><small class="technical-secondary">${escapeHtml(item.ruleId)}</small></details>`).join('')}</div></section>`;
};
