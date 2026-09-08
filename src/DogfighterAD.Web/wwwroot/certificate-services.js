const certificateServicesState = {
  analysisId: null,
  view: null,
  selectedSection: 'authorities',
  selectedAuthority: null,
  selectedTemplate: null
};

const certificateServicesEls = {
  status: document.getElementById('certificateServicesStatus'),
  summary: document.getElementById('certificateServicesSummary'),
  coverage: document.getElementById('certificateServicesCoverage'),
  nav: document.getElementById('certificateServicesNav'),
  authorities: document.getElementById('certificateAuthorities'),
  templates: document.getElementById('certificateTemplates'),
  findings: document.getElementById('certificateFindings')
};

function csAdcsFindings() {
  return (state.report?.findings ?? []).filter(finding => String(finding.ruleId ?? '').startsWith('ADCS.'));
}

function csFindingsFor(stableId) {
  return csAdcsFindings().filter(finding =>
    (finding.affectedObjects ?? []).some(object => object.stableId === stableId));
}

function csFormatInterval(ticks) {
  if (ticks === null || ticks === undefined) return 'Not collected';
  const absolute = Math.abs(Number(ticks));
  if (!Number.isFinite(absolute)) return String(ticks);
  const seconds = absolute / 10000000;
  const days = seconds / 86400;
  if (days >= 1) return `${days.toFixed(days >= 10 ? 0 : 1)} days (${ticks} ticks)`;
  const hours = seconds / 3600;
  return `${hours.toFixed(1)} hours (${ticks} ticks)`;
}

function csHex(value) {
  if (value === null || value === undefined) return 'Not collected';
  const unsigned = Number(value) >>> 0;
  return `0x${unsigned.toString(16).padStart(8, '0').toUpperCase()}`;
}

function csTagList(values, empty = 'None') {
  if (!values?.length) return `<span class="muted">${escapeHtml(empty)}</span>`;
  return `<div class="cs-tags">${values.map(value => `<code>${escapeHtml(value)}</code>`).join('')}</div>`;
}

function csFindingBadges(findings) {
  if (!findings.length) return '<span class="cs-clean">No AD CS risk finding</span>';
  return `<div class="cs-finding-badges">${findings.map(finding =>
    `<span class="severity-badge ${severityClass(finding.severity)}" title="${escapeHtml(finding.ruleId)}">${escapeHtml(finding.severity)}</span>`).join('')}</div>`;
}

function csRenderEvidence(findings) {
  const evidence = findings.flatMap(finding => (finding.evidence ?? []).map(item => ({ finding, item })));
  if (!evidence.length) return '<div class="empty-state compact">No AD CS finding evidence attached.</div>';
  return `<div class="table-wrap"><table><thead><tr><th>Rule / fact</th><th>Value</th><th>Provenance</th></tr></thead><tbody>${evidence.map(({ finding, item }) => `
    <tr>
      <td><strong>${escapeHtml(finding.ruleId)}</strong><code>${escapeHtml(item.path)}</code></td>
      <td>${escapeHtml(item.value ?? '—')}</td>
      <td>${escapeHtml(item.source)}<small>${escapeHtml(item.collectorId)} ${escapeHtml(item.collectorVersion)}<br>${escapeHtml(formatDate(item.observedAt))}</small></td>
    </tr>`).join('')}</tbody></table></div>`;
}

function csRenderAces(aces) {
  if (!aces?.length) return '<div class="empty-state compact">No direct ACE rows in the normalized DACL.</div>';
  return `<div class="table-wrap"><table><thead><tr><th>Trustee</th><th>Type</th><th>Rights</th><th>Scope</th></tr></thead><tbody>${aces.map(ace => `
    <tr>
      <td><code>${escapeHtml(ace.trusteeSid)}</code></td>
      <td>${escapeHtml(ace.accessType)}${ace.isInherited ? '<small>inherited</small>' : '<small>direct</small>'}</td>
      <td>${csTagList(ace.rights ?? [], 'No mapped milestone right')}</td>
      <td><code>${escapeHtml(ace.objectType || 'all / unscoped')}</code><small>${escapeHtml(ace.accessMask)} · flags ${escapeHtml(ace.aceFlags)}</small></td>
    </tr>`).join('')}</tbody></table></div>`;
}

function csEnrollmentPrincipals(template) {
  const grants = (template.directAces ?? []).filter(ace =>
    ace.accessType === 'Allow' && (ace.rights ?? []).some(right => right === 'Enroll' || right === 'AutoEnroll'));
  if (!grants.length) return '<div class="empty-state compact">No direct Enroll/AutoEnroll grant is present in the normalized ACE rows.</div>';
  return `<ul class="object-list">${grants.map(ace => `
    <li><strong><code>${escapeHtml(ace.trusteeSid)}</code></strong><small>${escapeHtml((ace.rights ?? []).filter(right => right === 'Enroll' || right === 'AutoEnroll').join(', '))}${ace.isInherited ? ' · inherited' : ' · direct'}</small></li>`).join('')}</ul>`;
}

function csNtAuthStatus(authority) {
  const trust = certificateServicesState.view?.ntAuth;
  if (!trust?.objectPresent) return { label: 'NTAuth object not present in collected directory posture', tone: 'warn' };
  const trustedHashes = new Set((trust.certificates ?? []).map(certificate => String(certificate.sha256).toLowerCase()));
  const matched = (authority.certificates ?? []).some(certificate => trustedHashes.has(String(certificate.sha256).toLowerCase()));
  return matched
    ? { label: 'CA certificate present in NTAuthCertificates', tone: 'ok' }
    : { label: 'CA certificate not matched in collected NTAuthCertificates', tone: 'warn' };
}

function csCertificateTable(certificates) {
  if (!certificates?.length) return '<div class="empty-state compact">No certificate metadata was collected for this object.</div>';
  return `<div class="table-wrap"><table><thead><tr><th>SHA-256</th><th>Subject / issuer</th><th>Validity</th></tr></thead><tbody>${certificates.map(certificate => `
    <tr>
      <td><code>${escapeHtml(certificate.sha256)}</code><small>serial ${escapeHtml(certificate.serialNumber || '—')}</small></td>
      <td>${escapeHtml(certificate.subject || '—')}<small>issuer: ${escapeHtml(certificate.issuer || '—')}</small></td>
      <td>${escapeHtml(formatDate(certificate.notBefore))}<small>to ${escapeHtml(formatDate(certificate.notAfter))}</small></td>
    </tr>`).join('')}</tbody></table></div>`;
}

function csRenderNtAuthPosture() {
  const trust = certificateServicesState.view?.ntAuth;
  if (!trust) {
    return '<div class="empty-state compact">NTAuth posture is unavailable in this snapshot.</div>';
  }
  const present = trust.objectPresent === true;
  return `
    <div class="cs-kv">
      <span>NTAuthCertificates object</span><strong class="cs-${present ? 'ok' : 'warn'}">${present ? 'Present' : 'Not present'}</strong>
      <span>Collected certificates</span><strong>${escapeHtml(trust.certificates?.length ?? 0)}</strong>
    </div>
    ${present && trust.distinguishedName ? `<code class="cs-block">${escapeHtml(trust.distinguishedName)}</code>` : ''}
    ${present ? csCertificateTable(trust.certificates ?? []) : '<div class="empty-state compact">The Configuration-NC search completed without an NTAuthCertificates object. This is a directory inventory result, not a live certificate-validation verdict.</div>'}`;
}

async function loadCertificateServices(force = false) {
  if (!state.analysisId) {
    certificateServicesState.analysisId = null;
    certificateServicesState.view = null;
    renderCertificateServices();
    return;
  }
  if (!force && certificateServicesState.analysisId === state.analysisId && certificateServicesState.view) {
    renderCertificateServices();
    return;
  }

  certificateServicesEls.status.textContent = 'Loading Certificate Services inventory…';
  try {
    const response = await fetch(`/api/analyses/${state.analysisId}/certificate-services`, { cache: 'no-store' });
    const view = await response.json();
    if (!response.ok) throw new Error(view.error || 'certificate-services-load-failed');
    certificateServicesState.analysisId = state.analysisId;
    certificateServicesState.view = view;
    certificateServicesState.selectedAuthority = view.authorities?.[0]?.stableId ?? null;
    certificateServicesState.selectedTemplate = view.templates?.[0]?.stableId ?? null;
    renderCertificateServices();
  } catch (error) {
    certificateServicesState.view = null;
    certificateServicesEls.status.textContent = `Certificate Services could not be loaded: ${error.message}`;
    certificateServicesEls.summary.innerHTML = '';
    certificateServicesEls.coverage.innerHTML = '';
    certificateServicesEls.nav.classList.add('hidden');
    certificateServicesEls.authorities.innerHTML = '';
    certificateServicesEls.templates.innerHTML = '';
    certificateServicesEls.findings.innerHTML = '';
  }
}

function renderCertificateServices() {
  const view = certificateServicesState.view;
  if (!state.analysisId) {
    certificateServicesEls.status.textContent = 'Run or open an assessment to inspect Certificate Services.';
    certificateServicesEls.summary.innerHTML = '';
    certificateServicesEls.coverage.innerHTML = '';
    certificateServicesEls.nav.classList.add('hidden');
    return;
  }
  if (!view) return;

  const coverage = view.coverage ?? [];
  const adcsFindings = csAdcsFindings();
  const allNotApplicable = coverage.length > 0 && coverage.every(item => item.status === 'NotApplicable');
  if (!view.available) {
    certificateServicesEls.status.textContent = allNotApplicable
      ? 'No Enterprise AD CS directory posture was found. The collector proved this capability not applicable for the assessment.'
      : 'This snapshot has no normalized Certificate Services payload. Legacy or unavailable AD CS evidence remains NotVerified rather than clean.';
    certificateServicesEls.summary.innerHTML = '';
    certificateServicesEls.nav.classList.add('hidden');
    certificateServicesEls.coverage.innerHTML = csCoverageTable(coverage);
    certificateServicesEls.authorities.innerHTML = '';
    certificateServicesEls.templates.innerHTML = '';
    certificateServicesEls.findings.innerHTML = '';
    return;
  }

  const authorityCount = view.authorities?.length ?? 0;
  certificateServicesEls.status.textContent = authorityCount === 0
    ? 'Configuration-NC collection completed, but no Enterprise CA Enrollment Services object was found. Directory NTAuth posture remains visible below; no runtime CA conclusion is inferred.'
    : 'Directory-derived Certificate Services inventory. Runtime CA registry/RPC/web-enrollment conditions are not inferred here.';
  certificateServicesEls.summary.innerHTML = [
    ['Enterprise CAs', authorityCount],
    ['Templates', view.templates?.length ?? 0],
    ['Published templates', (view.templates ?? []).filter(template => template.publishedAuthorities?.length).length],
    ['NTAuth certificates', view.ntAuth?.certificates?.length ?? 0],
    ['AD CS findings', adcsFindings.length]
  ].map(([label, value]) => `<article class="summary-card"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></article>`).join('');
  certificateServicesEls.coverage.innerHTML = csCoverageTable(coverage);
  certificateServicesEls.nav.classList.remove('hidden');
  csActivateSection(certificateServicesState.selectedSection, false);
}

function csCoverageTable(coverage) {
  if (!coverage?.length) return '<div class="empty-state compact">No AD CS capability coverage records are present.</div>';
  return `<details class="cs-coverage"><summary>AD CS collection coverage</summary><div class="table-wrap"><table><thead><tr><th>Capability</th><th>Status</th><th>Items</th><th>Issues</th></tr></thead><tbody>${coverage.map(item => `
    <tr><td><code>${escapeHtml(item.capabilityId)}</code></td><td><span class="status-pill status-${String(item.status).toLowerCase()}">${escapeHtml(item.status)}</span></td><td>${escapeHtml(item.observedItemCount)}</td><td>${escapeHtml((item.issueCodes ?? []).join(', ') || '—')}</td></tr>`).join('')}</tbody></table></div></details>`;
}

function csActivateSection(section, updateState = true) {
  if (updateState) certificateServicesState.selectedSection = section;
  for (const button of certificateServicesEls.nav.querySelectorAll('[data-cs-section]'))
    button.classList.toggle('active', button.dataset.csSection === section);
  certificateServicesEls.authorities.classList.toggle('hidden', section !== 'authorities');
  certificateServicesEls.templates.classList.toggle('hidden', section !== 'templates');
  certificateServicesEls.findings.classList.toggle('hidden', section !== 'findings');
  if (section === 'authorities') csRenderAuthorities();
  if (section === 'templates') csRenderTemplates();
  if (section === 'findings') csRenderFindings();
}

function csRenderAuthorities() {
  const authorities = certificateServicesState.view?.authorities ?? [];
  if (!authorities.length) {
    certificateServicesEls.authorities.innerHTML = `
      <section class="panel cs-detail">
        <div class="detail-heading"><div><span class="eyebrow">Enterprise CA inventory</span><h2>No Enterprise CA objects found</h2></div></div>
        <p>The Configuration-NC search returned no <code>pKIEnrollmentService</code> objects. This is a proven directory inventory result for this assessment, not a claim about CA runtime security.</p>
        <h3>NTAuth directory posture</h3>${csRenderNtAuthPosture()}
      </section>`;
    return;
  }
  if (!authorities.some(item => item.stableId === certificateServicesState.selectedAuthority))
    certificateServicesState.selectedAuthority = authorities[0].stableId;
  const selected = authorities.find(item => item.stableId === certificateServicesState.selectedAuthority) ?? authorities[0];
  const findings = csFindingsFor(selected.stableId);
  const ntauth = csNtAuthStatus(selected);

  certificateServicesEls.authorities.innerHTML = `
    <div class="cs-master-detail">
      <section class="panel cs-list">${authorities.map(authority => `
        <button type="button" class="cs-row ${authority.stableId === selected.stableId ? 'selected' : ''}" data-cs-ca="${escapeHtml(authority.stableId)}">
          <strong>${escapeHtml(authority.name || authority.dnsHostName || authority.stableId)}</strong>
          <small>${escapeHtml(authority.dnsHostName || authority.distinguishedName)}</small>
          ${csFindingBadges(csFindingsFor(authority.stableId))}
        </button>`).join('')}</section>
      <section class="panel cs-detail">
        <div class="detail-heading"><div><span class="eyebrow">Enterprise CA</span><h2>${escapeHtml(selected.name || selected.stableId)}</h2><code>${escapeHtml(selected.stableId)}</code></div></div>
        <div class="detail-meta"><span>DNS <strong>${escapeHtml(selected.dnsHostName || '—')}</strong></span><span>DACL <strong>${escapeHtml(selected.daclState || 'NotVerified')}</strong></span><span>NTAuth <strong class="cs-${ntauth.tone}">${escapeHtml(ntauth.label)}</strong></span></div>
        <h3>Directory object</h3><code class="cs-block">${escapeHtml(selected.distinguishedName)}</code>
        <h3>CA certificate metadata</h3>${csCertificateTable(selected.certificates)}
        <h3>Published templates</h3>${(selected.publishedTemplates ?? []).length ? `<ul class="object-list">${selected.publishedTemplates.map(template => `<li><strong>${escapeHtml(template.name)}</strong><small>${escapeHtml(template.id)}</small></li>`).join('')}</ul>` : '<div class="empty-state compact">No published templates in the collected publication inventory.</div>'}
        <h3>Directory ACL</h3>${csRenderAces(selected.directAces)}
        <h3>NTAuth directory posture</h3>${csRenderNtAuthPosture()}
        <h3>Risk findings</h3>${findings.length ? `<ul class="object-list">${findings.map(finding => `<li><strong>${escapeHtml(finding.title)}</strong><small>${escapeHtml(finding.ruleId)} · ${escapeHtml(finding.status)} · ${escapeHtml(finding.confidence)}</small><p>${escapeHtml(finding.description)}</p></li>`).join('')}</ul>` : '<div class="empty-state compact">No AD CS CA finding for this object.</div>'}
        <h3>Evidence</h3>${csRenderEvidence(findings)}
      </section>
    </div>`;

  for (const button of certificateServicesEls.authorities.querySelectorAll('[data-cs-ca]'))
    button.addEventListener('click', () => { certificateServicesState.selectedAuthority = button.dataset.csCa; csRenderAuthorities(); });
}

function csRenderTemplates() {
  const templates = certificateServicesState.view?.templates ?? [];
  if (!templates.length) {
    certificateServicesEls.templates.innerHTML = '<div class="panel empty-state">No certificate template objects were collected from the Configuration NC.</div>';
    return;
  }
  if (!templates.some(item => item.stableId === certificateServicesState.selectedTemplate))
    certificateServicesState.selectedTemplate = templates[0].stableId;
  const selected = templates.find(item => item.stableId === certificateServicesState.selectedTemplate) ?? templates[0];
  const findings = csFindingsFor(selected.stableId);
  const published = (selected.publishedAuthorities ?? []).length > 0;
  const suppliesSubject = selected.certificateNameFlags !== null && selected.certificateNameFlags !== undefined
    ? (Number(selected.certificateNameFlags) & 0x1) !== 0 : null;
  const approvalRequired = selected.enrollmentFlags !== null && selected.enrollmentFlags !== undefined
    ? (Number(selected.enrollmentFlags) & 0x2) !== 0 : null;

  certificateServicesEls.templates.innerHTML = `
    <div class="cs-master-detail">
      <section class="panel cs-list">${templates.map(template => {
        const objectFindings = csFindingsFor(template.stableId);
        return `<button type="button" class="cs-row ${template.stableId === selected.stableId ? 'selected' : ''}" data-cs-template="${escapeHtml(template.stableId)}">
          <strong>${escapeHtml(template.displayName || template.commonName)}</strong>
          <small>${template.publishedAuthorities?.length ? `Published on ${template.publishedAuthorities.length} CA(s)` : 'Unpublished'}</small>
          ${csFindingBadges(objectFindings)}
        </button>`;
      }).join('')}</section>
      <section class="panel cs-detail">
        <div class="detail-heading"><div><span class="eyebrow">Certificate template</span><h2>${escapeHtml(selected.displayName || selected.commonName)}</h2><code>${escapeHtml(selected.stableId)}</code></div></div>
        <div class="detail-meta"><span>Publication <strong>${published ? 'Published' : 'Unpublished'}</strong></span><span>DACL <strong>${escapeHtml(selected.daclState || 'NotVerified')}</strong></span><span>Risk findings <strong>${findings.length}</strong></span></div>
        <h3>Identity</h3><div class="cs-kv"><span>CN</span><strong>${escapeHtml(selected.commonName)}</strong><span>OID</span><code>${escapeHtml(selected.templateOid || '—')}</code><span>Schema / revision</span><strong>${escapeHtml(selected.schemaVersion ?? '—')} / ${escapeHtml(selected.minorRevision ?? '—')}</strong></div><code class="cs-block">${escapeHtml(selected.distinguishedName)}</code>
        <h3>Published on CA</h3>${published ? `<ul class="object-list">${selected.publishedAuthorities.map(authority => `<li><strong>${escapeHtml(authority.name)}</strong><small>${escapeHtml(authority.dnsHostName || authority.id)}</small></li>`).join('')}</ul>` : '<div class="empty-state compact">This template is not present in the complete normalized CA publication inventory.</div>'}
        <h3>Purposes</h3><div class="cs-kv"><span>EKUs</span>${csTagList(selected.extendedKeyUsages ?? [], 'No stored EKU values')}<span>Application policies</span>${csTagList(selected.applicationPolicies ?? [], 'No stored application-policy values')}</div>
        <h3>Subject / issuance gates</h3><div class="cs-kv"><span>Certificate name flags</span><strong>${escapeHtml(csHex(selected.certificateNameFlags))}${suppliesSubject === null ? '' : suppliesSubject ? ' · enrollee supplies subject' : ' · enrollee cannot supply subject by this flag'}</strong><span>Enrollment flags</span><strong>${escapeHtml(csHex(selected.enrollmentFlags))}${approvalRequired === null ? '' : approvalRequired ? ' · manager approval/pending required' : ' · no manager approval flag'}</strong><span>Authorized signatures</span><strong>${escapeHtml(selected.requiredAuthorizedSignatures ?? 'Not collected')}</strong><span>Private key flags</span><strong>${escapeHtml(csHex(selected.privateKeyFlags))}</strong></div>
        <h3>Validity</h3><div class="cs-kv"><span>Validity period</span><strong>${escapeHtml(csFormatInterval(selected.expirationPeriodTicks))}</strong><span>Overlap period</span><strong>${escapeHtml(csFormatInterval(selected.overlapPeriodTicks))}</strong></div>
        <h3>Enrollment principals</h3>${csEnrollmentPrincipals(selected)}
        <h3>Directory ACL</h3>${csRenderAces(selected.directAces)}
        <h3>Risk findings</h3>${findings.length ? `<ul class="object-list">${findings.map(finding => `<li><strong>${escapeHtml(finding.title)}</strong><small>${escapeHtml(finding.ruleId)} · ${escapeHtml(finding.status)} · ${escapeHtml(finding.confidence)}</small><p>${escapeHtml(finding.description)}</p></li>`).join('')}</ul>` : '<div class="empty-state compact">No AD CS risk finding for this template. Safe templates remain visible by design.</div>'}
        <h3>Evidence</h3>${csRenderEvidence(findings)}
      </section>
    </div>`;

  for (const button of certificateServicesEls.templates.querySelectorAll('[data-cs-template]'))
    button.addEventListener('click', () => { certificateServicesState.selectedTemplate = button.dataset.csTemplate; csRenderTemplates(); });
}

function csRenderFindings() {
  const findings = [...csAdcsFindings()].sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || a.ruleId.localeCompare(b.ruleId));
  if (!findings.length) {
    certificateServicesEls.findings.innerHTML = '<section class="panel empty-state">No AD CS findings were emitted. Inventory remains available under CAs and Templates.</section>';
    return;
  }
  certificateServicesEls.findings.innerHTML = `<section class="panel"><h2>AD CS findings</h2><p class="muted">Directory-derived candidates are intentionally distinguished from fully verified CA runtime conditions.</p><div class="unknown-list">${findings.map(finding => {
    const subject = finding.affectedObjects?.[0]?.displayName || finding.affectedObjects?.[0]?.distinguishedName || finding.affectedObjects?.[0]?.stableId || 'Certificate Services';
    return `<details class="unknown-row"><summary><span class="severity-badge ${severityClass(finding.severity)}">${escapeHtml(finding.severity)}</span> <strong>${escapeHtml(finding.ruleId)}</strong> · ${escapeHtml(subject)}</summary><p>${escapeHtml(finding.description)}</p><p><strong>Risk:</strong> ${escapeHtml(finding.risk)}</p>${csRenderEvidence([finding])}</details>`;
  }).join('')}</div></section>`;
}

for (const button of certificateServicesEls.nav.querySelectorAll('[data-cs-section]'))
  button.addEventListener('click', () => csActivateSection(button.dataset.csSection));

const certificateServicesTab = document.querySelector('.tab[data-tab="certificate-services"]');
if (certificateServicesTab)
  certificateServicesTab.addEventListener('click', () => loadCertificateServices());

const snapshotObserver = new MutationObserver(() => {
  if (certificateServicesState.analysisId !== state.analysisId) {
    certificateServicesState.analysisId = null;
    certificateServicesState.view = null;
  }
});
const snapshotIdElement = document.getElementById('snapshotId');
if (snapshotIdElement) snapshotObserver.observe(snapshotIdElement, { childList: true, characterData: true, subtree: true });
