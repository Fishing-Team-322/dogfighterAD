#!/usr/bin/env python3
"""Offline DOM regression suite for the existing Web UI.

Only local HTML/CSS/JS and synthetic JSON responses are used. No LDAP/SMB,
real .dogad parsing, ASP.NET server, or external network is involved.
Requires Python 3.10+ and Playwright (test tooling only, not an app dependency).
Example: python tests/Web.Ui/smoke.py --chromium /usr/bin/chromium
"""
from __future__ import annotations
import argparse
import copy
import json
import re
import shutil
import subprocess
from pathlib import Path
from playwright.sync_api import sync_playwright, expect

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / 'src/DogfighterAD.Web/wwwroot'
FIXTURE = json.loads(Path(__file__).with_name('fixture.json').read_text(encoding='utf-8'))
BOOTSTRAP = r"""fixture => {
 window.__fixture = fixture;
 window.__uiTest = { requests: [], index: 0, presentationFail: false, certificateFail: false, importFail: false,
   deferPresentation: false, deferCertificate: false, scanState: 'collecting', pending: [] };
 window.fetch = async (url, init = {}) => {
   const test = window.__uiTest;
   const path = String(url);
   test.requests.push({url: path, method: init.method || 'GET', headers: init.headers || {}});
   const response = (data, status = 200) => new Response(JSON.stringify(data), {status, headers: {'Content-Type':'application/json'}});
   const clone = value => JSON.parse(JSON.stringify(value));
   if (path === '/api/status') return response({mode:'local-assessment', bind:'http://127.0.0.1:5090'});
   if (path === '/api/analyze') {
     test.importBody = await init.body.text();
     if (test.importFail) return response({code:'dogad.container.invalid'},400);
     return response({analysisId:`analysis-${++test.index}`, report:clone(fixture.report)});
   }
   if (path.endsWith('/presentation')) {
     if (test.presentationFail) return response({error:'presentation-load-failed'},503);
     const data = clone(fixture.presentation);
     if (test.deferPresentation) return new Promise(resolve => test.pending.push(() => resolve(response(data))));
     return response(data);
   }
   if (path.endsWith('/certificate-services')) {
     if (test.certificateFail) return response({error:'inventory-load-failed'},503);
     const data = clone(fixture.certificateServices);
     if (test.deferCertificate) return new Promise(resolve => test.pending.push(() => resolve(response(data))));
     return response(data);
   }
   if (path === '/api/assessments' && init.method === 'POST') {
     test.lastAssessment = JSON.parse(init.body);
     return response({assessmentId:'assessment-1'},202);
   }
   if (path.endsWith('/cancel')) { test.scanState = 'canceled'; return response({canceled:true}); }
   if (path === '/api/assessments/assessment-1') return response({
     assessmentId:'assessment-1', state:test.scanState, target:'dc.lab.example.test', profile:'audit-full',
     snapshotStatus: test.scanState === 'complete' ? 'Partial' : null,
     snapshotPath: test.scanState === 'complete' ? '/local/assessment.dogad' : null,
     analysisId: test.scanState === 'complete' ? 'assessment-analysis' : null,
     progress:[{collectorId:'ad.ldap.rootdse',state:'Completed',elapsed:'00:00:00.050',issueCode:null}]
   });
   if (path === '/api/analyses/assessment-analysis') return response(clone(fixture.report));
   throw new Error(`Unexpected request in offline UI test: ${path}`);
 };
}"""


def setup(browser, fixture=None, width=1440):
    page = browser.new_page(viewport={'width': width, 'height': 960})
    page.set_default_timeout(5000)
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    # Inject the exact local assets into about:blank. This also works in offline
    # environments that disallow browser URL navigation. No production file is
    # changed. HTTP resource delivery and server CSP are not exercised here.
    html = (WEB / 'index.html').read_text(encoding='utf-8')
    html = re.sub(r'<link[^>]+rel="stylesheet"[^>]*>', '', html)
    html = re.sub(r'<script[^>]*src=[^>]+></script>', '', html)
    page.set_content(html)
    page.evaluate(BOOTSTRAP, fixture or FIXTURE)
    for name in ['styles.css', 'certificate-services.css', 'finding-presentation.css']:
        page.add_style_tag(content=(WEB / name).read_text(encoding='utf-8'))
    for name in ['app.js', 'certificate-services-core.js', 'finding-presentation.js']:
        page.add_script_tag(content=(WEB / name).read_text(encoding='utf-8'))
    return page, errors


def nav(page, section):
    if page.locator('#openNavigation').is_visible() and not page.locator('#sidebar').is_visible():
        page.click('#openNavigation')
    page.click('#nav-' + section)
    expect(page.locator('#nav-' + section)).to_have_attribute('aria-current', 'page')
    expect(page.locator('#tab-' + section)).to_be_visible()


def import_snapshot(page, wait=True):
    previous = page.evaluate('state.analysisId')
    nav(page, 'import')
    page.locator('#snapshotFile').set_input_files({'name':'fixture.dogad','mimeType':'application/octet-stream','buffer':b'TEST-ONLY-DOGAD-BYTES'})
    page.click('#analyzeButton')
    page.wait_for_function('old => state.analysisId && state.analysisId !== old', arg=previous)
    if wait:
        page.wait_for_function('findingPresentationState.view !== null && findingPresentationState.analysisId === state.analysisId')


def no_overflow(page):
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth + 1'), page.evaluate('({width:innerWidth,scroll:document.documentElement.scrollWidth})')


def test_empty_navigation(page):
    expect(page.locator('#overviewEmpty')).to_be_visible()
    expect(page.locator('#exportJson')).to_be_disabled()
    for section in ['findings', 'technical', 'certificate-services', 'import', 'overview']:
        nav(page, section)
        assert page.locator('.workspace > .tab-page.active').count() == 1
        assert page.locator('.main-nav [aria-current="page"]').count() == 1
    assert not page.evaluate('__uiTest.requests.some(r => r.url === "/api/analyze")')


def test_import_dashboard(page):
    import_snapshot(page)
    expect(page.locator('.summary-card.posture > strong')).to_have_text(FIXTURE['presentation']['summary']['overallPosture'])
    expect(page.locator('.priorities li')).to_have_count(3)
    expect(page.locator('.summary-card.high > strong')).to_have_text('3')
    expect(page.locator('.summary-card.warn > strong')).to_have_text('2')
    expect(page.locator('#exportJson')).to_be_enabled()
    assert page.evaluate('state.report') == FIXTURE['report']
    assert page.evaluate('__uiTest.importBody') == 'TEST-ONLY-DOGAD-BYTES'
    req = page.evaluate('__uiTest.requests.find(r => r.url === "/api/analyze")')
    assert req['method'] == 'POST' and req['headers']['X-Dogfighter-Filename'] == 'fixture.dogad'
    assert req['headers']['Content-Type'] == 'application/octet-stream'


def test_finding_filters_and_modes(page):
    import_snapshot(page); nav(page, 'findings')
    expect(page.locator('.finding-row')).to_have_count(7)
    page.select_option('#severityFilter', 'High'); expect(page.locator('.finding-row')).to_have_count(3)
    page.select_option('#statusFilter', 'Potential'); expect(page.locator('.finding-row')).to_have_count(2)
    page.fill('#findingSearch', 'impersonation'); expect(page.locator('.finding-row')).to_have_count(1)
    expect(page.locator('.finding-row .status-pill')).to_have_text('Potential')
    page.locator('.finding-row').click()
    expect(page.locator('#findingDetail .status-boundary')).to_contain_text('issuance were not verified')
    page.click('[data-finding-mode="technical"]')
    expect(page.locator('#findingDetail h2')).to_have_text(FIXTURE['report']['findings'][0]['title'])
    expect(page.locator('#findingDetail')).to_contain_text('template.certificateNameFlags')
    page.click('[data-finding-mode="overview"]')
    page.fill('#findingSearch', 'NO-SUCH-OBJECT'); expect(page.locator('.finding-row')).to_have_count(0)
    page.click('#clearFindingFilters'); expect(page.locator('.finding-row')).to_have_count(7)
    assert page.evaluate('state.report') == FIXTURE['report']


def test_technical_sections(page):
    import_snapshot(page); nav(page, 'technical')
    expect(page.locator('#coverageBody tr')).to_have_count(7)
    page.click('[data-technical="unknowns"]')
    expect(page.locator('.customer-notverified')).to_have_count(2)
    page.locator('.customer-notverified summary').first.click()
    expect(page.locator('#unknownList')).to_contain_text('not be interpreted as a clean result')
    page.locator('#unknownList > .disclosure > summary').click()
    expect(page.locator('#unknownList pre')).to_contain_text('ca.runtimePolicy')
    page.locator('#technical-unknowns').focus(); page.keyboard.press('ArrowRight')
    expect(page.locator('#technical-evidence')).to_have_attribute('aria-selected','true')
    expect(page.locator('#evidenceBody tr')).to_have_count(7)
    page.fill('#evidenceSearch', 'template.certificateNameFlags')
    expect(page.locator('#evidenceBody tr')).to_have_count(1)
    page.locator('#evidenceBody button').click()
    expect(page.locator('[data-finding-mode="technical"]')).to_have_attribute('aria-pressed','true')
    expect(page.locator('#findingDetail h2')).to_have_text(FIXTURE['report']['findings'][0]['title'])


def test_evidence_pagination(page):
    page.evaluate("""() => {
      const sample = __fixture.report.findings[0].evidence[0];
      __fixture.report.findings[0].evidence = Array.from({length:245},(_,i) => ({...sample, factId:`fixture-fact-${i}`, value:`value-${i}`}));
    }""")
    import_snapshot(page)
    expect(page.locator('#evidenceBody tr')).to_have_count(0)
    nav(page,'technical');page.click('[data-technical="evidence"]')
    expect(page.locator('#evidenceBody tr')).to_have_count(100)
    expect(page.locator('#evidencePage')).to_have_text('Page 1 of 3')
    page.click('#evidenceNext');expect(page.locator('#evidencePage')).to_have_text('Page 2 of 3')
    page.click('#evidenceNext');expect(page.locator('#evidenceBody tr')).to_have_count(51)
    expect(page.locator('#evidenceNext')).to_be_disabled()
    page.fill('#evidenceSearch','fixture-fact-244')
    expect(page.locator('#evidenceBody tr')).to_have_count(1)
    expect(page.locator('#evidencePage')).to_have_text('Page 1 of 1')
    expect(page.locator('#evidenceBody')).to_contain_text('value-244')


def test_certificate_inventory(page):
    import_snapshot(page); nav(page,'certificate-services')
    expect(page.locator('#certificateAuthorities .cs-row')).to_have_count(1)
    page.locator('#certificateAuthorities .cs-disclosure > summary').filter(has_text='CA certificate metadata').click()
    expect(page.locator('#certificateAuthorities .cs-detail')).to_contain_text('1234567890abcdef')
    page.click('[data-cs-section="risky"]')
    expect(page.locator('#certificateRiskyTemplates .cs-row')).to_have_count(2)
    page.locator('#certificateRiskyTemplates .cs-row').first.click()
    page.locator('#certificateRiskyTemplates .customer-object-summary .disclosure > summary').click()
    page.locator('#certificateRiskyTemplates [data-open-mode="technical"]').click()
    expect(page.locator('[data-finding-mode="technical"]')).to_have_attribute('aria-pressed','true')
    assert page.evaluate('state.selectedFingerprint') == FIXTURE['report']['findings'][0]['fingerprint']
    nav(page,'certificate-services'); page.click('[data-cs-section="templates"]')
    expect(page.locator('#certificateTemplates .cs-row')).to_have_count(3)
    page.fill('#certificateInventorySearch','Secure Web')
    expect(page.locator('#certificateTemplates .cs-row')).to_have_count(1)
    page.locator('#certificateTemplates .cs-row').click()
    expect(page.locator('#certificateTemplates .cs-detail')).to_contain_text('No risk finding emitted')
    page.locator('#certificateTemplates .cs-disclosure > summary').filter(has_text='Subject / issuance gates').click()
    expect(page.locator('#certificateTemplates .cs-detail')).to_contain_text('0x00000001')
    page.click('[data-cs-section="findings"]')
    expect(page.locator('#certificateFindings .unknown-row')).to_have_count(3)
    assert page.evaluate('state.report') == FIXTURE['report']


def test_assessment_cancel(page):
    nav(page,'import')
    page.fill('#assessmentTarget','dc.lab.example.test')
    page.select_option('#authenticationMode','explicit')
    page.fill('#assessmentUsername',r'LAB\tester')
    page.fill('#assessmentPassword','UI-TEST-PASSWORD')
    page.select_option('#ldapAuthMode','ntlm')
    page.check('#useLdaps'); page.fill('#ldapPort','636')
    page.fill('#sysvolAuthorities','pki01.lab.example.test, files.lab.example.test')
    page.click('#startAssessment')
    expect(page.locator('#assessmentPassword')).to_have_value('')
    page.wait_for_function('state.assessmentId !== null')
    body=page.evaluate('__uiTest.lastAssessment')
    assert body == dict(target='dc.lab.example.test',profile='audit-full',authentication='explicit',username=r'LAB\tester',password='UI-TEST-PASSWORD',ldapAuth='ntlm',useLdaps=True,ldapPort=636,sysvolAuthorities=['pki01.lab.example.test','files.lab.example.test'])
    nav(page,'overview'); nav(page,'import')
    page.click('#cancelAssessment')
    expect(page.locator('#assessmentState')).to_have_text('Assessment canceled')
    expect(page.locator('#startAssessment')).to_be_enabled()


def test_assessment_complete(page):
    page.evaluate('__uiTest.scanState = "complete"')
    nav(page,'import'); page.fill('#assessmentTarget','dc.lab.example.test'); page.click('#startAssessment')
    page.wait_for_function('state.analysisId === "assessment-analysis" && findingPresentationState.view !== null')
    expect(page.locator('#tab-overview')).to_be_visible()
    nav(page,'import')
    expect(page.locator('#snapshotDownload')).to_have_attribute('href','/api/assessments/assessment-1/snapshot')
    expect(page.locator('#snapshotDownload')).to_be_visible()
    expect(page.locator('#collectorProgress')).to_contain_text('ad.ldap.rootdse')


def test_failure_recovery(page):
    nav(page,'import');page.click('#analyzeButton')
    expect(page.locator('#importMessage')).to_contain_text('Choose a .dogad')
    page.locator('#snapshotFile').set_input_files({'name':'wrong.zip','mimeType':'application/zip','buffer':b'x'})
    page.click('#analyzeButton');expect(page.locator('#importMessage')).to_contain_text('.dogad extension')
    assert not page.evaluate('__uiTest.requests.some(r => r.url === "/api/analyze")')
    import_snapshot(page)
    page.evaluate('__uiTest.importFail = true')
    nav(page,'import');page.click('#analyzeButton')
    expect(page.locator('#importMessage')).to_contain_text('dogad.container.invalid')
    assert page.evaluate('state.report') is None
    expect(page.locator('#exportJson')).to_be_disabled()
    page.evaluate('__uiTest.importFail = false; __uiTest.presentationFail = true')
    import_snapshot(page,wait=False)
    expect(page.locator('#presentationNotice')).to_contain_text('unavailable')
    nav(page,'findings'); expect(page.locator('.finding-row')).to_have_count(7)
    expect(page.locator('.technical-fallback')).to_be_visible()
    nav(page,'overview');page.evaluate('__uiTest.presentationFail = false');page.click('#retryPresentation')
    page.wait_for_function('findingPresentationState.view !== null')
    page.evaluate('__uiTest.certificateFail = true'); nav(page,'certificate-services')
    expect(page.locator('#retryCertificateServices')).to_be_visible()
    page.evaluate('__uiTest.certificateFail = false');page.click('#retryCertificateServices')
    expect(page.locator('#certificateAuthorities .cs-row')).to_have_count(1)


def test_unavailable_inventory(page):
    page.evaluate('__fixture.certificateServices = {available:false, coverage:[{capabilityId:"adcs.templates",status:"Partial",observedItemCount:0,issueCodes:["missing-evidence"]}]}')
    import_snapshot(page);nav(page,'certificate-services')
    expect(page.locator('#certificateServicesStatus')).to_contain_text('NotVerified rather than clean')
    expect(page.locator('#certificateServicesNav')).not_to_be_visible()
    page.evaluate('__fixture.certificateServices.coverage[0].status = "NotApplicable"')
    page.evaluate('loadCertificateServices(true)')
    expect(page.locator('#certificateServicesStatus')).to_contain_text('proved this capability not applicable')


def test_stale_responses(page):
    page.evaluate('__uiTest.deferPresentation = true; __uiTest.deferCertificate = true')
    import_snapshot(page,wait=False);nav(page,'certificate-services')
    page.wait_for_function('__uiTest.pending.length === 2')
    page.evaluate('''() => {
      __uiTest.deferPresentation = false; __uiTest.deferCertificate = false;
      __fixture.report.snapshotId = '99999999-9999-4999-8999-999999999999';
      __fixture.presentation.summary.overallPosture = 'CURRENT SNAPSHOT ONLY';
      __fixture.certificateServices.authorities[0].name = 'CURRENT-CA';
    }''')
    import_snapshot(page);nav(page,'certificate-services')
    expect(page.locator('#certificateAuthorities')).to_contain_text('CURRENT-CA')
    page.evaluate('__uiTest.pending.forEach(resolve => resolve())')
    page.wait_for_timeout(50)
    assert page.evaluate('findingPresentationState.analysisId === state.analysisId && certificateServicesState.analysisId === state.analysisId')
    expect(page.locator('#certificateAuthorities')).to_contain_text('CURRENT-CA')
    nav(page,'overview');expect(page.locator('.summary-card.posture > strong')).to_have_text('CURRENT SNAPSHOT ONLY')


def test_mobile_and_reflow(page):
    import_snapshot(page)
    for width in [1440,1280,1024,820,768,760,700,390,320]:
        page.set_viewport_size({'width':width,'height':844})
        for section in ['overview','findings','certificate-services','technical','import']:
            nav(page,section);no_overflow(page)
    page.set_viewport_size({'width':390,'height':844})
    nav(page,'findings');page.locator('.finding-row').first.click()
    expect(page.locator('.finding-detail-panel')).to_be_visible()
    expect(page.locator('.finding-list-panel')).not_to_be_visible()
    no_overflow(page)
    page.click('#backToFindings');expect(page.locator('.finding-list-panel')).to_be_visible()
    page.click('#openNavigation')
    assert page.evaluate('document.getElementById("mainShell").inert')
    expect(page.locator('#sidebar')).to_have_attribute('aria-modal','true')
    for _ in range(10):
        page.keyboard.press('Tab')
        assert page.evaluate('document.getElementById("sidebar").contains(document.activeElement)')
    page.keyboard.press('Escape')
    expect(page.locator('#sidebar')).not_to_be_visible()
    expect(page.locator('#openNavigation')).to_be_focused()
    nav(page,'certificate-services');page.click('[data-cs-section="templates"]')
    page.locator('#certificateTemplates .cs-row').first.click()
    expect(page.locator('#certificateTemplates .cs-detail')).to_be_visible()
    page.locator('#certificateTemplates .detail-back').click()
    expect(page.locator('#certificateTemplates .cs-list')).to_be_visible()


def test_escaped_content(page):
    page.evaluate('''() => {
      const text = '<img src=x onerror="window.__xss=true">';
      __fixture.report.findings[0].title = text;
      __fixture.report.findings[0].description = text;
      __fixture.report.findings[0].evidence[0].value = text;
      __fixture.presentation.findings[0].customerTitle = text;
      __fixture.presentation.findings[0].summary = text;
      __fixture.certificateServices.templates[0].displayName = text;
    }''')
    import_snapshot(page);nav(page,'findings')
    expect(page.locator('#findingDetail')).to_contain_text('<img')
    assert page.locator('#workspace img').count() == 0
    nav(page,'certificate-services');page.click('[data-cs-section="templates"]')
    assert page.locator('#workspace img').count() == 0
    assert not page.evaluate('Boolean(window.__xss)')


def static_checks():
    html=(WEB/'index.html').read_text(encoding='utf-8')
    assert '<title>DogfighterAD</title>' in html, 'Retain the existing HTTP asset smoke contract'
    ids=re.findall(r'\bid="([^"]+)"',html)
    assert len(ids)==len(set(ids)), 'Duplicate HTML IDs'
    assert not re.search(r'\s(?:style|onclick|onload|onerror)=',html,re.I)
    assert not re.search(r'<(?:script|link)[^>]+(?:src|href)="https?://',html)
    assert not re.search(r'linear-gradient|radial-gradient|backdrop-filter|text-shadow', '\n'.join(p.read_text(encoding='utf-8') for p in WEB.glob('*.css')))
    source=(WEB/'app.js').read_text(encoding='utf-8')
    assert not re.search(r'localStorage|sessionStorage',source)
    node=shutil.which('node')
    if node:
        for f in WEB.glob('*.js'): subprocess.run([node,'--check',str(f)],check=True,capture_output=True)
        # Test unchanged URL dispatch without causing a real browser navigation.
        export=re.search(r'function exportAnalysis\(format\) \{.*?\n\}',source,re.S).group(0)
        code="const assert=require('node:assert/strict'); const state={analysisId:'id-1'}; const window={location:{href:''}};"+export+";exportAnalysis('json');assert.equal(window.location.href,'/api/analyses/id-1/json');exportAnalysis('html');assert.equal(window.location.href,'/api/analyses/id-1/html');state.analysisId=null;window.location.href='unchanged';exportAnalysis('json');assert.equal(window.location.href,'unchanged');"
        subprocess.run([node,'-e',code],check=True,capture_output=True)
    return bool(node)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--chromium', help='Optional system Chromium executable path')
    parser.add_argument('--screenshots', type=Path, help='Save synthetic-fixture screenshots here')
    args=parser.parse_args()
    node_checked=static_checks()
    results=[]
    with sync_playwright() as playwright:
        options={'headless':True}
        if args.chromium: options['executable_path']=args.chromium
        browser=playwright.chromium.launch(**options)
        try:
            for test in [test_empty_navigation,test_import_dashboard,test_finding_filters_and_modes,test_technical_sections,test_evidence_pagination,test_certificate_inventory,test_assessment_cancel,test_assessment_complete,test_failure_recovery,test_unavailable_inventory,test_stale_responses,test_mobile_and_reflow,test_escaped_content]:
                page,errors=setup(browser)
                try:
                    test(page)
                    assert not errors, errors
                    results.append({'test':test.__name__,'status':'passed'})
                    print('PASS',test.__name__,flush=True)
                except Exception:
                    print('FAIL',test.__name__,errors,flush=True)
                    raise
                finally:
                    page.close()
            if args.screenshots:
                args.screenshots.mkdir(parents=True,exist_ok=True)
                page,errors=setup(browser)
                import_snapshot(page)
                for section,name in [('overview','overview'),('findings','findings'),('certificate-services','certificate-services'),('import','import-assessment')]:
                    nav(page,section)
                    if section=='certificate-services': page.click('[data-cs-section="risky"]')
                    page.screenshot(path=str(args.screenshots/f'{name}.png'),full_page=True)
                page.set_viewport_size({'width':390,'height':844});nav(page,'overview')
                page.screenshot(path=str(args.screenshots/'mobile-overview.png'),full_page=True)
                assert not errors, errors
                page.close()
            print(json.dumps({'browser':browser.version,'node_syntax_and_export_dispatch':node_checked,'cases':results,'scope':'Offline DOM/fixture tests only; no .NET, real artifact parsing, HTTP delivery, or server CSP test.'},indent=2),flush=True)
        finally:
            browser.close()

if __name__=='__main__':
    main()
