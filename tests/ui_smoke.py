"""اختبار واجهة محلي فقط؛ استجابة فحص الموقع محاكاة وليست تقرير موقع حقيقي."""
import json
from pathlib import Path
from playwright.sync_api import sync_playwright
ROOT=Path(__file__).resolve().parents[1]
with sync_playwright() as p:
    browser=p.chromium.launch(executable_path='/usr/bin/chromium',headless=True,args=['--no-sandbox'])
    page=browser.new_page(viewport={'width':390,'height':844},device_scale_factor=1)
    errors=[]
    page.on('pageerror',lambda e:errors.append(str(e)))
    page.route('**/*',lambda route: route.continue_() if route.request.url.startswith('http://127.0.0.1:8766/') else route.abort())
    page.goto('http://127.0.0.1:8766/')
    page.wait_for_function("!document.getElementById('siteScanBtn').disabled")
    page.locator('#analyzeBtn').click()
    assert 'الإذن' in page.locator('#scanStatus').inner_text()
    marker='X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    page.locator('#filesInput').set_input_files([
        {'name':'demo.js','mimeType':'text/javascript','buffer':b'eval(userInput);'},
        {'name':'test.txt','mimeType':'text/plain','buffer':marker.encode()},
        {'name':'binary.bin','mimeType':'application/octet-stream','buffer':bytes([0,0,255,1])}])
    page.locator('#fileConsent').check()
    page.locator('#analyzeBtn').click()
    page.wait_for_function("!document.getElementById('resultsSection').hidden")
    assert 'EICAR' in page.locator('#findings').inner_text()
    assert 'تنفيذ ديناميكي' in page.locator('#findings').inner_text()
    assert '3 بصمة' in page.locator('#summary').inner_text()
    with page.expect_download() as download:
        page.locator('#jsonBtn').click()
    data=json.loads(Path(download.value.path()).read_text())
    assert len(data['inventory'])==3
    assert data['codeFilesScanned']==1
    assert all(len(f['sha256'])==64 for f in data['inventory'])
    page.locator('#siteScanBtn').click()
    assert 'الإذن' in page.locator('#siteStatus').inner_text()
    page.route('**/api/site-scan',lambda r:r.fulfill(json={'statusCode':200,'bytesRead':12,'coverage':{'scope':'استجابة محاكاة اختبار محلي فقط'},'findings':[],'checks':[{'id':'hsts','status':'not_observed'}]}))
    page.locator('#siteUrl').fill('https://authorized.example/')
    page.locator('#siteConsent').check()
    page.locator('#siteScanBtn').click()
    page.wait_for_function("!document.getElementById('siteJsonBtn').hidden")
    assert 'محاكاة اختبار' in page.locator('#siteResults').inner_text()
    assert '[object Object]' not in page.locator('#siteResults').inner_text()
    page.locator('#clearBtn').click()
    assert page.locator('#resultsSection').is_hidden()
    page.reload();page.wait_for_function("!document.getElementById('siteScanBtn').disabled");page.evaluate('window.scrollTo(0,0)')
    assert page.evaluate('document.documentElement.scrollWidth<=window.innerWidth')
    page.screenshot(path=str(ROOT/'rasnira-preview-mobile.png'),full_page=True)
    assert not errors,errors
    page.emulate_media(color_scheme='light');page.screenshot(path=str(ROOT/'rasnira-preview-light.png'),full_page=True)
    print('نجح اختبار الواجهة: تفويض الملفات والموقع، 3 ملفات وبصمات، EICAR، الشفرة، JSON، محاكاة الموقع، المسح، عرض الهاتف. لا فحص حي.')
    browser.close()
