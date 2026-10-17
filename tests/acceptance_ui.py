"""قبول محلي: 15 MiB، أحداث تقدم وOTP محاكى؛ لا شبكة خارجية أو بريد حقيقي."""
import json,time
from pathlib import Path
from playwright.sync_api import sync_playwright
ROOT=Path(__file__).resolve().parents[1]
with sync_playwright() as p:
 browser=p.chromium.launch(executable_path='/usr/bin/chromium',headless=True,args=['--no-sandbox'])
 context=browser.new_context(service_workers='block')
 page=context.new_page()
 page.route('**/*',lambda route:route.continue_() if route.request.url.startswith('http://127.0.0.1:8766/') else route.abort())
 page.goto('http://127.0.0.1:8766/')
 page.wait_for_function("document.getElementById('authBadge').textContent!=='جارٍ التحقق'")
 page.locator('#googleBtn').click();assert 'error' in page.locator('#googleStatus').get_attribute('class')
 # 8 × 1.875 MiB = 15 MiB؛ سطور قصيرة كثيرة لا ملف minified سهل فقط.
 size=15*1024*1024//8
 content=(b'eval(userInput);\n'*(size//len(b"eval(userInput);\n")+1))[:size]
 assert len(content)==size
 files=[{'name':f'large-{i}.js','mimeType':'text/javascript','buffer':content} for i in range(8)]
 page.locator('#filesInput').set_input_files(files)
 page.locator('#fileConsent').check()
 page.evaluate("window.beats=0;window.maxGap=0;window.lastBeat=performance.now();window.beatTimer=setInterval(()=>{const n=performance.now();window.maxGap=Math.max(window.maxGap,n-window.lastBeat);window.lastBeat=n;window.beats++},30);window.progressMessages=[];new MutationObserver(()=>window.progressMessages.push(document.getElementById('scanStatus').textContent)).observe(document.getElementById('scanStatus'),{childList:true,subtree:true,characterData:true})")
 started=time.monotonic();page.locator('#analyzeBtn').click()
 page.wait_for_function("document.getElementById('scanStatus').classList.contains('success')",timeout=90000)
 stats=page.evaluate("({beats:window.beats,maxGap:window.maxGap,progress:window.progressMessages.filter(x=>x.includes('جارٍ فحص')).length})")
 page.evaluate('clearInterval(window.beatTimer)')
 assert stats['beats']>=5,stats
 assert stats['maxGap']<1000,stats
 assert stats['progress']>0,stats
 stats['seconds']=round(time.monotonic()-started,2)
 stats['bytes']=15*1024*1024
 assert page.locator('.finding').count()<=200
 # OTP: كل الخادم محاكى؛ لا بيانات اعتماد ولا إرسال بريد.
 auth=context.new_page()
 auth.route('**/config.js',lambda r:r.fulfill(content_type='text/javascript',body="export const SUPABASE_URL='https://auth.invalid';export const SUPABASE_PUBLISHABLE_KEY='test';export const EMAIL_OTP_READY=true;"))
 auth.route('**/supabase-client.js',lambda r:r.fulfill(content_type='text/javascript',body="export function createClient(){return {auth:{getSession:async()=>({data:{session:null}}),onAuthStateChange:()=>{},signInWithOtp:async()=>({error:null})}}}"))
 auth.goto('http://127.0.0.1:8766/')
 auth.locator('#emailInput').fill('wrong@example.test');auth.locator('#sendCodeBtn').click()
 auth.locator('#otpForm').wait_for(state='visible');auth.locator('#changeEmailBtn').click()
 assert auth.locator('#emailForm').is_visible()
 assert auth.locator('#otpForm').is_hidden()
 assert auth.locator('#resendBtn').inner_text()=='إعادة إرسال الرمز'
 stats['otpChangeEmail']='passed';stats['googleErrorStyle']='passed'
 (ROOT/'acceptance-results.json').write_text(json.dumps(stats,ensure_ascii=False,indent=2)+'\n')
 print(json.dumps(stats,ensure_ascii=False))
 browser.close()
