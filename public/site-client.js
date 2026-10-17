const $=id=>document.getElementById(id);
let report=null;
const labels={high:'مرتفع',medium:'متوسط',low:'منخفض',info:'معلومة'};
function status(text,error=false){$('siteStatus').textContent=text;$('siteStatus').className=`status${error?' error':''}`}
(async()=>{try{const response=await fetch('/api/capabilities',{cache:'no-store'});const data=await response.json();if(!response.ok||data.siteScan!==true)throw Error();$('siteScanBtn').disabled=false;status('المحرك متاح. لن يتصل بموقع إلا بعد إدخال الرابط وتأكيد الإذن والضغط على الفحص.')}catch{status('محرك الموقع غير متاح على هذه الاستضافة الثابتة. شغّل server.py من حزمة المصدر لفحص مواقعك المصرح بها. نسخة APK الحالية تفحص الملفات فقط. فحص الملفات المحلي متاح.')}})();
$('siteScanBtn').addEventListener('click',async()=>{
 if(!$('siteConsent').checked){status('أكّد الملكية أو الإذن الصريح أولًا.',true);return}
 let url;try{url=new URL($('siteUrl').value.trim());if(url.protocol!=='https:'||url.username||url.password||url.hash)throw Error()}catch{status('أدخل رابط HTTPS صالحًا دون بيانات دخول أو جزء #.',true);return}
 $('siteScanBtn').disabled=true;$('siteResults').replaceChildren();$('siteJsonBtn').hidden=true;report=null;status('جارٍ طلب صفحة واحدة دون تتبع تحويلات…');
 try{
 const response=await fetch('/api/site-scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:url.href,consent:true}),signal:AbortSignal.timeout(20000)});const data=await response.json();if(!response.ok||data.error)throw Error(data.message||data.error||'تعذر الطلب');report=data;
 const note=document.createElement('p');note.className='notice';note.textContent=`HTTP ${data.statusCode??'—'} • ${data.bytesRead??0} بايت. ${typeof data.coverage==='object'?data.coverage.scope:(data.coverage||'مراجعة إعدادات محدودة؛ ليست شهادة أمان.')}`;$('siteResults').append(note);
 const checks=document.createElement('p');checks.className='hint';checks.textContent='الرصد: '+(data.checks||[]).map(c=>`${c.id}: ${c.status==='present'?'موجود':c.status==='observed'?'مؤشر مرصود':'غير مرصود'}`).join(' • ');$('siteResults').append(checks);
 for(const finding of data.findings||[]){const article=document.createElement('article');article.className='finding';const title=document.createElement('h3');title.textContent=`${finding.title} — ${labels[finding.severity]||'معلومة'}`;article.append(title);for(const [label,value] of [['التفصيل',finding.description],['المقترح',finding.fix]])if(value){const p=document.createElement('p');p.textContent=`${label}: ${value}`;article.append(p)}$('siteResults').append(article)}
 if(!data.findings?.length){const p=document.createElement('p');p.textContent='لم تظهر مؤشرات ضمن الاختبارات المحدودة. لا يعني ذلك غياب الثغرات.';$('siteResults').append(p)}
 $('siteJsonBtn').hidden=false;status('اكتملت المراجعة السلبية المحدودة. لا استغلال ولا مسح شامل.');
 }catch(e){status(`تعذر فحص الموقع: ${e.message||'فشل الاتصال'}`,true)}finally{$('siteScanBtn').disabled=false}
});
$('siteJsonBtn').addEventListener('click',()=>{if(!report)return;const blob=new Blob([JSON.stringify(report,null,2)],{type:'application/json'});const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download='rasnira-site-report.json';document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000)});
