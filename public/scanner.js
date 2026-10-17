export const TEXT_EXT = /\.(?:js|jsx|mjs|cjs|ts|tsx|py|rb|php|java|go|rs|cs|cpp?|h|hpp|json|ya?ml|toml|ini|cfg|conf|env|properties|xml|html?|css|sql|sh|bash|gradle|tf|md|pem|key|npmrc|pypirc)$/i;
export function isSupportedFile(name){const base=String(name||'').split(/[\\/]/).pop();return /^(?:Dockerfile|Makefile|\.npmrc|\.pypirc)$/i.test(base)||/^\.env(?:\..*)?$/i.test(base)||/\.properties(?:\..*)?$/i.test(base)||(!base.includes('.')&&!!base)||TEXT_EXT.test(base);}
const PLACEHOLDER=/(?:your[_ -]?(?:key|token|secret|password)|changeme|change[_ -]?me|example|placeholder|dummy|<[^>]+>|\*{3,}|xxx+|test(?:ing)?[_-]?(?:key|secret|token)|redacted)/i;
const RULES=[
{id:'dynamic-eval',re:/\beval\s*\(|\bnew\s+Function\s*\(/g,severity:'high',title:'تنفيذ ديناميكي للكود',description:'استدعاء eval أو Function قد ينفذ مدخلًا غير موثوق؛ راجع المصدر والسياق.',fix:'تجنب التنفيذ الديناميكي واستخدم تحليلًا آمنًا.',confidence:'مرتفعة'},
{id:'dynamic-html',re:/\.(?:innerHTML|outerHTML)\s*=\s*([^;\n]+)/g,severity:'medium',title:'إدراج محتوى ديناميكي في HTML',description:'إسناد محتوى إلى HTML قد يسمح بحقن DOM.',fix:'استخدم textContent أو واجهة آمنة.',confidence:'متوسطة',dynamic:true},
{id:'child-exec',re:/\bchild_process\s*\.\s*exec(?:Sync|File)?\s*\(|\bexec(?:Sync|File)\s*\(/g,severity:'high',title:'تشغيل أمر نظام',description:'تشغيل أوامر النظام خطر عند دمج مدخلات غير موثوقة.',fix:'فضّل واجهات الوسائط المنفصلة وتجنب تركيب الأمر من مدخلات.',confidence:'متوسطة'},
{id:'python-shell',re:/\bsubprocess\.(?:run|Popen|call|check_call|check_output)\s*\([^\n]{0,300}\bshell\s*=\s*True/g,severity:'high',title:'Python subprocess مع shell=True',description:'تفعيل shell قد يؤدي لحقن أوامر.',fix:'اجعل shell=False ومرر الوسائط كمصفوفة.',confidence:'مرتفعة'},
{id:'ssl-disabled',re:/\b(?:verify\s*=\s*False|CERT_NONE|check_hostname\s*=\s*False)\b/g,severity:'high',title:'تعطيل التحقق من شهادة TLS',description:'تعطيل التحقق من الشهادة يضعف حماية الاتصال.',fix:'فعّل التحقق من الشهادة واسم المضيف.',confidence:'مرتفعة'},
{id:'flask-debug',re:/\b(?:app|application)\.run\s*\([^)]*\bdebug\s*=\s*True|\bFLASK_DEBUG\s*=\s*1\b/g,severity:'high',title:'وضع التصحيح مفعّل',description:'تفعيل التصحيح قد يكشف معلومات.',fix:'عطل التصحيح في الإنتاج.',confidence:'متوسطة'},
{id:'weak-hash',re:/\b(?:md5|sha1)\s*\([^\n]{0,160}(?:password|passwd|pwd)|(?:password|passwd|pwd)[^\n]{0,160}\b(?:md5|sha1)\s*\(/gi,severity:'medium',title:'تجزئة ضعيفة ضمن سياق كلمة مرور',description:'MD5/SHA-1 غير مناسبتين لتخزين كلمات المرور.',fix:'استخدم Argon2id أو bcrypt أو scrypt.',confidence:'متوسطة'},
{id:'sql-concat',re:/\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^;\n]{0,240}(?:\+\s*[A-Za-z_$][\w$.]*|\$\{|\bformat\s*\()/gi,severity:'medium',title:'استعلام SQL قد يكون مركبًا نصيًا',description:'تركيب استعلام SQL بالنص قد يتيح حقنًا.',fix:'استخدم معاملات مربوطة.',confidence:'منخفضة'},
{id:'aws-key',re:/\bAKIA[0-9A-Z]{16}\b/g,severity:'high',title:'مفتاح وصول AWS محتمل',description:'عُثر على نمط يشبه معرّف مفتاح AWS.',fix:'ألغ المفتاح أو دوّره.',confidence:'مرتفعة',secret:true},
{id:'github-token',re:/\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/g,severity:'high',title:'رمز GitHub محتمل',description:'عُثر على نمط يشبه رمز GitHub.',fix:'ألغ الرمز ودوّره.',confidence:'مرتفعة',secret:true},
{id:'private-key',re:/-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,severity:'high',title:'ترويسة مفتاح خاص',description:'عُثر على ترويسة مفتاح خاص.',fix:'أزل المفتاح ودوّره أو أبطله.',confidence:'مرتفعة',secret:true},
{id:'explicit-secret',re:/\b(password|passwd|api[_-]?secret|secret[_-]?key|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*(["'`])([^\n"'`]{4,})\2/gi,severity:'high',title:'قيمة سرية مضمنة صراحة',description:'عُثر على إسناد يبدو أنه يحتوي سرًا؛ القيمة محجوبة.',fix:'أزل القيمة ودوّر السر واستخدم مخزن أسرار.',confidence:'متوسطة',secret:true,secretCapture:true},
{id:'wildcard-cors',re:/\b(?:Access-Control-Allow-Origin\s*[:=]\s*["']?\*|(?:cors|CORS)\s*\([^\n)]{0,180}\borigins?\s*[:=]\s*["']?\*|origins?\s*[:=]\s*["']\*)/gi,severity:'medium',title:'سياسة CORS تسمح لأي أصل',description:'السماح لجميع الأصول قد يكون واسعًا.',fix:'حدد الأصول الموثوقة صراحةً.',confidence:'منخفضة',proximity:true}
];
export function redactSensitive(value){if(Array.isArray(value))return value.map(redactSensitive);if(value&&typeof value==='object'){const out={};for(const [k,v] of Object.entries(value))out[redact(k)]=redactSensitive(v);return out;}if(typeof value==='string')return redact(value);return value;}
function redact(s){return String(s).replace(/\bAKIA[0-9A-Z]{16}\b/g,'[محجوب]').replace(/\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/g,'[محجوب]').replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_.-]+/g,'[محجوب]').replace(/-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,'[محجوب]').replace(/\b(password|passwd|api[_-]?secret|secret[_-]?key|access[_-]?token|auth[_-]?token)\b\s*([:=])\s*(["'`])[^\n"'`]*\3/gi,'$1$2[محجوب]');}

const MAX_LINE=5000,MAX_FINDINGS=500;
// ماسك خفيف وليس parser كاملًا: يحافظ على مواضع الحروف دون تشغيل أي شفرة.
function maskLine(line,state){
 let code='',uncommented='';
 for(let i=0;i<line.length;i++){
  const c=line[i],next=line[i+1];
  if(state.block){if(c==='*'&&next==='/'){state.block=false;code+='  ';uncommented+='  ';i++}else{code+=' ';uncommented+=' '}continue}
  if(state.quote){uncommented+=c;code+=' ';if(c==='\\'&&next!==undefined){uncommented+=next;code+=' ';i++;continue}if(c===state.quote)state.quote='';continue}
  if(c==='/'&&next==='*'){state.block=true;code+='  ';uncommented+='  ';i++;continue}
  if((c==='/'&&next==='/')||c==='#'||(/^\s*$/.test(code)&&c==='*')){code+=' '.repeat(line.length-i);uncommented+=' '.repeat(line.length-i);break}
  if(c==='"'||c==="'"||c==='`'){state.quote=c;code+=' ';uncommented+=c;continue}
  code+=c;uncommented+=c;
 }
 // الاقتباسات البسيطة لا تتجاوز السطر عادة؛ يستمر القالب النصي فقط.
 if(state.quote!=='`'&&!/\\$/.test(line))state.quote='';
 return{code,uncommented};
}
function collectBindings(raw,code,bindings){
 let m;
 const namespaces=/\b(?:const|let|var)\s+([\w$]+)\s*=\s*require\s*\(\s*['"](?:node:)?child_process['"]\s*\)|\bimport\s+(?:\*\s+as\s+)?([\w$]+)\s+from\s*['"](?:node:)?child_process['"]/g;
 while((m=namespaces.exec(raw)))if(/\b(?:const|let|var|import)\b/.test(code.slice(m.index,m.index+12)))bindings.namespaces.add(m[1]||m[2]);
 const named=/(?:\b(?:const|let|var)\s*\{([^}]+)\}\s*=\s*require\s*\(\s*['"](?:node:)?child_process['"]\s*\)|\bimport\s*\{([^}]+)\}\s*from\s*['"](?:node:)?child_process['"])/g;
 while((m=named.exec(raw)))if(/\b(?:const|let|var|import)\b/.test(code.slice(m.index,m.index+12))){for(const entry of (m[1]||m[2]).split(',')){const parts=entry.trim().split(/\s+as\s+|\s*:\s*/);if(/^exec(?:Sync|File|FileSync)?$/.test(parts[0]))bindings.functions.add(parts[1]||parts[0])}}
}
function hasChildExec(code,bindings){
 const calls=/\b([\w$]+)(?:\s*\.\s*([\w$]+))?\s*\(/g;let m;
 while((m=calls.exec(code))){if(m[2]){if(bindings.namespaces.has(m[1])&&/^exec(?:Sync|File|FileSync)?$/.test(m[2]))return true}else{const prefix=code.slice(0,m.index);if(/\.\s*$/.test(prefix))continue;if(bindings.functions.has(m[1])||/^exec(?:Sync|File|FileSync)$/.test(m[1]))return true}}
 return false;
}
export function analyzeFiles(files){
 if(!Array.isArray(files))throw new TypeError('files يجب أن تكون مصفوفة');
 const findings=[],unsupportedFiles=[],truncatedLines=[];
 let filesScanned=0,linesScanned=0,truncatedLineCount=0,findingsTruncated=0;
 for(const item of files){
  if(!item||typeof item.name!=='string'||typeof item.text!=='string')continue;
  const filename=redactSensitive(item.name);
  if(!isSupportedFile(item.name)){unsupportedFiles.push({file:filename,reason:'ملف نصي لم يُفحص لأن امتداده غير مدعوم'});continue}
  filesScanned++;
  const lines=item.text.split(/\r?\n/),state={block:false,quote:''},bindings={namespaces:new Set(['child_process']),functions:new Set()};
  for(let i=0;i<lines.length;i++){
   linesScanned++;const original=lines[i];
   if(original.length>MAX_LINE){truncatedLineCount++;if(truncatedLines.length<100)truncatedLines.push({file:filename,line:i+1,originalLength:original.length,scannedLength:MAX_LINE})}
   const line=original.slice(0,MAX_LINE),{code,uncommented}=maskLine(line,state);
   collectBindings(uncommented,code,bindings);
   for(const rule of RULES){
    let matched=false,m;
    if(rule.id==='child-exec')matched=hasChildExec(code,bindings);
    else{
     const source=rule.secret?line:(rule.id==='sql-concat'||rule.id==='wildcard-cors'?uncommented:code);
     rule.re.lastIndex=0;m=rule.re.exec(source);rule.re.lastIndex=0;
     if(!m)continue;
     if(rule.dynamic&&!/(?:\b(?:req|request|user|input|param|query|search|location|data|response|message|document)\b|\$\{|\+|\bconcat\s*\()/i.test(m[1]||''))continue;
     if(rule.secretCapture&&PLACEHOLDER.test(m[3]))continue;
     if(rule.id==='sql-concat'&&!/\+\s*[\w$]|\bformat\s*\(/.test(code)&&!(/`/.test(uncommented)&&/\$\{/.test(uncommented)))continue;
     if(rule.proximity){if(!/\b(?:origins?|CORS|cors|Access-Control-Allow-Origin)\b/.test(code))continue;const around=lines.slice(Math.max(0,i-4),Math.min(lines.length,i+5)).map(x=>x.slice(0,MAX_LINE)).join(' ');if(!/credentials\s*[:=]\s*true|supports_credentials\s*=\s*True|Access-Control-Allow-Credentials\s*[:=]\s*true/i.test(around))continue}
     matched=true;
    }
    if(!matched)continue;
    if(findings.length>=MAX_FINDINGS){findingsTruncated++;continue}
    findings.push({id:`${rule.id}-${filesScanned}-${i+1}`,severity:rule.severity,title:rule.title,description:rule.description,fix:rule.fix,file:filename,line:i+1,evidence:rule.secret?'[محجوب: قيمة سرية محتملة]':'[مقتطف محجوب لحماية الأسرار؛ راجع الملف والسطر محليًا]',confidence:rule.confidence,qualification:'مؤشر ساكن تقريبي يحتاج مراجعة؛ ليس إثباتًا لثغرة.'});
   }
  }
 }
 return redactSensitive({findings,filesScanned,linesScanned,truncatedLines,truncatedLineCount,findingsTruncated,unsupportedFiles,coverage:`فُحصت ${filesScanned} ملفات نصية مدعومة؛ ${unsupportedFiles.length} غير مدعوم؛ حد السطر ${MAX_LINE} محرف؛ نتائج لم تُعرض: ${findingsTruncated}؛ أسطر محدودة الطول: ${truncatedLineCount}.`,generatedAt:new Date().toISOString()});
}
export default analyzeFiles;
