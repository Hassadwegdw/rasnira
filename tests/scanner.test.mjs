import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
const scannerSource = await readFile(new URL('../public/scanner.js', import.meta.url), 'utf8');
const { analyzeFiles, isSupportedFile, redactSensitive } = await import(`data:text/javascript;base64,${Buffer.from(scannerSource).toString('base64')}`);

const fixtures = [
  { name:'src/app.js', text:`const x = eval(userInput);\nel.innerHTML = request.query;\nconst crypto = require('crypto');\nconst hash = md5(password);\nconst sql = "SELECT * FROM users WHERE name = " + user.name;\nconst child_process = require('child_process'); child_process.exec(cmd);\nconst p = 'AKIA1234567890ABCDEF';\nconst token = 'ghp_abcdefghijklmnopqrstuvwxyz0123456789';\nconst password = 'super-secret-real-value';\n// -----BEGIN RSA PRIVATE KEY-----\nconst anon = 'eyJhbGciOiJIUzI1NiJ9.supabase.anon';` },
  { name:'src/net.py', text:`requests.get(url, verify=False)\nsubprocess.run(cmd, shell=True)` },
  { name:'config.yml', text:`app.run(debug=True)\nCORS(app, supports_credentials=True, origins="*")` },
  { name:'safe.js', text:`const rendered = el.innerHTML;\nconst message = 'hello';\nconst password = 'change-me';\nconst hash = sha256(data);` },
  { name:'README.bin', text:`eval(secret); AKIA1234567890ABCDEF` },
];
const result = analyzeFiles(fixtures);
assert.equal(result.filesScanned, 4, 'يفحص النصوص المدعومة فقط');
assert.ok(result.findings.some(f => f.title === 'تنفيذ ديناميكي للكود'));
assert.ok(result.findings.some(f => f.title === 'إدراج محتوى ديناميكي في HTML'));
assert.ok(result.findings.some(f => f.title === 'Python subprocess مع shell=True'));
assert.ok(result.findings.some(f => f.title === 'تعطيل التحقق من شهادة TLS'));
assert.ok(result.findings.some(f => f.title === 'وضع التصحيح مفعّل'));
assert.ok(result.findings.some(f => f.title === 'سياسة CORS تسمح لأي أصل'));
assert.ok(result.findings.some(f => f.title === 'استعلام SQL قد يكون مركبًا نصيًا'));
assert.ok(result.findings.some(f => f.title === 'تجزئة ضعيفة ضمن سياق كلمة مرور'));
assert.ok(result.findings.some(f => f.title === 'مفتاح وصول AWS محتمل'));
assert.ok(result.findings.some(f => f.title === 'رمز GitHub محتمل'));
assert.ok(result.findings.some(f => f.title === 'ترويسة مفتاح خاص'));
assert.ok(result.findings.some(f => f.title === 'قيمة سرية مضمنة صراحة'));
const serialized = JSON.stringify(result);
for (const secret of ['super-secret-real-value','AKIA1234567890ABCDEF','ghp_abcdefghijklmnopqrstuvwxyz0123456789']) assert.ok(!serialized.includes(secret), `لا يجب إرجاع السر: ${secret}`);
assert.ok(!result.findings.some(f => f.evidence.includes('supabase.anon')));
assert.ok(!result.findings.some(f => f.file === 'safe.js' && ['إدراج محتوى ديناميكي في HTML','قيمة سرية مضمنة صراحة'].includes(f.title)));
assert.ok(result.findings.every(f => f.confidence && f.qualification && f.evidence));
assert.equal(result.linesScanned, fixtures.slice(0,4).reduce((n,f)=>n+f.text.split(/\r?\n/).length,0));
const empty = analyzeFiles([]);
assert.equal(empty.filesScanned, 0);
console.log(`نجحت الاختبارات: ${result.filesScanned} ملفات، ${result.linesScanned} أسطر، ${result.findings.length} مؤشرات؛ اجتاز إخفاء الأسرار والاختبارات السلبية.`);

const mixedSecret = "not-a-real-credential-123";
const mixed = analyzeFiles([{name:"mixed.js",text:`eval(userInput); const password = "${mixedSecret}";`}]);
assert(!JSON.stringify(mixed).includes(mixedSecret), "mixed-line finding must not leak a secret");
// 1: RegExp.exec ليس تشغيل أمر، بينما الاستيراد الحقيقي له سياق ملف.
assert.equal(analyzeFiles([{name:'regex.js',text:'const m=re.exec(line);\nregex.exec(x);\nexec(x);\nmyexecSync(x);'}]).findings.length,0);
const execCases=analyzeFiles([{name:'a.js',text:"const cp=require('child_process');\ncp.exec(userInput);\ncp.execSync(x);\ncp.execFile(x);"},{name:'b.js',text:"import {exec as run} from 'node:child_process';\nrun(userInput);"},{name:'c.js',text:"const {exec}=require('child_process');\nexec(userInput);"}]);
assert.equal(execCases.findings.filter(f=>f.title==='تشغيل أمر نظام').length,5);
assert.equal(analyzeFiles([{name:'x.js',text:'execSync(input);\nexecFile(input);'}]).findings.length,2);
// 2: التعليقات والسلاسل لا تنفذ eval؛ فحص الأسرار يبقى متاحًا داخل السلاسل والتعليقات.
assert.equal(analyzeFiles([{name:'false.js',text:"// eval(x)\n# eval(x)\n/* eval(x)\neval(x) */\n* eval(x)\n'eval(';\nconst text=\"eval(x)\";"}]).findings.length,0);
assert.equal(analyzeFiles([{name:'real.js',text:'eval(input) // eval(x)'}]).findings.length,1);
// 3: أسماء بلا امتداد وإعدادات مهمة مع تقرير صريح لغير المدعوم.
for(const name of ['Dockerfile','Makefile','script','.env.local','.env.production','private.pem','private.key','.npmrc','.pypirc','service.properties.dev'])assert.ok(isSupportedFile(name),name);
const coverage=analyzeFiles([{name:'Dockerfile',text:'FROM node'},{name:'.env.local',text:'password="not-real-but-secret-29"'},{name:'x.pem',text:'-----BEGIN PRIVATE KEY-----'},{name:'unknown.zzz',text:'x'}]);
assert.equal(coverage.filesScanned,3);assert.equal(coverage.unsupportedFiles.length,1);assert.match(coverage.coverage,/3/);assert.ok(coverage.findings.length>=2);
// 4: لا يفحص الذيل غير المقروء من سطر minified طويل، ويسجل الحد بوضوح.
const long=analyzeFiles([{name:'long.js',text:'x'.repeat(2*1024*1024)+' eval(input)'}]);assert.equal(long.truncatedLineCount,1);assert.equal(long.truncatedLines.length,1);assert.equal(long.findings.length,0);
const cap=analyzeFiles([{name:'many.js',text:'eval(input);\n'.repeat(600)}]);assert.equal(cap.findings.length,500);assert.equal(cap.findingsTruncated,100);
const filename='AKIA1234567890ABCDEF';const sanitized=redactSensitive({file:filename,nested:['ghp_abcdefghijklmnopqrstuvwxyz0123456789']});assert.ok(!JSON.stringify(sanitized).includes(filename));
for(const r of [coverage,analyzeFiles([{name:filename+'.js',text:'eval(x); password="never-print-the-whole-value"'}])]){const json=JSON.stringify(r);for(const value of ['not-real-but-secret-29',filename,'never-print-the-whole-value'])assert.ok(!json.includes(value),value)}
console.log('نجحت حالات الإصلاح 1–4، حفظ الاختبارات الأصلية، حد النتائج، وحجب الأسرار بجميع حقول التقرير.');
