import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
const scannerSource = await readFile(new URL('./scanner.js', import.meta.url), 'utf8');
const { analyzeFiles } = await import(`data:text/javascript;base64,${Buffer.from(scannerSource).toString('base64')}`);

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
