// مؤشرات دفاعية محدودة، لا تنفيذ ولا رفع للملفات ولا قاعدة فيروسات شاملة.
const EICAR='X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
export function decodeFileBytes(bytes){
 if(!(bytes instanceof Uint8Array))throw new TypeError('المحتوى يجب أن يكون بايتات');
 let encoding='utf-8';
 if(bytes[0]===0xff&&bytes[1]===0xfe)encoding='utf-16le';
 else if(bytes[0]===0xfe&&bytes[1]===0xff)encoding='utf-16be';
 const text=new TextDecoder(encoding).decode(bytes),sample=text.slice(0,8192);
 let controls=0;
 for(const char of sample){const c=char.charCodeAt(0);if(c===0||c<8||(c>13&&c<32&&c!==27))controls++}
 const binary=sample.length>0&&controls/sample.length>.015;
 return{text,binary,encoding,binaryReason:binary?'أكثر من 1.5% من العينة محارف تحكم/صفر بعد فك الترميز؛ ESC مستثنى.':''};
}
export async function inspectBytes(name,bytes){
 const hash=await crypto.subtle.digest('SHA-256',bytes);
 const sha256=[...new Uint8Array(hash)].map(n=>n.toString(16).padStart(2,'0')).join('');
 const decoded=decodeFileBytes(bytes);
 const marker=decoded.text.includes(EICAR);
 const findings=marker?[{id:'eicar-test-marker',severity:'info',title:'علامة اختبار EICAR (ليست فيروسًا حقيقيًا)',description:'عُثر على علامة الاختبار القياسية. هذا يختبر القاعدة فقط ولا يثبت وجود برمجية خبيثة.',fix:'إذا أضفت العلامة عمدًا فهي ملف اختبار غير ضار؛ راجع مصدر الملف عند الشك.',file:name,evidence:'EICAR test marker',confidence:'مرتفعة'}]:[];
 return{name,size:bytes.length,sha256,binary:decoded.binary,encoding:decoded.encoding,binaryReason:decoded.binaryReason,findings,coverage:'بصمة SHA-256 وعلامة EICAR فقط؛ لا بحث سحابي ولا قاعدة توقيعات فيروسات.'};
}
