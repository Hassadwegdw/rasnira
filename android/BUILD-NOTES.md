# بناء APK التجريبي — رصنيرا 0.3.0

الملف الناتج `build/rasnira.apk`، الحزمة `com.rasnira.app`، رقم الإصدار 3. الحد الأدنى Android API 21 (Android 5.0) والهدف API 35. بُنيت الموارد باستخدام منصة API 28 المتوافقة مع أداة aapt المتاحة؛ لا يعني target 35 أن التطبيق اختُبر على Android 15.

## وظائفه وحدوده

اختيار مستندات متعددة عبر `ACTION_OPEN_DOCUMENT` فقط، دون إذن إنترنت أو إذن تخزين شامل. SHA-256 لكامل الملف، وفحص أول 2 MiB من النص لأنماط محدودة وأسرار وعلامة EICAR الاختبارية غير الضارة. حد الملف 20 MiB والمجموعة 100 MiB، مع تقدم n من m في خيط خلفي. يدعم BOM لـUTF-8 وUTF-16LE/BE، ويحجب محتوى الأسرار والتعليقات والسلاسل من قواعد التنفيذ. لا تظهر أسماء الملفات أو تفاصيل الاستثناءات التي قد تحمل معلومات حساسة؛ تُستخدم أرقام الملفات.

ليس مضاد فيروسات شاملًا، ولا يفحص بيانات التطبيقات المحمية أو الجهاز كله. لا فحص مواقع أو تسجيل دخول أو تصدير في هذا الإصدار؛ النتائج داخل التطبيق. لا تنفيذ أو رفع للمحتوى.

## إعادة البناء

تحتاج Java وAndroid build-tools التي توفر aapt وzipalign وapksigner، وملف منصة Android `android.jar`، وملف D8/R8 JAR، وzip. المسارات الافتراضية تخص بيئة البناء الحالية، وليست ملفات مضمنة في حزمة المصدر:

```sh
cd android
ANDROID_PLATFORM=/path/to/android-platform-directory \
R8_JAR=/path/to/r8.jar \
BUILD_TOOLS=/path/to/android-build-tools \
./build.sh
```

`ANDROID_PLATFORM` مجلد يحتوي `android.jar`. الافتراضي الحالي `/tmp/platform28/android-9`، وD8 في `/tmp/d8.jar`، وbuild-tools في `/usr/lib/android-sdk/build-tools/debian`. استخدم SDK موثوقًا؛ أدوات البناء ليست ضمن ملف ZIP. يجمع السكربت جميع مصادر Java، ويحولها إلى DEX ويضبط المحاذاة ويوقّع ويتحقق من APK.

ينشئ السكربت مفتاح اختبار محليًا عند غيابه داخل `.private/rasnira-test.jks`، ويستعمل مفتاح البيئة الحالي عند وجوده. المفتاح الخاص غير مضمن في ZIP ولا Git. مفتاح جديد يعني توقيعًا مختلفًا؛ قد يلزم إزالة النسخة القديمة قبل تثبيت بناء وقّع بمفتاح آخر. لا تستخدم هذا المفتاح أو طريقة التوقيع التجريبية لإصدار إنتاج أو متجر.

## الاختبارات المنجزة

```sh
mkdir -p /tmp/rasnira-java-tests
javac -encoding UTF-8 -d /tmp/rasnira-java-tests \
  src/com/rasnira/app/ScanEngine.java tests/ScanEngineTest.java
java -cp /tmp/rasnira-java-tests ScanEngineTest
apksigner verify --verbose build/rasnira.apk
aapt dump badging build/rasnira.apk
```

نجح `ScanEngineTest: OK`: علامة EICAR، سر عادي وسر مقتبس دون إرجاع قيم، استبعاد نصوص eval في التعليقات والسلاسل والقوالب، كشف التنفيذ الحقيقي بعدها، وBOM لـUTF-8 وUTF-16LE/BE. نجح البناء وD8 والتوقيع v1/v2/v3 وبيانات الحزمة. تحذيرات javac تخص خيارات Java 8 القديمة.

**لم يُشغّل التطبيق على جهاز Android أو محاكي.** لا يوجد تحقق فعلي لمنتقي المستندات أو توافق العرض والأداء على هاتف؛ لذلك يُسلّم APK كتجريبي، لا إصدار إنتاج مختبر ميدانيًا.
