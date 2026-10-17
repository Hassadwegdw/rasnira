#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
ROOT="$(cd .. && pwd)"
PLATFORM="${ANDROID_PLATFORM:-/tmp/platform28/android-9}"
R8="${R8_JAR:-/tmp/d8.jar}"
BT="${BUILD_TOOLS:-/usr/lib/android-sdk/build-tools/debian}"
OUT="$PWD/build"; rm -rf "$OUT"; mkdir -p "$OUT/classes" "$OUT/dex" "$OUT/unsigned"
[[ -f "$PLATFORM/android.jar" ]] || { echo "Missing android.jar: $PLATFORM" >&2; exit 1; }
[[ -f "$R8" ]] || { echo "Missing D8 jar: $R8" >&2; exit 1; }
"$BT/aapt" package -f -M AndroidManifest.xml -S res -I "$PLATFORM/android.jar" -F "$OUT/resources.ap_"
find src -name "*.java" -print0 | xargs -0 javac -encoding UTF-8 -source 8 -target 8 -bootclasspath "$PLATFORM/android.jar" -d "$OUT/classes"
java -cp "$R8" com.android.tools.r8.D8 --min-api 21 --lib "$PLATFORM/android.jar" --output "$OUT/dex" $(find "$OUT/classes" -name "*.class" -print)
cp "$OUT/resources.ap_" "$OUT/unsigned/app.apk"; (cd "$OUT/dex" && zip -q -0 "$OUT/unsigned/app.apk" classes.dex)
"$BT/zipalign" -f 4 "$OUT/unsigned/app.apk" "$OUT/rasnira-aligned.apk"
KEY="$PWD/.private/rasnira-test.jks"
if [[ ! -f "$KEY" ]]; then mkdir -p "$(dirname "$KEY")"; keytool -genkeypair -noprompt -keystore "$KEY" -storepass rasnira-local-only -keypass rasnira-local-only -alias rasnira -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=Rasnira Local Test, OU=Build, O=Rasnira, L=Local, ST=Local, C=XX"; chmod 600 "$KEY"; fi
apksigner sign --ks "$KEY" --ks-pass pass:rasnira-local-only --key-pass pass:rasnira-local-only --out "$OUT/rasnira.apk" "$OUT/rasnira-aligned.apk"
apksigner verify --verbose "$OUT/rasnira.apk"
"$BT/aapt" dump badging "$OUT/rasnira.apk"
echo "APK: $OUT/rasnira.apk"
