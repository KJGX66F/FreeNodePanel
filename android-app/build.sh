#!/bin/bash
# 免费公益节点面板 · 安卓版打包脚本（纯 build-tools 手工管线，无 Gradle/AGP）
# 前置：JDK 17、Android SDK（含 build-tools 与 platform）、Go。
# 工具链定位一律环境变量优先：JAVA_HOME、ANDROID_SDK_ROOT/ANDROID_HOME、GOROOT
# 或 PATH 上的 go；GitHub Actions 的 ubuntu runner 全部现成。
# 只有本机开发环境约定路径（~/workspace/tools/…）作最后兜底。
set -e
cd "$(dirname "$0")"

# JDK：JAVA_HOME 已设则用它；没设且本机约定路径存在则兜底用它；再否则用 PATH 上的 java/javac。
if [ -z "$JAVA_HOME" ] && [ -x "$HOME/workspace/tools/jdk/bin/javac" ]; then
    export JAVA_HOME="$HOME/workspace/tools/jdk"
fi
if [ -n "$JAVA_HOME" ]; then
    export PATH="$JAVA_HOME/bin:$PATH"
fi

# Android SDK：ANDROID_SDK_ROOT / ANDROID_HOME 优先，本机约定路径兜底。
SDK="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
if [ -z "$SDK" ] && [ -d "$HOME/workspace/tools/android-sdk" ]; then
    SDK="$HOME/workspace/tools/android-sdk"
fi
if [ -z "$SDK" ] || [ ! -d "$SDK" ]; then
    echo "找不到 Android SDK：请设置 ANDROID_SDK_ROOT 或 ANDROID_HOME" >&2
    exit 1
fi
# build-tools 取已安装的最高版本；platform 优先 android-34，没有就取最高的。
BT="$(ls -d "$SDK"/build-tools/* | sort -V | tail -1)"
ANDROID_JAR="$SDK/platforms/android-34/android.jar"
if [ ! -f "$ANDROID_JAR" ]; then
    ANDROID_JAR="$(ls "$SDK"/platforms/*/android.jar | sort -V | tail -1)"
fi
echo "SDK=$SDK BT=$BT JAR=$ANDROID_JAR"

# Go：GOROOT/bin/go → PATH 上的 go → 本机约定路径。
GO_BIN=""
if [ -n "$GOROOT" ] && [ -x "$GOROOT/bin/go" ]; then
    GO_BIN="$GOROOT/bin/go"
elif command -v go >/dev/null 2>&1; then
    GO_BIN="$(command -v go)"
elif [ -x "$HOME/workspace/tools/go/bin/go" ]; then
    GO_BIN="$HOME/workspace/tools/go/bin/go"
else
    echo "找不到 Go：请设置 GOROOT 或把 go 放进 PATH" >&2
    exit 1
fi

# 0) 构建 Go 服务二进制（GOOS=android / arm64），作为 .so 放入 APK 的 lib 目录
echo "== 构建 Go 服务 =="
(cd .. && CGO_ENABLED=0 GOOS=android GOARCH=arm64 "$GO_BIN" build -trimpath -tags timetzdata -ldflags "-s -w" -o android-app/native/libfreenodepanel.so .)
mkdir -p build/lib/arm64-v8a
cp native/libfreenodepanel.so build/lib/arm64-v8a/libfreenodepanel.so

# 1) 编译资源 + 链接出基础 APK
echo "== aapt2 compile/link =="
rm -rf build/gen build/classes build/dex
mkdir -p build/gen build/classes build/dex
"$BT/aapt2" compile --dir res -o build/res.zip
"$BT/aapt2" link -o build/base.apk \
    -I "$ANDROID_JAR" \
    --manifest AndroidManifest.xml \
    --java build/gen \
    build/res.zip

# 2) 编译 Java（连同 aapt2 生成的 R.java）
echo "== javac =="
javac -source 8 -target 8 -encoding UTF-8 \
    -cp "$ANDROID_JAR" \
    -d build/classes \
    $(find src build/gen -name '*.java')

# 3) 转 dex
echo "== d8 =="
"$BT/d8" --lib "$ANDROID_JAR" --min-api 26 \
    --output build/dex \
    $(find build/classes -name '*.class')

# 4) 把 dex 与原生库塞进 APK
echo "== 组装 =="
cp build/base.apk build/unsigned.apk
(cd build/dex && zip -q ../unsigned.apk classes.dex)
(cd build && zip -q unsigned.apk lib/arm64-v8a/libfreenodepanel.so)

# 5) 对齐 + 签名
echo "== zipalign / apksigner =="
"$BT/zipalign" -f -p 4 build/unsigned.apk build/aligned.apk
if [ ! -f debug.keystore ]; then
    keytool -genkeypair -v -keystore debug.keystore -storepass android -keypass android \
        -alias androiddebugkey -keyalg RSA -keysize 2048 -validity 10000 \
        -dname "CN=Android Debug,O=FreeNodePanel,C=CN"
fi
"$BT/apksigner" sign \
    --ks debug.keystore --ks-pass pass:android --key-pass pass:android \
    --out build/FreeNodePanel-android.apk \
    build/aligned.apk

echo "== 完成 =="
ls -la build/FreeNodePanel-android.apk
"$BT/apksigner" verify --print-certs build/FreeNodePanel-android.apk
"$BT/aapt2" dump badging build/FreeNodePanel-android.apk
sha256sum build/FreeNodePanel-android.apk
