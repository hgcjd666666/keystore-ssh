#!/usr/bin/env bash
# 构建 KeystoreSSH：Android app + root agent
#
# 用法:
#   ./build.sh            # debug APK
#   ./build.sh release    # release APK（R8，约 998KB）
#   ./build.sh agent      # 只编 C agent（aarch64）
#   ./build.sh module     # 打包 Magisk/KSU 模块（agent + 可选 release APK）
#   ./build.sh all        # debug APK + agent + 模块
#
# 依赖环境变量:
#   JAVA_HOME     JDK 17+
#   ANDROID_HOME  SDK（platforms/android-35、build-tools、可选 ndk）
#   GRADLE        gradle 可执行文件（默认 `gradle`）
set -euo pipefail
cd "$(dirname "$0")"

TARGET="${1:-debug}"

: "${ANDROID_HOME:?请设置 ANDROID_HOME（Android SDK）}"

build_app() {
    : "${JAVA_HOME:?请设置 JAVA_HOME（JDK 17+）}"
    GRADLE="${GRADLE:-gradle}"
    command -v "$GRADLE" >/dev/null 2>&1 || { echo "找不到 gradle：$GRADLE" >&2; exit 1; }
    [ -f local.properties ] || echo "sdk.dir=$ANDROID_HOME" > local.properties
    echo ">> gradle :app:assemble$1"
    "$GRADLE" --console=plain ":app:assemble$1"
    ls -lh app/build/outputs/apk/*/app-*.apk
}

build_agent() {
    local ndk="${ANDROID_NDK_HOME:-}"
    if [ -z "$ndk" ]; then
        if [ -d "$ANDROID_HOME/ndk" ]; then
            ndk="$ANDROID_HOME/ndk/$(ls -1 "$ANDROID_HOME/ndk" | sort -V | tail -1)"
        fi
    fi
    : "${ndk:?请设置 ANDROID_NDK_HOME（或把 NDK 放在 \$ANDROID_HOME/ndk 下）}"
    local cc="$ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android24-clang"
    [ -x "$cc" ] || { echo "找不到 $cc" >&2; exit 1; }
    echo ">> 编译 agent/ksv-agent (aarch64)"
    "$cc" -O2 -Wall -Wextra -o agent/ksv-agent agent/ksv-agent.c
    ls -lh agent/ksv-agent
}

build_module() {
    [ -x agent/ksv-agent ] || build_agent

    local ver stage out
    ver=$(sed -n 's/^version=//p' magisk/module.prop)
    stage="build/magisk-stage"
    rm -rf "$stage"
    mkdir -p "$stage/bin"
    cp -a magisk/. "$stage/"
    cp -f agent/ksv-agent "$stage/bin/ksv-agent"

    find "$stage" -type f -exec chmod 0644 {} +
    chmod 0755 "$stage/service.sh" "$stage/customize.sh" \
               "$stage/META-INF/com/google/android/update-binary" \
               "$stage/bin/ksv-agent"

    mkdir -p dist
    out="$(pwd)/dist/keystore-ssh-${ver}.zip"
    rm -f "$out"
    ( cd "$stage" && zip -qr9 "$out" . )
    echo ">> 模块: $out"
    unzip -l "$out" | tail -n +4
    ls -lh "$out"
}

case "$TARGET" in
    debug)   build_app Debug ;;
    release) build_app Release ;;
    agent)   build_agent ;;
    module)  build_module ;;
    all)     build_app Debug; build_agent; build_module ;;
    *)       echo "用法: $0 [debug|release|agent|module|all]" >&2; exit 1 ;;
esac

echo "✓ 完成: $TARGET"
