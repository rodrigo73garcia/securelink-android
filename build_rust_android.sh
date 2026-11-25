#!/bin/bash
# Script para compilar a biblioteca Rust para todos os ABIs Android
# Uso: ./build_rust_android.sh

set -e

CORE_DIR="$(dirname "$0")/../core"
ANDROID_JNI_LIBS_DIR="$(dirname "$0")/../android/app/src/main/jniLibs"

# Verifica se rustup está instalado
if ! command -v rustup &> /dev/null; then
    echo "rustup não encontrado. Instale em https://rustup.rs/"
    exit 1
fi

# Adiciona targets Android
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android

# Verifica NDK
if [ -z "$ANDROID_NDK_HOME" ] && [ -z "$NDK_HOME" ]; then
    echo "ANDROID_NDK_HOME ou NDK_HOME não definido."
    echo "Exemplo: export ANDROID_NDK_HOME=/home/ubuntu/Android/Sdk/ndk/26.1.10909125"
    exit 1
fi

NDK_PATH=${ANDROID_NDK_HOME:-$NDK_HOME}

# Configura linker para cada target
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$NDK_PATH/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android24-clang"
export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER="$NDK_PATH/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi24-clang"
export CARGO_TARGET_I686_LINUX_ANDROID_LINKER="$NDK_PATH/toolchains/llvm/prebuilt/linux-x86_64/bin/i686-linux-android24-clang"
export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$NDK_PATH/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android24-clang"

echo "Compilando para arm64-v8a (aarch64-linux-android)..."
cd "$CORE_DIR"
cargo build --target aarch64-linux-android --release --features android
mkdir -p "$ANDROID_JNI_LIBS_DIR/arm64-v8a"
cp target/aarch64-linux-android/release/libsecurelink_core.so "$ANDROID_JNI_LIBS_DIR/arm64-v8a/"

echo "Compilando para armeabi-v7a (armv7-linux-androideabi)..."
cargo build --target armv7-linux-androideabi --release --features android
mkdir -p "$ANDROID_JNI_LIBS_DIR/armeabi-v7a"
cp target/armv7-linux-androideabi/release/libsecurelink_core.so "$ANDROID_JNI_LIBS_DIR/armeabi-v7a/"

echo "Compilando para x86 (i686-linux-android)..."
cargo build --target i686-linux-android --release --features android
mkdir -p "$ANDROID_JNI_LIBS_DIR/x86"
cp target/i686-linux-android/release/libsecurelink_core.so "$ANDROID_JNI_LIBS_DIR/x86/"

echo "Compilando para x86_64 (x86_64-linux-android)..."
cargo build --target x86_64-linux-android --release --features android
mkdir -p "$ANDROID_JNI_LIBS_DIR/x86_64"
cp target/x86_64-linux-android/release/libsecurelink_core.so "$ANDROID_JNI_LIBS_DIR/x86_64/"

echo "✅ Todas as bibliotecas compiladas e copiadas para $ANDROID_JNI_LIBS_DIR"
ls -la "$ANDROID_JNI_LIBS_DIR"/**/libsecurelink_core.so