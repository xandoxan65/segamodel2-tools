#!/usr/bin/env bash
# Build Ghidra decompile + sleigh natives for the current Linux platform when missing.
set -euo pipefail

LIB="${SEGAMOD2_CONTAINER_LIB:-/usr/local/lib/segamod2}"
# shellcheck source=decomp-platform.sh
source "$LIB/decomp-platform.sh"

GHIDRA_ROOT="${GHIDRA_ROOT:-/opt/ghidra}"
GRADLE_VERSION="${GRADLE_VERSION:-9.4.1}"
platform="$(decomp_ghidra_platform)"
native_dir="$(decomp_ghidra_native_dir)"
decompile="${native_dir}/decompile"
sleigh="${native_dir}/sleigh"

if [[ -x "$decompile" && -x "$sleigh" ]]; then
  echo "ghidra natives ok: $native_dir"
  exit 0
fi

echo "building ghidra natives for ${platform} → ${native_dir}"

if [[ -z "${JAVA_HOME:-}" || ! -x "${JAVA_HOME}/bin/java" ]]; then
  echo "error: JAVA_HOME must point at a JDK (got '${JAVA_HOME:-}')" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends g++ make bison flex wget unzip ca-certificates
rm -rf /var/lib/apt/lists/*

wget -q "https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip" -O /tmp/gradle.zip
unzip -q /tmp/gradle.zip -d /opt
export PATH="/opt/gradle-${GRADLE_VERSION}/bin:${PATH}"

cd "${GHIDRA_ROOT}/Ghidra/Features/Decompiler"
gradle "buildNatives_${platform}" --no-daemon

mkdir -p "$native_dir"
cp "build/os/${platform}/decompile" "build/os/${platform}/sleigh" "$native_dir/"
chmod +x "$decompile" "$sleigh"

rm -rf build "/opt/gradle-${GRADLE_VERSION}" /tmp/gradle.zip
echo "ghidra natives installed: $native_dir"
