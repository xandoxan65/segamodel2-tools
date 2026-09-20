#!/usr/bin/env bash
# Build segamod2 i960 toolchain container image (multi-arch capable).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
TARGET="binutils"
IMAGE="${I960_TOOLCHAIN_IMAGE:-segamod2/i960-toolchain:binutils-2.30}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      TARGET="$2"
      shift 2
      ;;
    --image)
      IMAGE="$2"
      shift 2
      ;;
    *)
      echo "usage: $0 [--target binutils|full|decomp|ghidra] [--image TAG]" >&2
      exit 1
      ;;
  esac
done

case "$TARGET" in
  binutils|full|decomp|ghidra) ;;
  *)
    echo "error: unknown target '$TARGET' (expected binutils, full, decomp, or ghidra)" >&2
    exit 1
    ;;
esac

ENGINE="${CONTAINER_ENGINE:-}"
if [[ -z "$ENGINE" ]]; then
  if command -v podman >/dev/null 2>&1; then
    ENGINE=podman
  elif command -v docker >/dev/null 2>&1; then
    ENGINE=docker
  else
    echo "error: need podman or docker (or set CONTAINER_ENGINE)" >&2
    exit 1
  fi
fi

# Default: build for the host's native Linux arch when loading locally.
# Set I960_PLATFORMS=linux/amd64,linux/arm64 to build a manifest list (requires --push).
PLATFORMS="${I960_PLATFORMS:-}"
if [[ -z "$PLATFORMS" ]]; then
  case "$(uname -m)" in
    arm64|aarch64) PLATFORMS=linux/arm64 ;;
    x86_64|amd64)  PLATFORMS=linux/amd64 ;;
    *)             PLATFORMS=linux/amd64 ;;
  esac
fi

PUSH="${I960_PUSH:-0}"
BUILD_ARGS=(build --platform "$PLATFORMS" -f "$SCRIPT_DIR/Dockerfile" -t "$IMAGE")

if [[ "$PUSH" == "1" ]]; then
  BUILD_ARGS+=(--push)
else
  # Local load supports a single platform only.
  if [[ "$PLATFORMS" == *","* ]]; then
    echo "warning: multi-platform load unsupported; building first platform only" >&2
    PLATFORMS="${PLATFORMS%%,*}"
    BUILD_ARGS=(build --platform "$PLATFORMS" -f "$SCRIPT_DIR/Dockerfile" -t "$IMAGE")
  fi
  if [[ "$ENGINE" == "docker" ]]; then
    BUILD_ARGS+=(--load)
  fi
fi

BUILD_ARGS+=("$REPO_ROOT")

echo "engine:   $ENGINE"
echo "context:  $REPO_ROOT"
echo "image:    $IMAGE"
echo "target:   $TARGET"
echo "platform: $PLATFORMS"
BUILD_ARGS+=(--target "$TARGET")
exec "$ENGINE" "${BUILD_ARGS[@]}"
