# syntax=docker/dockerfile:1
# segamod2 decomp container — i960 cross toolchain + Ghidra headless.
#
# Targets:
#   binutils  — gas/ld/objdump only (fast)
#   full      — binutils + GCC 2.95.3 + newlib
#   decomp    — full + Ghidra 12.1.2 + i960 processor + Python deps (default)
#   ghidra    — alias of decomp (backward compatible)
#
# Build: tooling/i960/container/build-decomp-image.sh
# Shell: tooling/i960/container/shell.sh

ARG BINUTILS_VERSION=2.30
ARG GCC_VERSION=2.95.3
ARG NEWLIB_VERSION=1.8.2
ARG TOOLCHAIN_PREFIX=/opt/i960-elf

FROM debian:bookworm-slim AS binutils-builder

ARG BINUTILS_VERSION
ARG DEBIAN_FRONTEND=noninteractive
ARG TOOLCHAIN_PREFIX

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    file \
    wget \
    xz-utils \
 && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    wget -q "https://ftp.gnu.org/gnu/binutils/binutils-${BINUTILS_VERSION}.tar.xz"; \
    tar xf "binutils-${BINUTILS_VERSION}.tar.xz"; \
    mkdir bld; \
    cd bld; \
    "../binutils-${BINUTILS_VERSION}/configure" \
        --prefix="${TOOLCHAIN_PREFIX}" \
        --target=i960-elf \
        --disable-nls \
        --disable-werror \
        --enable-obsolete; \
    make -j"$(nproc)"; \
    make install

FROM debian:bookworm-slim AS gcc-builder

ARG GCC_VERSION
ARG NEWLIB_VERSION
ARG DEBIAN_FRONTEND=noninteractive
ARG TOOLCHAIN_PREFIX

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    wget \
    bison \
    flex \
    gawk \
    autoconf \
    texinfo \
    patch \
 && rm -rf /var/lib/apt/lists/*

COPY --from=binutils-builder "${TOOLCHAIN_PREFIX}" "${TOOLCHAIN_PREFIX}"
ENV PATH="${TOOLCHAIN_PREFIX}/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

COPY decomp/toolchain/build-i960-toolchain.sh /opt/build-i960-toolchain.sh
RUN chmod +x /opt/build-i960-toolchain.sh \
 && BINUTILS_VERSION="${BINUTILS_VERSION}" GCC_VERSION="${GCC_VERSION}" NEWLIB_VERSION="${NEWLIB_VERSION}" \
    TOOLCHAIN_PREFIX="${TOOLCHAIN_PREFIX}" I960_TOOLCHAIN_PREFIX="${TOOLCHAIN_PREFIX}" \
    I960_TOOLCHAIN_BUILD=/opt/i960-toolchain-build \
    /opt/build-i960-toolchain.sh --gcc-only \
 && rm -rf /opt/i960-toolchain-build /opt/build-i960-toolchain.sh

FROM debian:bookworm-slim AS binutils

ARG TOOLCHAIN_PREFIX

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates file \
 && rm -rf /var/lib/apt/lists/*

COPY --from=binutils-builder "${TOOLCHAIN_PREFIX}" "${TOOLCHAIN_PREFIX}"

ENV PATH="${TOOLCHAIN_PREFIX}/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
WORKDIR /src

LABEL org.opencontainers.image.title="segamod2-i960-binutils" \
      org.segamod2.binutils.version="2.30"

FROM binutils AS full

ARG TOOLCHAIN_PREFIX

COPY --from=gcc-builder "${TOOLCHAIN_PREFIX}" "${TOOLCHAIN_PREFIX}"

LABEL org.opencontainers.image.title="segamod2-i960-toolchain" \
      org.segamod2.gcc.version="2.95.3" \
      org.segamod2.newlib.version="1.8.2"

FROM full AS decomp

ARG GHIDRA_VERSION=12.1.2
ARG GHIDRA_RELEASE_DATE=20260605
ARG GHIDRA_ROOT=/opt/ghidra
ARG GRADLE_VERSION=9.4.1
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    ca-certificates \
    git \
    unzip \
    wget \
    tar \
    xxd \
    g++ \
    make \
    bison \
    flex \
 && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) jdk="OpenJDK21U-jdk_x64_linux_hotspot_21.0.2_13.tar.gz" ;; \
      arm64) jdk="OpenJDK21U-jdk_aarch64_linux_hotspot_21.0.2_13.tar.gz" ;; \
      *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
    esac; \
    url="https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.2%2B13/${jdk}"; \
    wget -q "$url" -O /tmp/jdk.tgz; \
    mkdir -p /opt/java; \
    tar xf /tmp/jdk.tgz -C /opt/java --strip-components=1; \
    rm /tmp/jdk.tgz

ENV JAVA_HOME=/opt/java
ENV PATH="${JAVA_HOME}/bin:${PATH}"

RUN set -eux; \
    url="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_RELEASE_DATE}.zip"; \
    wget -q "$url" -O /tmp/ghidra.zip; \
    unzip -q /tmp/ghidra.zip -d /tmp; \
    mv "/tmp/ghidra_${GHIDRA_VERSION}_PUBLIC" "${GHIDRA_ROOT}"; \
    rm /tmp/ghidra.zip; \
    git clone --depth 1 https://github.com/mumbel/ghidra_i960.git /tmp/ghidra_i960; \
    rm -rf "${GHIDRA_ROOT}/Ghidra/Processors/i960"; \
    cp -R /tmp/ghidra_i960 "${GHIDRA_ROOT}/Ghidra/Processors/i960"; \
    rm -rf /tmp/ghidra_i960

COPY tooling/i960/container/scripts/ /usr/local/lib/segamod2/
RUN chmod +x /usr/local/lib/segamod2/*.sh \
 && ln -sf /usr/local/lib/segamod2/build-i960-gcc.sh /usr/local/bin/build-i960-gcc \
 && ln -sf /src/decomp/toolchain/build-i960-toolchain.sh /usr/local/bin/build-i960-toolchain \
 && ln -sf /usr/local/lib/segamod2/build-ghidra-natives.sh /usr/local/bin/build-ghidra-natives \
 && ln -sf /usr/local/lib/segamod2/ensure-ghidra-natives.sh /usr/local/bin/ensure-ghidra-natives

# Release zip ships linux_x86_64 natives only; compile for arm64 at image build time.
RUN GRADLE_VERSION="${GRADLE_VERSION}" GHIDRA_ROOT="${GHIDRA_ROOT}" /usr/local/lib/segamod2/build-ghidra-natives.sh

COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages -r /tmp/requirements.txt \
 && rm /tmp/requirements.txt

ENV GHIDRA_ROOT=${GHIDRA_ROOT}
ENV PATH=${GHIDRA_ROOT}/support:/opt/i960-elf/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

WORKDIR /src

LABEL org.opencontainers.image.title="segamod2-i960-decomp" \
      org.segamod2.ghidra.version="12.1.2" \
      org.segamod2.gcc.version="2.95.3"

FROM decomp AS ghidra
