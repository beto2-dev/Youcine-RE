#!/usr/bin/env bash
# Youcine-RE - reproducible analysis environment.
# Downloads JDK 21, Ghidra 12.1.3, Jadx 1.5.6, Apktool, platform-tools.
# Override install location with TOOLS_DIR. Do not hard-code machine paths.
set -euo pipefail

TOOLS_DIR="${TOOLS_DIR:-$(pwd)/tools}"
mkdir -p "${TOOLS_DIR}"
cd "${TOOLS_DIR}"

JDK_VERSION="21"
GHIDRA_TAG="Ghidra_12.1.3_build"
GHIDRA_ZIP="ghidra_12.1.3_PUBLIC_20260817.zip"
GHIDRA_SHA256="93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54"
JADX_VERSION="1.5.6"
APKTOOL_VERSION="2.12.1"

log() { printf '[*] %s\n' "$*"; }

ARCH="$(uname -m)"
case "${ARCH}" in
  x86_64) JDK_ARCH="x64" ;;
  aarch64|arm64) JDK_ARCH="aarch64" ;;
  *) echo "unsupported arch ${ARCH}" >&2; exit 1 ;;
esac

if [ ! -d "jdk-${JDK_VERSION}" ]; then
  log "Temurin JDK ${JDK_VERSION} (${JDK_ARCH})"
  curl -fsSL -o jdk.tar.gz \
    "https://api.adoptium.net/v3/binary/latest/${JDK_VERSION}/ga/linux/${JDK_ARCH}/jdk/hotspot/normal/eclipse?project=jdk"
  mkdir -p "jdk-${JDK_VERSION}"
  tar -xzf jdk.tar.gz -C "jdk-${JDK_VERSION}" --strip-components=1
  rm -f jdk.tar.gz
fi
export JAVA_HOME="${TOOLS_DIR}/jdk-${JDK_VERSION}"
export PATH="${JAVA_HOME}/bin:${PATH}"
java -version

if [ ! -d "ghidra_12.1.3_PUBLIC" ]; then
  log "Ghidra 12.1.3"
  curl -fsSL -o ghidra.zip \
    "https://github.com/NationalSecurityAgency/ghidra/releases/download/${GHIDRA_TAG}/${GHIDRA_ZIP}"
  echo "${GHIDRA_SHA256}  ghidra.zip" | sha256sum -c -
  unzip -q ghidra.zip
  rm -f ghidra.zip
fi

if [ ! -d "jadx-${JADX_VERSION}" ]; then
  log "Jadx ${JADX_VERSION}"
  curl -fsSL -o jadx.zip \
    "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip"
  mkdir -p "jadx-${JADX_VERSION}"
  unzip -q jadx.zip -d "jadx-${JADX_VERSION}"
  chmod +x "jadx-${JADX_VERSION}/bin/jadx" "jadx-${JADX_VERSION}/bin/jadx-gui" || true
  rm -f jadx.zip
fi

if [ ! -f apktool.jar ]; then
  log "Apktool ${APKTOOL_VERSION}"
  curl -fsSL -o apktool.jar \
    "https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar"
fi

if [ ! -d platform-tools ]; then
  log "Android platform-tools"
  curl -fsSL -o platform-tools.zip \
    "https://dl.google.com/android/repository/platform-tools-latest-linux.zip"
  unzip -q platform-tools.zip
  rm -f platform-tools.zip
fi

log "Python packages"
python3 -m pip install --quiet --upgrade \
  androguard frida-tools pyelftools pycryptodome lief || \
  echo "[!] pip install failed; install manually"

cat <<EOF

export TOOLS_DIR="${TOOLS_DIR}"
export JAVA_HOME="${TOOLS_DIR}/jdk-${JDK_VERSION}"
export PATH="\$JAVA_HOME/bin:${TOOLS_DIR}/jadx-${JADX_VERSION}/bin:${TOOLS_DIR}/platform-tools:\$PATH"
alias apktool='java -jar ${TOOLS_DIR}/apktool.jar'

EOF
