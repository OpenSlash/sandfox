#!/bin/sh
set -eu

ROOT_DIR=${SANDFOX_ROOT_DIR:-$(pwd)}
CROSS_IMAGE=${SANDFOX_CROSS_IMAGE:-wails-cross}
WAILS_VERSION=${SANDFOX_WAILS_VERSION:-v3.0.0-alpha.96}
GOPROXY_VALUE=${GOPROXY:-https://goproxy.cn,direct}

if [ -z "${ARCH:-}" ]; then
  case "$(uname -m)" in
    arm64|aarch64) ARCH=arm64 ;;
    x86_64|amd64) ARCH=amd64 ;;
    *) ARCH=amd64 ;;
  esac
fi

case "$ARCH" in
  arm64) APPIMAGE_ARCH=aarch64 ;;
  amd64) APPIMAGE_ARCH=x86_64 ;;
  *) echo "Unsupported Linux package ARCH: $ARCH" >&2; exit 1 ;;
esac

GO_MOD_CACHE=${SANDFOX_GO_MOD_CACHE:-${HOME}/go/pkg/mod}
APPIMAGE_CACHE_DIR=${SANDFOX_APPIMAGE_CACHE_DIR:-${ROOT_DIR}/build/linux/appimage/cache}
LINUXDEPLOY_CACHE=${SANDFOX_LINUXDEPLOY_CACHE:-${APPIMAGE_CACHE_DIR}/linuxdeploy-${APPIMAGE_ARCH}.AppImage}
APPRUN_CACHE=${SANDFOX_APPRUN_CACHE:-${APPIMAGE_CACHE_DIR}/AppRun-${APPIMAGE_ARCH}}

docker run --rm \
  -v "${ROOT_DIR}:/app" \
  -v "${GO_MOD_CACHE}:/go/pkg/mod" \
  -w /app \
  -e "ARCH=${ARCH}" \
  -e "GOPROXY=${GOPROXY_VALUE}" \
  -e "SANDFOX_WAILS_VERSION=${WAILS_VERSION}" \
  -e "SANDFOX_LINUXDEPLOY=/app/build/linux/appimage/cache/linuxdeploy-${APPIMAGE_ARCH}.AppImage" \
  -e "SANDFOX_APPRUN=/app/build/linux/appimage/cache/AppRun-${APPIMAGE_ARCH}" \
  --entrypoint /bin/sh \
  "${CROSS_IMAGE}" -lc '
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update >/dev/null
apt-get install -y --no-install-recommends dpkg-dev file >/dev/null

export GOBIN=/tmp/wailsbin
export PATH=/tmp/wailsbin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

go mod download "github.com/wailsapp/wails/v3@${SANDFOX_WAILS_VERSION}"
WAILS_DIR="$(go env GOPATH)/pkg/mod/github.com/wailsapp/wails/v3@${SANDFOX_WAILS_VERSION}"

if [ -f "$SANDFOX_LINUXDEPLOY" ] && [ -f "$SANDFOX_APPRUN" ]; then
  rm -rf /tmp/wails-src
  mkdir -p /tmp/wails-src
  cp -a "$WAILS_DIR/." /tmp/wails-src
  node - <<'"'"'NODE'"'"'
const fs = require("fs");
const file = "/tmp/wails-src/internal/commands/appimage.go";
let source = fs.readFileSync(file, "utf8");
source = source.replace(
  "s.DOWNLOAD(urls[\"linuxdeploy\"], linuxdeployPath)",
  "if os.Getenv(\"SANDFOX_LINUXDEPLOY\") != \"\" { s.COPY(os.Getenv(\"SANDFOX_LINUXDEPLOY\"), linuxdeployPath) } else { s.DOWNLOAD(urls[\"linuxdeploy\"], linuxdeployPath) }",
);
source = source.replace(
  "s.DOWNLOAD(urls[\"AppRun\"], target)",
  "if os.Getenv(\"SANDFOX_APPRUN\") != \"\" { s.COPY(os.Getenv(\"SANDFOX_APPRUN\"), target) } else { s.DOWNLOAD(urls[\"AppRun\"], target) }",
);
fs.writeFileSync(file, source);
NODE
  (cd /tmp/wails-src/cmd/wails3 && go install .)
else
  go install "github.com/wailsapp/wails/v3/cmd/wails3@${SANDFOX_WAILS_VERSION}"
fi

wails3 task linux:package "ARCH=${ARCH}"
'
