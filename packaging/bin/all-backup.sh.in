#!/bin/sh

set -eu

DEST_DIR="${1:-}"

if [ -z "${DEST_DIR}" ]; then
    echo "FAIL: 저장 위치가 필요합니다." 1>&2
    exit 1
fi

mkdir -p "${DEST_DIR}"

timestamp="$(date +%Y%m%d%H%M%S)"
archive="${DEST_DIR%/}/${timestamp}.tar.gz"

if sudo -n /bin/tar --ignore-failed-read -czf "${archive}" -C /var/log ovirt-engine; then
    echo "SUCCESS: ${archive}"
    exit 0
fi

if [ -f "${archive}" ]; then
    echo "SUCCESS (with warnings): ${archive}"
    exit 0
fi

echo "FAIL: ${archive}"
exit 1
