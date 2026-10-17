#!/bin/sh
#
# ovirt-engine-backup root wrapper
#
# Copyright 새올정보기술 (OV-Works), 2026
# SPDX-License-Identifier: Apache-2.0
#

set -eu

if [ "$#" -ne 1 ]; then
    echo "FAIL: 저장 위치 인자는 하나만 허용됩니다." 1>&2
    exit 1
fi

DEST_DIR="$1"
if [ -z "${DEST_DIR}" ]; then
    echo "FAIL: 저장 위치가 필요합니다." 1>&2
    exit 1
fi

mkdir -p "${DEST_DIR}"

exec /usr/bin/engine-backup \
    --mode=backup \
    --file="${DEST_DIR%/}/engine_backup.tar.gz" \
    --log="${DEST_DIR%/}/engine_backup.log"
