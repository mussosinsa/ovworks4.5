#!/bin/bash
#
# audit-log-dummy-fill.sh - fill the engine's audit log (events) with dummy records, to test
# what happens when the audit records outgrow their storage:
#
#   - the event tables limit (ENGINE_AUDIT_EVENT_TABLES_MAX_SIZE_MB) and the capacity purge
#   - the DB filesystem levels (70/80/90/95%), the emergency reserve and the critical-level purge
#
# FOR TEST SYSTEMS ONLY. The records go into the live engine database. Every dummy record carries
# origin 'OVWORKS_DUMMY_TEST', so that they can be counted and removed again (`clean`) without
# touching a real record.
#
# Run as root on the engine host. It connects as the engine's own database user, read from the
# engine configuration (encrypted configuration files are decrypted the way the engine does, so
# the KEK passphrase must be held in memory), since local logins to PostgreSQL need a password.
#
#   audit-log-dummy-fill.sh status
#   audit-log-dummy-fill.sh fill --size-mb 2048
#   audit-log-dummy-fill.sh fill --rows 500000 --from-days 120 --to-days 31
#   audit-log-dummy-fill.sh clean
#
# See usage() for every option.

set -euo pipefail

MARKER="OVWORKS_DUMMY_TEST"
PGDATA_DIR="${PGDATA_DIR:-}"
ENGINE_DEFAULTS="${ENGINE_DEFAULTS:-/usr/share/ovirt-engine/services/ovirt-engine/ovirt-engine.conf}"
ENGINE_VARS="${ENGINE_VARS:-/etc/ovirt-engine/engine.conf}"
# The read-only monitoring role root reaches by peer authentication (see ovirt_engine.pg_local_auth),
# used only to ask where the data directory is.
DB_OPS_ROLE="ovworks_ops"

SIZE_MB=0
ROWS=0
MESSAGE_BYTES=1000
FROM_DAYS=120
TO_DAYS=31
BATCH=20000
STOP_AT_PERCENT=97
ASSUME_YES=0

usage() {
    cat <<EOF
사용법: $(basename "$0") <작업> [옵션]

작업
  status                 더미 기록 건수, 감사기록 테이블 크기, DB 파일시스템 사용률을 보여 줍니다.
  fill                   더미 감사기록을 넣습니다 (--size-mb 또는 --rows 중 하나 필수).
  clean                  더미 감사기록만 지우고 VACUUM ANALYZE 합니다.

fill 옵션
  --size-mb N            약 N MiB 만큼 넣습니다 (한 건 크기로 건수를 계산).
  --rows N               N 건 넣습니다.
  --message-bytes N      한 건 메시지 길이 (기본 ${MESSAGE_BYTES}, 64~1900).
                         압축되지 않는 임의 문자열이므로 실제로 디스크를 그만큼 씁니다.
  --from-days N          가장 오래된 기록의 시각: N일 전 (기본 ${FROM_DAYS}).
  --to-days N            가장 최근 기록의 시각: N일 전 (기본 ${TO_DAYS}).
                         기본값(120~31일 전)은 최소 보존기간(30일)보다 오래되어 정리 대상이 됩니다.
                         --to-days 0 이면 최근 기록이 되어 정리되지 않습니다(정리 차단 시험).
  --batch N              한 트랜잭션에 넣는 건수 (기본 ${BATCH}).
  --stop-at-percent P    DB 파일시스템 사용률이 P% 이상이면 멈춥니다 (기본 ${STOP_AT_PERCENT}, 최대 99).
                         DB가 100%가 되어 PostgreSQL이 멈추는 것을 막기 위한 안전장치입니다.
  -y, --yes              확인 질문 없이 진행합니다.

접속
  엔진 설정(${ENGINE_VARS}, engine.conf.d)의 ENGINE_DB_HOST/PORT/USER/PASSWORD/DATABASE 로
  엔진 DB 계정으로 접속합니다. 암호화된 설정 파일은 엔진과 같은 방식으로 복호화하므로
  KEK 패스프레이즈가 메모리에 있어야 합니다(kek_agent.py --status).

환경 변수
  PGDATA_DIR             PostgreSQL 데이터 디렉터리 (기본: SHOW data_directory 조회, 안 되면 /var/lib/pgsql/data)

예
  $(basename "$0") fill --size-mb 1024          # 약 1 GiB, 120~31일 전 기록
  $(basename "$0") fill --rows 100000 --to-days 0 -y
  $(basename "$0") clean -y
EOF
}

die() {
    echo "오류: $*" >&2
    exit 1
}

# Exports PGHOST, PGPORT, PGUSER, PGPASSWORD and PGDATABASE from the engine configuration.
load_engine_database() {
    local settings
    settings=$(ENGINE_DEFAULTS="$ENGINE_DEFAULTS" ENGINE_VARS="$ENGINE_VARS" python3 - <<'PY'
import os
import shlex
import sys

try:
    from ovirt_engine import configfile
    config = configfile.ConfigFile((os.environ["ENGINE_DEFAULTS"], os.environ["ENGINE_VARS"]))
except Exception as error:  # pylint: disable=broad-except
    sys.stderr.write("엔진 DB 설정을 읽을 수 없습니다: %s\n" % error)
    sys.exit(1)
for key, name in (("HOST", "PGHOST"), ("PORT", "PGPORT"), ("USER", "PGUSER"),
                  ("PASSWORD", "PGPASSWORD"), ("DATABASE", "PGDATABASE")):
    print("export %s=%s" % (name, shlex.quote(config.get("ENGINE_DB_%s" % key, "") or "")))
PY
    ) || die "엔진 DB 접속 정보를 읽지 못했습니다. 설정 파일이 암호화되어 있으면 KEK 패스프레이즈가 메모리에 있는지 확인하십시오(kek_agent.py --status)."
    eval "$settings"
    [ -n "${PGUSER:-}" ] && [ -n "${PGDATABASE:-}" ] || die "엔진 설정에 ENGINE_DB_USER/ENGINE_DB_DATABASE 가 없습니다."
    export PGCONNECT_TIMEOUT=10
    psql_engine -At -c "SELECT 1" >/dev/null \
        || die "엔진 DB(${PGDATABASE}@${PGHOST:-local}:${PGPORT:-5432}, 계정 ${PGUSER})에 접속하지 못했습니다."
}

psql_engine() {
    psql -X -q -w -v ON_ERROR_STOP=1 "$@"
}

query() {
    psql_engine -At -c "$1"
}

is_number() {
    [[ "$1" =~ ^[0-9]+$ ]]
}

# Where the data directory is: as configured, as the server says (only a privileged role may
# ask: the engine's own user, else the monitoring role over the local socket), or the default.
data_directory() {
    local dir=""
    if [ -n "$PGDATA_DIR" ]; then
        echo "$PGDATA_DIR"
        return
    fi
    dir=$(query "SHOW data_directory" 2>/dev/null) \
        || dir=$(env -u PGHOST -u PGPORT -u PGUSER -u PGPASSWORD -u PGDATABASE \
                 psql -X -q -w -At -U "$DB_OPS_ROLE" -d postgres -c "SHOW data_directory" 2>/dev/null) \
        || dir=""
    if [ -z "$dir" ] && [ -d /var/lib/pgsql/data ]; then
        dir=/var/lib/pgsql/data
    fi
    [ -n "$dir" ] || die "PostgreSQL 데이터 디렉터리를 알 수 없습니다. PGDATA_DIR 을 지정하십시오."
    echo "$dir"
}

# Used percent of the DB filesystem, the way df reports it (used / (used + available)).
db_used_percent() {
    df -P "$DATA_DIR" | awk 'NR == 2 { gsub("%", "", $5); print $5 }'
}

status() {
    local dir="$DATA_DIR"
    echo "== 더미 감사기록 (origin=${MARKER})"
    query "SELECT '  건수: ' || count(*) || ', 기간: ' || COALESCE(min(log_time)::date::text, '-')
                  || ' ~ ' || COALESCE(max(log_time)::date::text, '-')
           FROM audit_log WHERE origin = '${MARKER}'"
    echo "== audit_log 전체"
    query "SELECT '  건수(추정): ' || COALESCE(n_live_tup, 0) || ', 테이블 크기: '
                  || pg_size_pretty(pg_total_relation_size('public.audit_log'))
           FROM pg_stat_user_tables WHERE relname = 'audit_log'"
    echo "== Engine DB 크기"
    query "SELECT '  ' || pg_size_pretty(pg_database_size(current_database()))"
    echo "== DB 파일시스템 (${dir})"
    df -hP "$dir" | sed 's/^/  /'
    if [ -e "$(dirname "$dir")/ovworks-db-reserve" ]; then
        echo "  비상 예비 공간: $(du -h "$(dirname "$dir")/ovworks-db-reserve" | cut -f1) 확보됨"
    else
        echo "  비상 예비 공간: 없음 (해제되었거나 만들지 않음)"
    fi
}

confirm() {
    [ "$ASSUME_YES" = "1" ] && return 0
    local answer
    read -r -p "$1 [y/N] " answer
    [[ "$answer" =~ ^[Yy]$ ]] || die "취소했습니다."
}

fill() {
    [ "$SIZE_MB" -gt 0 ] || [ "$ROWS" -gt 0 ] || die "--size-mb 또는 --rows 를 지정하십시오."
    [ "$MESSAGE_BYTES" -ge 64 ] && [ "$MESSAGE_BYTES" -le 1900 ] || die "--message-bytes 는 64~1900 입니다."
    [ "$FROM_DAYS" -ge "$TO_DAYS" ] || die "--from-days 는 --to-days 보다 크거나 같아야 합니다."
    [ "$BATCH" -ge 1 ] || die "--batch 는 1 이상입니다."
    [ "$STOP_AT_PERCENT" -le 99 ] || die "--stop-at-percent 는 99 이하입니다."

    # A row is the message plus about 300 bytes of columns, tuple header and index entries.
    local row_bytes=$((MESSAGE_BYTES + 300))
    if [ "$ROWS" -eq 0 ]; then
        ROWS=$(( SIZE_MB * 1024 * 1024 / row_bytes ))
    fi
    local total_mb=$(( ROWS * row_bytes / 1024 / 1024 ))
    local used
    used=$(db_used_percent)

    echo "엔진 DB(${PGDATABASE}@${PGHOST:-local}, 계정 ${PGUSER})의 audit_log 에 더미 감사기록을 넣습니다."
    echo "  건수: ${ROWS} 건 (약 ${total_mb} MiB, 한 건 약 ${row_bytes} B)"
    echo "  시각: ${FROM_DAYS}일 전 ~ ${TO_DAYS}일 전 (오래된 것부터)"
    echo "  DB 파일시스템 사용률: ${used}% (${STOP_AT_PERCENT}% 이상이면 멈춤)"
    echo "  표시: origin='${MARKER}', 메시지 '[더미 용량시험] ...'"
    confirm "시험 시스템이 맞습니까? 계속할까요?"

    local done_rows=0 batch_rows start
    while [ "$done_rows" -lt "$ROWS" ]; do
        used=$(db_used_percent)
        if [ "$used" -ge "$STOP_AT_PERCENT" ]; then
            echo "DB 파일시스템 사용률 ${used}% - --stop-at-percent ${STOP_AT_PERCENT}% 에 도달하여 멈춥니다."
            break
        fi
        batch_rows=$BATCH
        [ $((done_rows + batch_rows)) -gt "$ROWS" ] && batch_rows=$((ROWS - done_rows))
        start=$done_rows
        # Spread evenly from FROM_DAYS ago (row 0) to TO_DAYS ago (the last row), so the ids grow
        # with the time the way real records do. The message is random hex - md5 of random
        # values - which does not compress, so the rows take the space they claim.
        psql_engine <<SQL
INSERT INTO audit_log (log_time, log_type, log_type_name, severity, message, origin, custom_event_id,
                       event_flood_in_sec, custom_data, processed)
SELECT now() - make_interval(secs => (${FROM_DAYS} * 86400.0)
                                      - ((${FROM_DAYS} - ${TO_DAYS}) * 86400.0) * (g::double precision / GREATEST(${ROWS} - 1, 1))),
       9801,
       'EXTERNAL_EVENT_NORMAL',
       0,
       left('[더미 용량시험] #' || g || ' ' ||
            (SELECT string_agg(md5(random()::text || g::text || s::text), '')
             FROM generate_series(1, ceil(${MESSAGE_BYTES} / 32.0)::int) s), ${MESSAGE_BYTES}),
       '${MARKER}',
       -1,
       0,
       '',
       true
FROM generate_series(${start}, ${start} + ${batch_rows} - 1) g;
SQL
        done_rows=$((done_rows + batch_rows))
        printf '  %d / %d 건 (%d%%), DB 파일시스템 %s%%\n' \
            "$done_rows" "$ROWS" $((done_rows * 100 / ROWS)) "$(db_used_percent)"
    done

    echo "통계 갱신(ANALYZE audit_log) - 엔진의 이벤트 테이블 크기 측정이 이 통계를 씁니다."
    psql_engine -c "ANALYZE public.audit_log"
    echo
    status
    echo
    echo "엔진은 1분마다 측정합니다. 이벤트 창과 보안 설정 화면의 저장소 용량에서 결과를 확인하십시오."
}

clean() {
    local count
    count=$(query "SELECT count(*) FROM audit_log WHERE origin = '${MARKER}'")
    echo "더미 감사기록 ${count} 건을 지웁니다 (origin='${MARKER}' 인 기록만)."
    [ "$count" -gt 0 ] || { echo "지울 기록이 없습니다."; return 0; }
    confirm "계속할까요?"
    local deleted
    while :; do
        deleted=$(psql_engine -At -c "WITH gone AS (
                DELETE FROM audit_log WHERE audit_log_id IN (
                    SELECT audit_log_id FROM audit_log WHERE origin = '${MARKER}' LIMIT ${BATCH})
                RETURNING 1)
            SELECT count(*) FROM gone")
        [ "$deleted" -gt 0 ] || break
        echo "  ${deleted} 건 삭제"
    done
    echo "VACUUM (ANALYZE) audit_log - 지운 자리를 새 기록이 다시 쓰게 합니다(디스크 반환은 아님)."
    psql_engine -c "VACUUM (ANALYZE) public.audit_log"
    echo
    status
}

[ $# -ge 1 ] || { usage; exit 1; }
case "$1" in -h|--help|help) usage; exit 0 ;; esac
[ "$(id -u)" -eq 0 ] || die "root 로 실행하십시오."
ACTION="$1"
shift
while [ $# -gt 0 ]; do
    case "$1" in
        --size-mb) SIZE_MB="${2:-}"; shift 2 ;;
        --rows) ROWS="${2:-}"; shift 2 ;;
        --message-bytes) MESSAGE_BYTES="${2:-}"; shift 2 ;;
        --from-days) FROM_DAYS="${2:-}"; shift 2 ;;
        --to-days) TO_DAYS="${2:-}"; shift 2 ;;
        --batch) BATCH="${2:-}"; shift 2 ;;
        --stop-at-percent) STOP_AT_PERCENT="${2:-}"; shift 2 ;;
        -y|--yes) ASSUME_YES=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "알 수 없는 옵션: $1" ;;
    esac
done
for value in "$SIZE_MB" "$ROWS" "$MESSAGE_BYTES" "$FROM_DAYS" "$TO_DAYS" "$BATCH" "$STOP_AT_PERCENT"; do
    is_number "$value" || die "숫자가 아닌 값: '$value'"
done

load_engine_database
DATA_DIR=$(data_directory) || exit 1
case "$ACTION" in
    status) status ;;
    fill) fill ;;
    clean) clean ;;
    -h|--help|help) usage ;;
    *) usage; exit 1 ;;
esac
