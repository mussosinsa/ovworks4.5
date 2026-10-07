#!/bin/bash
###############################################################################
# OV-Works self-test (보안기능 자체시험)
#
# Checks that the main processes of the engine host are running normally, and nothing else:
#   ovirt-engine, ovirt-engine-proxy (httpd), postgresql, ovirt-engine-kek-agent,
#   ovirt-engine-dwhd, ovirt-websocket-proxy
# - each one whose failure or stop affects a security function (authentication, access control,
# audit records, encrypted communication, the encryption key). For each, two items:
#   프로세스 실행 상태  the service runs, with its main process, as the account it should
#   응답 확인          the process answers: the engine's health page, the web server over HTTPS,
#                      the database (pg_isready), the KEK agent holding the passphrase, the
#                      data warehouse's collector (its Java process), the websocket proxy's port
# Files are not checked here: their ownership, permissions and content are the integrity
# verification's (AIDE).
#
# Every item prints its result - [PASS], [FAIL], [WARN] or [SKIP] - tagged with the process and
# the item, and the engine records each one in the audit log and shows them on the security
# screen.
###############################################################################

set -e

# Colorize interactive terminal output only. Escape sequences make WebAdmin,
# systemd journal, and persistent log output difficult to read.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

# Audit result counters
PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0
SKIP_COUNT=0
# The process and the item a check belongs to, set by run_check while it runs and printed in
# front of every result line, so that the engine can put in the event list the result of each
# item of each process - which passed as well as which did not.
CHECK_COMPONENT=""
CHECK_ITEM=""

# Log file
AUDIT_LOG="${SECURITY_AUDIT_LOG_FILE:-/var/log/ovirt-engine/security-audit-$(date +%Y%m%d-%H%M%S).log}"
# Where this run leaves its result for the engine to read.
#
# Not /tmp. That directory is world-writable, so a local user can pre-create this path or
# replace the file between the moment it is written and the moment the engine reads it, and
# what then reaches the event list as an audit result is whatever they wrote. It lives beside
# the integrity baseline instead, in a directory only the engine user can write.
#
# SECURITY_AUDIT_RESULTS overrides it. The runner script and the engine read the same
# variable with the same default, so the three agree wherever it is pointed.
AUDIT_RESULTS="${SECURITY_AUDIT_RESULTS:-/var/lib/ovirt-engine/security/audit-results.json}"
AUDIT_LOCK="${AUDIT_LOCK:-/var/tmp/ov-works-security-audit.lock}"
SYSTEMCTL="${SYSTEMCTL:-systemctl}"
PS_COMMAND="${PS_COMMAND:-ps}"
# What the response checks use; named so that tests can stand in for them.
CURL_COMMAND="${CURL_COMMAND:-curl}"
PG_ISREADY_COMMAND="${PG_ISREADY_COMMAND:-pg_isready}"
KEK_AGENT_COMMAND="${KEK_AGENT_COMMAND:-/usr/bin/python3 /usr/share/ovirt-engine/encryptor/kek_agent.py}"
ENGINE_CONF_DIR="${ENGINE_CONF_DIR:-/etc/ovirt-engine}"

# Creates a directory under the engine's state directory, and leaves it belonging to the engine.
#
# Run by hand as root, or from engine-setup, mkdir would leave it owned by root - and then the
# engine user can never write in it again. That is not a small thing: the start gate writes its
# result here, so a directory created once by a root run stops the engine from starting at all,
# with "Permission denied" and nothing else to go on. The owner is taken from the parent, which
# the package owns, rather than from a user name written down here.
ensure_engine_dir() {
    local dir="$1"
    [ -d "$dir" ] || mkdir -p "$dir" || return 1
    if [ "$(id -u)" -eq 0 ]; then
        chown --reference="$(dirname "$dir")" "$dir" 2>/dev/null || true
        chmod 0700 "$dir" 2>/dev/null || true
    fi
    return 0
}

###############################################################################
# Logging Functions
###############################################################################

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$AUDIT_LOG"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $(check_tag)$1" | tee -a "$AUDIT_LOG"
    PASS_COUNT=$((PASS_COUNT + 1))
}

# An item that does not apply here: a process that is not installed or not in use, or an answer
# that cannot be asked for yet. Recorded, so that the audit log names every item, but neither a pass
# nor a failure.
log_skip() {
    echo -e "${BLUE}[SKIP]${NC} $(check_tag)$1" | tee -a "$AUDIT_LOG"
    SKIP_COUNT=$((SKIP_COUNT + 1))
}

# "[ovirt-engine/응답 확인] " while a check runs under run_check, nothing otherwise.
check_tag() {
    if [ -n "$CHECK_ITEM" ]; then
        printf '[%s/%s] ' "${CHECK_COMPONENT:-엔진 서버}" "$CHECK_ITEM"
    fi
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $(check_tag)$1" | tee -a "$AUDIT_LOG"
    FAIL_COUNT=$((FAIL_COUNT + 1))
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $(check_tag)$1" | tee -a "$AUDIT_LOG"
    WARN_COUNT=$((WARN_COUNT + 1))
}

# run_check COMPONENT ITEM FUNCTION [ARGS...]: runs one check with its results tagged.
run_check() {
    CHECK_COMPONENT="$1"
    CHECK_ITEM="$2"
    shift 2
    "$@"
    CHECK_COMPONENT=""
    CHECK_ITEM=""
}

###############################################################################
# Process checks
###############################################################################

# PROCESS|UNIT|ACCOUNT|RESPONSE CHECK, in the order they are checked and shown.
SELF_TEST_PROCESSES="
ovirt-engine|ovirt-engine.service|ovirt|respond_engine_health
ovirt-engine-proxy|httpd.service|root|respond_httpd
postgresql|postgresql.service|postgres|respond_postgresql
ovirt-engine-kek-agent|ovirt-engine-kek-agent.service|ovirt|respond_kek_agent
ovirt-engine-dwhd|ovirt-engine-dwhd.service|ovirt|respond_dwhd
ovirt-websocket-proxy|ovirt-websocket-proxy.service|ovirt|respond_websocket_proxy
"

# The last value KEY has in FILE and FILE.d/*.conf, or DEFAULT.
conf_value() {
    local base="$1" key="$2" default="$3" value="" file file_value
    for file in "$base" "$base".d/*.conf; do
        [ -r "$file" ] || continue
        file_value=$(sed -n "s/^[[:space:]]*$key=[\"']\{0,1\}\([^\"']*\)[\"']\{0,1\}[[:space:]]*$/\1/p" "$file" | tail -n 1)
        [ -n "$file_value" ] && value="$file_value"
    done
    printf '%s' "${value:-$default}"
}

# Whether something answers on 127.0.0.1:PORT within three seconds.
tcp_answers() {
    timeout 3 bash -c "exec 3<>/dev/tcp/127.0.0.1/$1" 2>/dev/null
}

unit_installed() {
    "$SYSTEMCTL" list-unit-files --no-legend "$1" 2>/dev/null | awk '{ print $1 }' | grep -qxF "$1"
}

# installed and in use (enabled), installed and not in use (disabled), or absent.
process_state() {
    local unit="$1"
    if ! unit_installed "$unit"; then
        echo "absent"
        return
    fi
    case "$("$SYSTEMCTL" is-enabled "$unit" 2>/dev/null)" in
        enabled|enabled-runtime|static|indirect|alias|linked|linked-runtime|generated)
            echo "enabled"
            ;;
        *)
            echo "disabled"
            ;;
    esac
}

# A process that does not run or answer before the engine starts may simply not be up yet: it is
# said, and does not keep the engine from starting.
log_not_normal() {
    if [ "${SECURITY_AUDIT_SOURCE:-}" = "engine-start" ]; then
        log_warn "$1 - 엔진 기동 전 점검"
    else
        log_fail "$1"
    fi
}

PROCESS_RUNNING=0
PROCESS_PID=""

# 프로세스 실행 상태: running, with its main process, as the account it should run as.
check_process_running() {
    local unit="$1" expected_user="$2" state="$3" active pid user
    PROCESS_RUNNING=0
    PROCESS_PID=""
    if [ "$state" = "absent" ]; then
        log_skip "$unit: 설치되지 않음 - 점검 대상 아님"
        return
    fi
    active=$("$SYSTEMCTL" is-active "$unit" 2>/dev/null || true)
    case "$active" in
        active|activating|reloading)
            ;;
        *)
            if [ "$state" = "disabled" ]; then
                log_skip "$unit: 사용 안 함(disabled, ${active:-inactive}) - 점검 대상 아님"
            else
                log_not_normal "$unit: 실행 중이 아님(${active:-unknown})"
            fi
            return
            ;;
    esac
    PROCESS_RUNNING=1
    pid=$("$SYSTEMCTL" show -p MainPID --value "$unit" 2>/dev/null || true)
    PROCESS_PID="$pid"
    user=""
    if [ -n "$pid" ] && [ "$pid" != "0" ]; then
        user=$("$PS_COMMAND" -o user= -p "$pid" 2>/dev/null | awk 'NF { print $1; exit }')
    fi
    if [ -n "$expected_user" ] && [ -n "$user" ] && [ "$user" != "$expected_user" ]; then
        log_warn "$unit: 실행 중($active, PID $pid)이나 실행 계정이 $user (기대값 $expected_user)"
        return
    fi
    log_pass "$unit: 실행 중($active, PID ${pid:-?}, 계정 ${user:-?})"
}

# 응답 확인 of the engine: its health page, which also asks the database, through the web server
# from 127.0.0.1 (always on the list of terminals allowed in). Not before the engine starts: the
# check runs in its start, before there is anything to answer.
respond_engine_health() {
    if [ "${SECURITY_AUDIT_SOURCE:-}" = "engine-start" ]; then
        log_skip "엔진 기동 전 점검: 응답 확인은 기동 후 주기·관리자 요청 시험에서 수행"
        return
    fi
    local port url output code body
    port=$(conf_value "$ENGINE_CONF_DIR/engine.conf" ENGINE_PROXY_HTTPS_PORT 443)
    url="https://127.0.0.1:$port/ovirt-engine/services/health"
    output=$("$CURL_COMMAND" -sk --max-time 15 -w '\n%{http_code}' "$url" 2>/dev/null || true)
    code=$(printf '%s\n' "$output" | tail -n 1)
    body=$(printf '%s\n' "$output" | sed '$d' | tr -d '\r' | tr '\n' ' ' | cut -c1-80)
    if [ "$code" = "200" ] && printf '%s' "$body" | grep -q "DB Up"; then
        log_pass "health 응답 정상($url, HTTP 200, ${body% })"
    else
        log_not_normal "health 응답 이상($url, HTTP ${code:-000}${body:+, ${body% }})"
    fi
}

# 응답 확인 of the web server: any HTTP answer over HTTPS. Before the engine starts its pages
# are a 503, which is still the web server answering.
respond_httpd() {
    local port code
    port=$(conf_value "$ENGINE_CONF_DIR/engine.conf" ENGINE_PROXY_HTTPS_PORT 443)
    code=$("$CURL_COMMAND" -sk --max-time 10 -o /dev/null -w '%{http_code}' \
        "https://127.0.0.1:$port/" 2>/dev/null || true)
    if [ -n "$code" ] && [ "$code" != "000" ]; then
        log_pass "HTTPS 응답 정상(https://127.0.0.1:$port/, HTTP $code)"
    else
        log_not_normal "HTTPS 응답 없음(https://127.0.0.1:$port/)"
    fi
}

# 응답 확인 of the database: pg_isready on the local socket, or the port where it is missing.
respond_postgresql() {
    local port=5432 rc=0
    if command -v "$PG_ISREADY_COMMAND" >/dev/null 2>&1; then
        "$PG_ISREADY_COMMAND" -q -h /var/run/postgresql -p "$port" -t 10 >/dev/null 2>&1 || rc=$?
        case "$rc" in
            0) log_pass "접속 수락 중(pg_isready, 포트 $port)" ;;
            1) log_not_normal "접속 거부 중 - 기동 중이거나 종료 중(pg_isready, 포트 $port)" ;;
            *) log_not_normal "응답 없음(pg_isready 종료코드 $rc, 포트 $port)" ;;
        esac
    elif tcp_answers "$port"; then
        log_pass "포트 $port 응답"
    else
        log_not_normal "포트 $port 응답 없음"
    fi
}

# 응답 확인 of the KEK agent: it answers, and holds the KEK passphrase. Without it the database
# credentials cannot be decrypted, and the engine, the data warehouse and the AAA extension
# cannot start.
respond_kek_agent() {
    local output rc=0
    output=$($KEK_AGENT_COMMAND --status 2>&1) || rc=$?
    case "$rc" in
        0)
            log_pass "KEK 패스프레이즈 메모리 보관 중"
            ;;
        3)
            log_not_normal "KEK 패스프레이즈가 메모리에 없음 - kek_agent.py --unlock 필요"
            ;;
        *)
            if printf '%s' "$output" | grep -q "not enabled in the encryptor configuration"; then
                log_skip "설정 파일 암호화에 KEK 보관 서비스를 사용하지 않음 - 점검 대상 아님"
            else
                log_not_normal "응답 없음($(printf '%s' "$output" | tr '\n' ' ' | cut -c1-120))"
            fi
            ;;
    esac
}

# 응답 확인 of the data warehouse: ovirt-engine-dwhd.py runs the collector as a Java process of
# its own, and the service is only doing its work while that process is there.
respond_dwhd() {
    if [ -z "$PROCESS_PID" ] || [ "$PROCESS_PID" = "0" ]; then
        log_not_normal "주 프로세스(PID)를 확인할 수 없음"
        return
    fi
    if "$PS_COMMAND" --ppid "$PROCESS_PID" -o comm= 2>/dev/null | grep -qx java; then
        log_pass "수집 프로세스(java) 실행 중(상위 PID $PROCESS_PID)"
    else
        log_not_normal "수집 프로세스(java)가 없음(상위 PID $PROCESS_PID)"
    fi
}

# 응답 확인 of the websocket proxy: its port accepts a connection.
respond_websocket_proxy() {
    local port
    port=$(conf_value "$ENGINE_CONF_DIR/ovirt-websocket-proxy.conf" PROXY_PORT 6100)
    if tcp_answers "$port"; then
        log_pass "포트 $port 응답"
    else
        log_not_normal "포트 $port 응답 없음"
    fi
}

# Both items of one process.
check_process() {
    local process="$1" unit="$2" account="$3" respond="$4" state
    state=$(process_state "$unit")
    log_info "Checking process $process ($unit: $state)..."
    run_check "$process" "프로세스 실행 상태" check_process_running "$unit" "$account" "$state"
    if [ "$PROCESS_RUNNING" = "1" ]; then
        run_check "$process" "응답 확인" "$respond"
    elif [ "$state" = "enabled" ]; then
        run_check "$process" "응답 확인" log_skip "프로세스가 실행 중이 아니어서 확인하지 않음"
    else
        run_check "$process" "응답 확인" log_skip "점검 대상 아님"
    fi
}

###############################################################################
# Main Execution
###############################################################################

main() {
    # Read-only when it exists, so a lock left by a run as root does not stop the engine user;
    # an unopenable lock is said as such, not as "already running".
    [ -e "$AUDIT_LOCK" ] || ( umask 022; : > "$AUDIT_LOCK" ) 2>/dev/null
    if ! { exec 8<"$AUDIT_LOCK"; } 2>/dev/null; then
        echo "Cannot open the security audit lock file $AUDIT_LOCK" >&2
        exit 1
    fi
    if ! flock -n 8; then
        echo "Security audit is already running" >&2
        exit 75
    fi

    echo "========================================================================="
    echo "OV-Works Self-Test (main processes)"
    echo "Date: $(date)"
    echo "========================================================================="
    echo ""

    # Create log directory if it doesn't exist
    mkdir -p "$(dirname $AUDIT_LOG)"

    # Run all security checks
    local process unit account respond
    while IFS='|' read -r process unit account respond; do
        [ -n "$process" ] || continue
        check_process "$process" "$unit" "$account" "$respond"
        echo ""
    done <<< "$SELF_TEST_PROCESSES"

    # Generate summary
    echo "========================================================================="
    echo "Security Audit Summary"
    echo "========================================================================="
    echo -e "${GREEN}Passed: $PASS_COUNT${NC}"
    echo -e "${YELLOW}Warnings: $WARN_COUNT${NC}"
    echo -e "${RED}Failed: $FAIL_COUNT${NC}"
    echo -e "${BLUE}Skipped: $SKIP_COUNT${NC}"
    echo ""
    echo "Detailed log: $AUDIT_LOG"
    echo ""

    # Generate JSON results
    #
    # Removed first rather than truncated: a run started by hand as root leaves the file
    # owned by root, and the engine user could then never write this path again - which
    # fails the start gate and stops the engine from starting at all.
    ensure_engine_dir "$(dirname "$AUDIT_RESULTS")"
    rm -f "$AUDIT_RESULTS"
    cat > "$AUDIT_RESULTS" << EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "summary": {
    "passed": $PASS_COUNT,
    "warnings": $WARN_COUNT,
    "failed": $FAIL_COUNT,
    "skipped": $SKIP_COUNT,
    "total": $((PASS_COUNT + WARN_COUNT + FAIL_COUNT))
  },
  "status": "$([ $FAIL_COUNT -eq 0 ] && echo "PASS" || echo "FAIL")",
  "source": "${SECURITY_AUDIT_SOURCE:-unknown}",
  "log_file": "$AUDIT_LOG"
}
EOF
    chmod 0600 "$AUDIT_RESULTS" 2>/dev/null || true

    echo "Results saved to: $AUDIT_RESULTS"

    # Return appropriate exit code
    # Default strict mode keeps CLI behavior (non-zero on failures).
    # SecurityAuditCommand sets SECURITY_AUDIT_STRICT=0 to return results
    # without failing the action when checks report vulnerabilities.
    if [ "${SECURITY_AUDIT_STRICT:-1}" = "1" ] && [ $FAIL_COUNT -gt 0 ]; then
        exit 1
    fi
    exit 0
}

# Run main function only when executed, allowing focused function tests to
# source this file without starting a complete host audit.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    main "$@"
fi
