#!/bin/bash
###############################################################################
# OV-Works self-test
#
# Checks the six main processes of the engine host - ovirt-engine, ovirt-engine-proxy (httpd),
# postgresql, ovirt-engine-dwhd, ovirt-websocket-proxy, ovirt-provider-ovn - and nothing else:
# for each, that it runs (as the account it should), that its executables are there and
# writable only by root, and that each of its configuration files, by exact name, is there with
# ownership and permissions that keep it safe. Operating system, network and log settings are
# not part of it.
#
# Every item prints its result - [PASS], [FAIL], [WARN] or [SKIP] - tagged with the process and
# the item, and the engine records each one in the audit log.
#
# The processes and files are those of /usr/share/ovirt-engine/conf/ovworks-process-files.conf,
# the list the integrity verification (AIDE) measures as well.
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
# The processes and their files.
PROCESS_FILES="${OVWORKS_PROCESS_FILES:-/usr/share/ovirt-engine/conf/ovworks-process-files.conf}"
# Reads ownership and modes as root (through sudo when this runs as the engine user), since the
# engine user cannot see into every directory the processes keep their files in.
FILE_STAT_HELPER="${FILE_STAT_HELPER:-/usr/share/ovirt-engine/bin/ovirt-engine-process-file-stat.sh}"
SYSTEMCTL="${SYSTEMCTL:-systemctl}"
PS_COMMAND="${PS_COMMAND:-ps}"

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

# An item that does not apply here: a process that is not installed or not in use, a file that
# is optional and absent. Recorded, so that the audit log names every item, but neither a pass
# nor a failure.
log_skip() {
    echo -e "${BLUE}[SKIP]${NC} $(check_tag)$1" | tee -a "$AUDIT_LOG"
    SKIP_COUNT=$((SKIP_COUNT + 1))
}

# "[ovirt-engine/설정 파일] " while a check runs under run_check, nothing otherwise.
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

PROCESS_ORDER="ovirt-engine ovirt-engine-proxy postgresql ovirt-engine-dwhd ovirt-websocket-proxy ovirt-provider-ovn"

# The lines of the list for one process and one type: "FLAGS PATH" each.
process_entries() {
    local want_process="$1" want_type="$2"
    awk -v p="$want_process" -v t="$want_type" \
        '$1 !~ /^#/ && $1 == p && $2 == t { print $3, $4 }' "$PROCESS_FILES"
}

has_flag() {
    case ",$1," in
        *,"$2",*) return 0 ;;
    esac
    return 1
}

FILE_STATS=""

# Ownership and mode of every listed file, once per run.
load_file_stats() {
    if [ ! -x "$FILE_STAT_HELPER" ]; then
        FILE_STATS=""
        return
    fi
    if [ "$(id -u)" -eq 0 ]; then
        FILE_STATS=$("$FILE_STAT_HELPER" 2>/dev/null || true)
        return
    fi
    # As the engine user: through the sudo rule engine-setup writes for this helper, or, where
    # there is none, as far as this account can see - a file out of its sight is then reported
    # as one that could not be checked.
    if ! FILE_STATS=$(sudo -n "$FILE_STAT_HELPER" 2>/dev/null); then
        FILE_STATS=$(OVWORKS_PROCESS_FILES="$PROCESS_FILES" "$FILE_STAT_HELPER" 2>/dev/null || true)
    fi
}

file_stat() {
    printf '%s\n' "$FILE_STATS" | awk -F '\t' -v f="$1" '$1 == f { print; exit }'
}

# Whether the process is installed at all: its unit is known to systemd.
unit_installed() {
    "$SYSTEMCTL" list-unit-files --no-legend "$1" 2>/dev/null | awk '{ print $1 }' | grep -qxF "$1"
}

# PROCESS_STATE: installed, in use (enabled) or not.
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

# 프로세스 실행 상태: running, and as the account it should run as.
check_process_running() {
    local unit="$1" flags="$2" state="$3"
    local expected_user="" active pid user
    case ",$flags," in
        *,user=*)
            expected_user=$(printf '%s' ",$flags," | sed 's/.*,user=\([^,]*\),.*/\1/')
            ;;
    esac

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
            elif [ "${SECURITY_AUDIT_SOURCE:-}" = "engine-start" ]; then
                # Before the engine starts, a process started after it may not be up yet.
                log_warn "$unit: 실행 중이 아님(${active:-unknown}) - 엔진 기동 전 점검"
            else
                log_fail "$unit: 실행 중이 아님(${active:-unknown})"
            fi
            return
            ;;
    esac
    pid=$("$SYSTEMCTL" show -p MainPID --value "$unit" 2>/dev/null || true)
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

# One executable or configuration file: present, and safe in ownership and permissions.
#   executable     owned by root, not writable by its group or others (nor anything in it, for
#                  a directory measured as a tree)
#   configuration  not writable by others, not owned by an ordinary account, and for a file
#                  that holds a secret, not open to others at all
check_process_file() {
    local type="$1" flags="$2" path="$3" state="$4"
    local line status mode uid user group kind writable value problems=""

    if [ "$state" = "absent" ]; then
        log_skip "$path: 프로세스 미설치 - 점검 대상 아님"
        return
    fi
    line=$(file_stat "$path")
    if [ -z "$line" ]; then
        log_warn "$path: 확인할 수 없음(점검 도구 $FILE_STAT_HELPER 응답 없음)"
        return
    fi
    IFS=$'\t' read -r _ status mode uid user group kind writable <<< "$line"
    case "$status" in
        missing)
            if has_flag "$flags" optional || [ "$state" = "disabled" ]; then
                log_skip "$path: 없음(선택 파일) - 점검 대상 아님"
            else
                log_fail "$path: 파일이 없음"
            fi
            return
            ;;
        denied)
            log_warn "$path: 권한이 없어 확인할 수 없음"
            return
            ;;
    esac

    value=$((8#$mode))
    if [ "$type" = "exec" ]; then
        [ "$uid" = "0" ] || problems="${problems}소유자가 root가 아님; "
        [ $((value & 8#022)) -eq 0 ] || problems="${problems}그룹·기타 사용자 쓰기 권한; "
        if [ -n "$writable" ] && [ "$writable" != "-" ]; then
            problems="${problems}하위 파일에 그룹·기타 사용자 쓰기 권한($writable); "
        fi
    else
        [ $((value & 8#002)) -eq 0 ] || problems="${problems}기타 사용자 쓰기 권한; "
        if [ "$uid" != "0" ] && [ "$uid" -ge 1000 ] 2>/dev/null; then
            problems="${problems}일반 사용자 계정 소유($user); "
        fi
        if has_flag "$flags" secret && [ $((value & 8#007)) -ne 0 ]; then
            problems="${problems}비밀정보 파일에 기타 사용자 접근 권한; "
        fi
    fi
    case "$kind" in
        file) ;;
        directory) has_flag "$flags" tree || problems="${problems}파일이 아닌 디렉터리; " ;;
        *) problems="${problems}일반 파일이 아님; " ;;
    esac

    local attrs
    attrs="권한 $(printf '%04o' "$value"), 소유자 $user:$group"
    if [ -n "$problems" ]; then
        log_fail "$path: ${problems%; } ($attrs)"
    else
        log_pass "$path: 정상 ($attrs)"
    fi
}

check_process_files() {
    local process="$1" type="$2" state="$3" flags path count=0
    while read -r flags path; do
        [ -n "$path" ] || continue
        count=$((count + 1))
        check_process_file "$type" "$flags" "$path" "$state"
    done < <(process_entries "$process" "$type")
    [ "$count" -gt 0 ] || log_fail "점검 대상 목록($PROCESS_FILES)에 항목이 없음"
}

# All the items of one process.
check_process() {
    local process="$1" unit="" flags="" state
    read -r flags unit < <(process_entries "$process" unit) || true
    if [ -z "${unit:-}" ]; then
        run_check "$process" "프로세스 실행 상태" log_fail "점검 대상 목록($PROCESS_FILES)에 서비스가 없음"
        return
    fi
    state=$(process_state "$unit")
    log_info "Checking process $process ($unit: $state)..."
    run_check "$process" "프로세스 실행 상태" check_process_running "$unit" "$flags" "$state"
    run_check "$process" "실행 파일" check_process_files "$process" exec "$state"
    run_check "$process" "설정 파일" check_process_files "$process" conf "$state"
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
    if [ ! -r "$PROCESS_FILES" ]; then
        run_check "ovirt-engine" "점검 대상 목록" log_fail "점검 대상 목록을 읽을 수 없음: $PROCESS_FILES"
    else
        load_file_stats
        for process in $PROCESS_ORDER; do
            check_process "$process"
            echo ""
        done
    fi

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
