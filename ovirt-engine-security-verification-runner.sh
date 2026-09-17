#!/bin/bash

set -u

SECURITY_AUDIT_SCRIPT="${SECURITY_AUDIT_SCRIPT:-/usr/share/ovirt-engine/bin/ov-works-security_audit.sh}"
SECURITY_AUDIT_RESULTS="${SECURITY_AUDIT_RESULTS:-/var/lib/ovirt-engine/security/audit-results.json}"
# The integrity verification keeps its own result, beside the security audit's and never mixed
# with it. They are two checks answering two questions, the audit log records them apart, and a
# run of one must not be readable as a statement about the other.
INTEGRITY_RESULTS="${INTEGRITY_VERIFICATION_RESULTS:-/var/lib/ovirt-engine/security/integrity-results.json}"
INTEGRITY_LOG_DIR="${INTEGRITY_LOG_DIR:-/var/log/ovirt-engine}"
AIDE_COMMAND="${AIDE_COMMAND:-/usr/sbin/aide}"
FLOCK_COMMAND="${FLOCK_COMMAND:-/usr/bin/flock}"
LOGGER_COMMAND="${LOGGER_COMMAND:-/usr/bin/logger}"
PYTHON_COMMAND="${PYTHON_COMMAND:-/usr/bin/python3}"
SUDO_COMMAND="${SUDO_COMMAND:-/usr/bin/sudo}"
TIMEOUT_COMMAND="${TIMEOUT_COMMAND:-/usr/bin/timeout}"
LOCK_FILE="${LOCK_FILE:-/var/tmp/ovirt-engine-security-verification.lock}"
MODE="${1:-all}"
SOURCE="${2:-unknown}"

log() {
    printf '[%s] %s\n' "$(date -Is)" "$*"
}

read_security_status() {
    "$PYTHON_COMMAND" - "$SECURITY_AUDIT_RESULTS" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding='utf-8') as stream:
        print(json.load(stream).get('status', 'ERROR'))
except (OSError, ValueError):
    print('ERROR')
PY
}

write_integrity_result() {
    local status="$1"
    local exit_code="$2"
    local report="$3"
    mkdir -p "$(dirname "$INTEGRITY_RESULTS")"
    # Removed rather than truncated: a run started by hand as root would otherwise leave a file
    # the engine user can never write again.
    rm -f "$INTEGRITY_RESULTS"
    cat > "$INTEGRITY_RESULTS" << EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "status": "$status",
  "exit_code": $exit_code,
  "source": "$SOURCE",
  "log_file": "$report"
}
EOF
    chmod 0600 "$INTEGRITY_RESULTS" 2>/dev/null || true
}

run_security_audit() {
    if [ ! -x "$SECURITY_AUDIT_SCRIPT" ]; then
        log "Security audit script is missing or not executable"
        return 40
    fi

    rm -f "$SECURITY_AUDIT_RESULTS"
    # SECURITY_AUDIT_RESULTS is passed on, not only read here. Without it this script would
    # delete and read one path while the audit wrote another, and every run would look like an
    # audit that reported nothing - which the engine start gate treats as a failed verification.
    SECURITY_AUDIT_STRICT=0 SECURITY_AUDIT_RESULTS="$SECURITY_AUDIT_RESULTS" \
        SECURITY_AUDIT_SOURCE="$SOURCE" \
        "$TIMEOUT_COMMAND" 10m "$SECURITY_AUDIT_SCRIPT"
    local command_status=$?
    if [ "$command_status" -eq 124 ]; then
        log "Security audit timed out"
        return 40
    fi
    if [ "$command_status" -ne 0 ]; then
        log "Security audit execution failed with status $command_status"
        return 40
    fi

    local audit_status
    audit_status=$(read_security_status)
    case "$audit_status" in
        PASS)
            log "Security audit completed successfully"
            return 0
            ;;
        FAIL)
            log "Security audit detected failed checks"
            return 20
            ;;
        *)
            log "Security audit result is missing or invalid"
            return 40
            ;;
    esac
}

run_integrity_verification() {
    local report="$INTEGRITY_LOG_DIR/integrity-verification-$(date +%Y%m%d-%H%M%S).log"

    if [ ! -x "$AIDE_COMMAND" ]; then
        log "AIDE is missing or not executable"
        write_integrity_result "ERROR" 40 ""
        return 40
    fi

    # Kept as well as printed: the caller sees it, and the engine reads which files AIDE
    # reported out of this file to put each of them in the audit log on its own.
    mkdir -p "$INTEGRITY_LOG_DIR"
    "$TIMEOUT_COMMAND" 10m "$SUDO_COMMAND" -n "$AIDE_COMMAND" --check 2>&1 | tee "$report"
    local aide_status=${PIPESTATUS[0]}

    if [ "$aide_status" -eq 0 ]; then
        log "Integrity verification completed successfully"
        write_integrity_result "PASS" 0 "$report"
        return 0
    fi
    if [ "$aide_status" -eq 124 ]; then
        log "Integrity verification timed out"
        write_integrity_result "ERROR" 40 "$report"
        return 40
    fi
    # AIDE reports what it found as a bit set: 1 added, 2 removed, 4 changed. Anything above
    # that (14 and up) is AIDE saying it could not do the check, which is not the same answer
    # as the check having found something and must not be recorded as if it were.
    if [ "$aide_status" -ge 1 ] && [ "$aide_status" -le 7 ]; then
        log "Integrity verification detected changes (AIDE status $aide_status)"
        write_integrity_result "FAIL" "$aide_status" "$report"
        return 20
    fi

    log "Integrity verification could not be completed (AIDE status $aide_status)"
    write_integrity_result "ERROR" "$aide_status" "$report"
    return 40
}

exec 9>"$LOCK_FILE"
if ! "$FLOCK_COMMAND" -n 9; then
    log "Another security verification is already running"
    exit 75
fi

log "Security verification started (mode=$MODE, source=$SOURCE)"
result=0
case "$MODE" in
    security)
        run_security_audit || result=$?
        ;;
    integrity)
        run_integrity_verification || result=$?
        ;;
    all)
        # Run and reported apart. The exit code the caller gets is the worse of the two,
        # because systemd has only one; which check produced it is in each result file and in
        # the two lines below, so a failure is never attributed to the check that passed.
        security_result=0
        run_security_audit || security_result=$?
        integrity_result=0
        run_integrity_verification || integrity_result=$?
        log "Security audit status=$security_result; integrity verification status=$integrity_result"
        result=$security_result
        if [ "$integrity_result" -gt "$result" ]; then
            result=$integrity_result
        fi
        ;;
    *)
        log "Unsupported verification mode: $MODE"
        exit 64
        ;;
esac

if [ "$result" -ne 0 ]; then
    "$LOGGER_COMMAND" -p authpriv.err -t ovirt-engine-security-verification \
        "Security verification failed (mode=$MODE, source=$SOURCE, status=$result)" || true
fi
log "Security verification finished (status=$result)"
exit "$result"
