#!/bin/bash

set -u

SECURITY_AUDIT_SCRIPT="${SECURITY_AUDIT_SCRIPT:-/usr/share/ovirt-engine/bin/ov-works-security_audit.sh}"
SECURITY_AUDIT_RESULTS="${SECURITY_AUDIT_RESULTS:-/tmp/ovirt-security-audit-results.json}"
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

run_security_audit() {
    if [ ! -x "$SECURITY_AUDIT_SCRIPT" ]; then
        log "Security audit script is missing or not executable"
        return 40
    fi

    rm -f "$SECURITY_AUDIT_RESULTS"
    SECURITY_AUDIT_STRICT=0 "$TIMEOUT_COMMAND" 10m "$SECURITY_AUDIT_SCRIPT"
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
    if [ ! -x "$AIDE_COMMAND" ]; then
        log "AIDE is missing or not executable"
        return 40
    fi

    "$TIMEOUT_COMMAND" 10m "$SUDO_COMMAND" -n "$AIDE_COMMAND" --check
    local aide_status=$?
    if [ "$aide_status" -eq 0 ]; then
        log "Integrity verification completed successfully"
        return 0
    fi
    if [ "$aide_status" -eq 124 ]; then
        log "Integrity verification timed out"
        return 40
    fi

    log "Integrity verification detected changes (AIDE status $aide_status)"
    return 20
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
        run_security_audit || result=$?
        integrity_result=0
        run_integrity_verification || integrity_result=$?
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
