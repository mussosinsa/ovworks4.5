#!/bin/bash
###############################################################################
# OVirt Engine Security Audit Script
# Purpose: Perform comprehensive security checks on OVirt Engine installation
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

# Log file
AUDIT_LOG="/var/log/ovirt-engine/security-audit-$(date +%Y%m%d-%H%M%S).log"
AUDIT_RESULTS="/tmp/ovirt-security-audit-results.json"
INTEGRITY_BASELINE="/var/lib/ovirt-engine/security/integrity-baseline.sha256"
AUDIT_LOCK="${AUDIT_LOCK:-/var/tmp/ov-works-security-audit.lock}"
SESSION_TIMEOUT_TARGET=600
ADMIN_NOTIFY_EMAIL="${ADMIN_NOTIFY_EMAIL:-root@localhost}"
AUDIT_RETENTION_DAYS=365

###############################################################################
# Logging Functions
###############################################################################

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$AUDIT_LOG"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1" | tee -a "$AUDIT_LOG"
    PASS_COUNT=$((PASS_COUNT + 1))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1" | tee -a "$AUDIT_LOG"
    FAIL_COUNT=$((FAIL_COUNT + 1))
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$AUDIT_LOG"
    WARN_COUNT=$((WARN_COUNT + 1))
}

###############################################################################
# Security Check Functions
###############################################################################

check_file_permissions() {
    log_info "Checking critical file permissions..."

    local checked=0

    # Check engine configuration files
    if [ -f "/etc/ovirt-engine/engine.conf" ]; then
        checked=$((checked + 1))
        PERMS=$(stat -c "%a" /etc/ovirt-engine/engine.conf)
        if [ "$PERMS" == "600" ] || [ "$PERMS" == "640" ]; then
            log_pass "engine.conf has secure permissions ($PERMS)"
        else
            log_fail "engine.conf has insecure permissions ($PERMS), should be 600 or 640"
        fi
    fi

    # Check database password file
    if [ -f "/etc/ovirt-engine/.pgpass" ]; then
        checked=$((checked + 1))
        PERMS=$(stat -c "%a" /etc/ovirt-engine/.pgpass)
        if [ "$PERMS" == "600" ]; then
            log_pass ".pgpass has secure permissions (600)"
        else
            log_fail ".pgpass has insecure permissions ($PERMS), must be 600"
        fi
    fi

    if [ "$checked" -eq 0 ]; then
        log_warn "No critical permission targets found on this installation"
    fi
}

check_ssl_certificates() {
    log_info "Checking SSL/TLS certificates..."

    CERT_PATH="/etc/pki/ovirt-engine/certs"
    if [ -d "$CERT_PATH" ]; then
        # Check certificate expiration
        for cert in "$CERT_PATH"/*.cer "$CERT_PATH"/*.pem; do
            if [ -f "$cert" ]; then
                EXPIRY=$(openssl x509 -enddate -noout -in "$cert" 2>/dev/null | cut -d= -f2)
                EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s 2>/dev/null || echo 0)
                CURRENT_EPOCH=$(date +%s)
                DAYS_LEFT=$(( ($EXPIRY_EPOCH - $CURRENT_EPOCH) / 86400 ))

                if [ $DAYS_LEFT -gt 30 ]; then
                    log_pass "Certificate $(basename $cert) valid for $DAYS_LEFT days"
                elif [ $DAYS_LEFT -gt 0 ]; then
                    log_warn "Certificate $(basename $cert) expires in $DAYS_LEFT days"
                else
                    log_fail "Certificate $(basename $cert) has expired"
                fi
            fi
        done
    else
        log_warn "Certificate directory not found: $CERT_PATH"
    fi
}

check_database_security() {
    log_info "Checking database security settings..."

    # Check PostgreSQL connection encryption
    if command -v psql &> /dev/null; then
        local db_ssl db_encrypt
        if ! db_ssl=$(postgres_psql -tAc 'SHOW ssl;' 2>/dev/null); then
            log_warn "Database security settings unavailable (non-interactive PostgreSQL access denied)"
            return
        fi
        db_ssl=$(printf '%s\n' "$db_ssl" | awk 'NF { print tolower($1); exit }')
        if [ "$db_ssl" = "on" ]; then
            log_pass "Database SSL is enabled"
        else
            log_warn "Database SSL is not enabled"
        fi

        # Check password encryption
        if ! db_encrypt=$(postgres_psql -tAc 'SHOW password_encryption;' 2>/dev/null); then
            log_warn "Database password encryption setting unavailable"
            return
        fi
        db_encrypt=$(printf '%s\n' "$db_encrypt" | awk 'NF { print tolower($1); exit }')
        if [ "$db_encrypt" = "scram-sha-256" ]; then
            log_pass "Database password encryption is scram-sha-256"
        else
            log_warn "Database password encryption is not using scram-sha-256"
        fi
    else
        log_warn "psql command not available, skipping database checks"
    fi
}

# The engine runs this script as the ovirt user. `su - postgres` can prompt for
# a password and wait forever because the web-admin action has no interactive
# stdin. Use non-interactive sudo instead so unavailable database access is
# reported as a warning rather than blocking the audit.
postgres_psql() {
    if ! command -v sudo >/dev/null 2>&1; then
        return 127
    fi

    timeout 15s sudo -n -u postgres psql -d engine "$@"
}

check_network_security() {
    log_info "Checking network security settings..."

    # Check firewall status
    if command -v firewall-cmd &> /dev/null; then
        if firewall-cmd --state &> /dev/null; then
            log_pass "Firewall is active"

            # Check required ports
            HTTPS_OPEN=$(firewall-cmd --list-ports 2>/dev/null | grep -c "443/tcp" || echo 0)
            if [ "$HTTPS_OPEN" -gt 0 ]; then
                log_pass "HTTPS port (443) is open in firewall"
            else
                log_warn "HTTPS port (443) may not be open in firewall"
            fi
        else
            log_warn "Firewall is not active"
        fi
    fi

    # Check SELinux status
    if command -v getenforce &> /dev/null; then
        SELINUX_STATUS=$(getenforce)
        if [ "$SELINUX_STATUS" == "Enforcing" ]; then
            log_pass "SELinux is enforcing"
        elif [ "$SELINUX_STATUS" == "Permissive" ]; then
            log_warn "SELinux is in permissive mode"
        else
            log_fail "SELinux is disabled"
        fi
    fi
}

check_authentication_settings() {
    log_info "Checking authentication settings..."

    # Check AAA configuration
    AAA_CONFIG="/etc/ovirt-engine/aaa"
    if [ -d "$AAA_CONFIG" ]; then
        log_pass "AAA configuration directory exists"

        # Check for LDAP configuration
        if ls "$AAA_CONFIG"/*.properties &> /dev/null; then
            log_pass "Authentication providers configured"
        else
            log_warn "No authentication providers found"
        fi
    else
        log_warn "AAA configuration directory not found"
    fi
}

check_auth_failure_controls() {
    log_info "Checking authentication failure controls (5-failure lockout/unlock)..."

    local engine_log="${ENGINE_LOG_OVERRIDE:-/var/log/ovirt-engine/engine.log}"
    if [ ! -f "$engine_log" ]; then
        log_warn "engine.log not found, cannot verify account lockout events"
        return
    fi

    local failed_count locked_count unlocked_count
    failed_count=$(grep -ci "login failed\|USER_LOGIN_FAILED" "$engine_log" 2>/dev/null || true)
    locked_count=$(grep -ci "account locked\|USER_ACCOUNT_LOCKED" "$engine_log" 2>/dev/null || true)
    unlocked_count=$(grep -ci "account unlocked\|USER_ACCOUNT_UNLOCKED" "$engine_log" 2>/dev/null || true)

    if [ "$failed_count" -gt 0 ]; then
        log_pass "Authentication failure audit events found ($failed_count)"
    else
        log_warn "No authentication failure audit events found"
    fi

    if [ "$locked_count" -gt 0 ]; then
        log_pass "Account lock events found ($locked_count)"
    else
        log_warn "No account lock events found (verify 5-failure lockout policy)"
    fi

    if [ "$unlocked_count" -gt 0 ]; then
        log_pass "Account unlock events found ($unlocked_count)"
    else
        log_warn "No account unlock events found"
    fi
}

check_session_timeout_controls() {
    log_info "Checking session timeout controls (10 minutes)..."

    local candidates=(
        "/etc/ovirt-engine/engine.conf.d/99-custom-sso.conf"
        "/etc/ovirt-engine/engine.conf"
        "/etc/ovirt-engine/ovirt-websocket-proxy.conf"
    )

    local found=0
    local match=0
    for cfg in "${candidates[@]}"; do
        if [ -f "$cfg" ]; then
            found=1
            if grep -Eq "(session|timeout|idle).*(600|10m|10min)" "$cfg"; then
                log_pass "Session timeout policy (~600s) found in $(basename "$cfg")"
                match=1
            fi
        fi
    done

    if [ "$found" -eq 0 ]; then
        log_warn "No known session timeout config files found"
    elif [ "$match" -eq 0 ]; then
        log_warn "Session timeout 600s not detected in known config files"
    fi
}

check_audit_query_capability() {
    log_info "Checking audit log query capability..."

    if ! command -v psql &> /dev/null; then
        log_warn "psql not available, cannot validate audit_log table access"
        return
    fi

    local audit_table
    if ! audit_table=$(postgres_psql -tAc \
            "SELECT 1 FROM information_schema.tables WHERE table_name='audit_log'" 2>/dev/null); then
        log_warn "audit_log query unavailable (non-interactive PostgreSQL access denied)"
        return
    fi

    if printf '%s\n' "$audit_table" | grep -qx "1"; then
        log_pass "audit_log table exists and is queryable"
    else
        log_warn "audit_log table was not found"
    fi
}

check_audit_logging() {
    log_info "Checking audit logging configuration..."

    # Check if audit log is enabled
    AUDIT_LOG_DIR="/var/log/ovirt-engine"
    if [ -d "$AUDIT_LOG_DIR" ]; then
        log_pass "Audit log directory exists"

        # Check recent audit activity
        if [ -f "$AUDIT_LOG_DIR/engine.log" ]; then
            RECENT_LOGS=$(find "$AUDIT_LOG_DIR/engine.log" -mtime -1 2>/dev/null | wc -l)
            if [ "$RECENT_LOGS" -gt 0 ]; then
                log_pass "Audit logging is active (logs from last 24 hours)"
            else
                log_warn "No recent audit logs found"
            fi
        fi
    else
        log_fail "Audit log directory not found"
    fi
}

check_service_security() {
    log_info "Checking service security..."

    # Check if engine is running as non-root
    if systemctl is-active ovirt-engine &> /dev/null; then
        ENGINE_USER=$(ps aux | grep ovirt-engine | grep -v grep | awk '{print $1}' | head -1)
        if [ "$ENGINE_USER" != "root" ]; then
            log_pass "Engine is running as non-root user ($ENGINE_USER)"
        else
            log_fail "Engine is running as root (security risk)"
        fi
    else
        log_warn "Engine service is not running"
    fi
}

check_integrity_checksums() {
    log_info "Checking file integrity checksums..."

    # Check critical JAR files
    ENGINE_LIB="/usr/share/ovirt-engine/modules"
    if [ -d "$ENGINE_LIB" ]; then
        JAR_COUNT=$(find "$ENGINE_LIB" -name "*.jar" 2>/dev/null | wc -l)
        if [ "$JAR_COUNT" -gt 0 ]; then
            log_pass "Found $JAR_COUNT engine JAR files"

            # Do not use a fixed /tmp path. A previous root-owned file at that
            # path prevents the ovirt user from opening it and causes this
            # otherwise read-only check to fail.
            local checksum_file
            if ! checksum_file=$(mktemp "${TMPDIR:-/tmp}/ovirt-jar-checksums.XXXXXX"); then
                log_warn "Unable to create a temporary checksum file"
                return
            fi

            if find "$ENGINE_LIB" -name "*.jar" -exec sha256sum {} \; > "$checksum_file" 2>/dev/null; then
                log_info "Generated checksums for $JAR_COUNT JAR files"
            else
                log_warn "Unable to generate checksums for engine JAR files"
            fi
            rm -f "$checksum_file"
        else
            log_warn "No JAR files found in engine library"
        fi
    else
        log_warn "Engine library directory not found"
    fi
}

create_integrity_baseline() {
    log_info "Creating integrity baseline..."

    local target_dirs=(
        "/usr/share/ovirt-engine/modules"
        "/etc/ovirt-engine"
    )

    mkdir -p "$(dirname "$INTEGRITY_BASELINE")"
    : > "$INTEGRITY_BASELINE"

    local wrote=0
    for d in "${target_dirs[@]}"; do
        if [ -d "$d" ]; then
            find "$d" -type f \( -name "*.jar" -o -name "*.conf" -o -name "*.properties" -o -name "*.xml" \) -exec sha256sum {} \; >> "$INTEGRITY_BASELINE" 2>/dev/null || true
            wrote=1
        fi
    done

    if [ "$wrote" -eq 1 ] && [ -s "$INTEGRITY_BASELINE" ]; then
        log_pass "Integrity baseline generated at $INTEGRITY_BASELINE"
    else
        log_warn "Integrity baseline could not be generated (no target files found)"
    fi
}

verify_integrity_baseline() {
    log_info "Verifying integrity baseline..."

    if [ ! -f "$INTEGRITY_BASELINE" ]; then
        log_warn "Integrity baseline missing: $INTEGRITY_BASELINE"
        return
    fi

    if sha256sum -c "$INTEGRITY_BASELINE" >/tmp/ovirt-integrity-check.log 2>&1; then
        log_pass "Integrity verification passed"
    else
        log_fail "Integrity verification failed (see /tmp/ovirt-integrity-check.log)"
    fi
}

check_ip_block_audit_events() {
    log_info "Checking audit entries for blocked source IP events..."

    local log_candidates=(
        "/var/log/firewalld"
        "/var/log/messages"
        "/var/log/secure"
        "/var/log/ovirt-engine/engine.log"
    )

    local found=0
    for lf in "${log_candidates[@]}"; do
        if [ -r "$lf" ] && grep -Eqi "DROP|REJECT|blocked|blacklist|ip block" "$lf" 2>/dev/null; then
            log_pass "IP block-related events found in $(basename "$lf")"
            found=1
            break
        fi
    done

    if [ "$found" -eq 0 ]; then
        log_warn "No IP block audit events found in common log locations"
    fi
}


notify_admin_storage_action() {
    local subject="$1"
    local body="$2"

    if command -v mail >/dev/null 2>&1; then
        echo "$body" | mail -s "$subject" "$ADMIN_NOTIFY_EMAIL" || true
        log_info "Admin notification sent to $ADMIN_NOTIFY_EMAIL"
    elif command -v mailx >/dev/null 2>&1; then
        echo "$body" | mailx -s "$subject" "$ADMIN_NOTIFY_EMAIL" || true
        log_info "Admin notification sent to $ADMIN_NOTIFY_EMAIL"
    else
        logger -t ovirt-security-audit "$subject - $body" || true
        log_warn "mail/mailx not found; notification sent via syslog logger"
    fi
}

compress_and_cleanup_old_audit_logs() {
    local audit_dir="$1"
    local archive_dir="$audit_dir/archive"
    local archive_file="$archive_dir/ovirt-engine-audit-older-than-${AUDIT_RETENTION_DAYS}d-$(date +%Y%m%d-%H%M%S).tar.gz"

    mkdir -p "$archive_dir"

    mapfile -t old_files < <(find "$audit_dir" -type f -mtime +$AUDIT_RETENTION_DAYS ! -path "$archive_dir/*" 2>/dev/null)

    if [ "${#old_files[@]}" -eq 0 ]; then
        log_warn "No audit files older than ${AUDIT_RETENTION_DAYS} days found for cleanup"
        return 1
    fi

    if tar -czf "$archive_file" "${old_files[@]}" 2>/tmp/ovirt-audit-compress.err; then
        rm -f "${old_files[@]}"
        log_pass "Compressed and removed ${#old_files[@]} old audit files -> $archive_file"
        notify_admin_storage_action \
            "[oVirt] Audit log storage emergency cleanup executed" \
            "Filesystem usage exceeded 95%. Compressed and removed ${#old_files[@]} files older than ${AUDIT_RETENTION_DAYS} days. Archive: $archive_file"
        return 0
    else
        log_fail "Failed to compress old audit logs (see /tmp/ovirt-audit-compress.err)"
        notify_admin_storage_action \
            "[oVirt] Audit log storage emergency cleanup FAILED" \
            "Filesystem usage exceeded 95%, but archive creation failed. Check /tmp/ovirt-audit-compress.err"
        return 1
    fi
}

check_audit_storage_capacity() {
    log_info "Checking audit storage capacity thresholds..."

    local audit_dir="${AUDIT_STORAGE_DIR_OVERRIDE:-/var/log/ovirt-engine}"
    if [ ! -d "$audit_dir" ]; then
        log_warn "Audit directory missing: $audit_dir"
        return
    fi

    local usage
    usage="${AUDIT_STORAGE_USAGE_OVERRIDE:-}"
    if [ -z "$usage" ]; then
        usage=$(df -P "$audit_dir" | awk 'NR==2 {gsub(/%/,"",$5); print $5}')
    fi
    if [ -z "$usage" ]; then
        log_warn "Unable to determine filesystem usage for $audit_dir"
        return
    fi

    if [ "$usage" -ge 95 ]; then
        log_fail "Audit storage usage critical: ${usage}% (triggering emergency cleanup for files older than ${AUDIT_RETENTION_DAYS} days)"
        compress_and_cleanup_old_audit_logs "$audit_dir" || true
    elif [ "$usage" -ge 85 ]; then
        log_warn "Audit storage usage high: ${usage}% (compress/archive and offload)"
    elif [ "$usage" -ge 70 ]; then
        log_warn "Audit storage usage warning: ${usage}% (capacity plan needed)"
    else
        log_pass "Audit storage usage healthy: ${usage}%"
    fi
}

check_audit_write_failures() {
    log_info "Checking audit write failure signals..."

    local engine_log="${ENGINE_LOG_OVERRIDE:-/var/log/ovirt-engine/engine.log}"
    if [ ! -f "$engine_log" ]; then
        log_warn "engine.log missing, cannot inspect write failure patterns"
        return
    fi

    local failure_pattern recent_log
    failure_pattern="failed to (persist|save|write).*(audit|event)|"\
"audit(log)?dao.*(fail|error)|insert into audit_log.*(fail|error)|"\
"audit[_ ]log.*(disk full|i/o error)"
    recent_log=$(tail -n 20000 "$engine_log" 2>/dev/null || true)
    if printf '%s\n' "$recent_log" | grep -Eiv \
            "SECURITY_AUDIT_(FAILED|WARNING)|Security audit" | grep -Eqi "$failure_pattern"; then
        log_fail "Detected potential audit write failure indicators in engine.log"
    else
        log_pass "No audit write failure indicators detected in engine.log"
    fi
}

self_test_security_controls() {
    cat << 'EOF'
==========================================================================
Self-test runbook (periodic or admin-requested)
==========================================================================
1) Create test accounts (user/admin) and record ticket/change ID.
2) Trigger 5 consecutive failed logins from one source IP.
3) Verify account lock event and audit-log fields (user, IP, reason, count).
4) Unlock by admin and verify unlock audit record with reason.
5) Login successfully, stay idle >10 minutes, verify session expiration.
6) Re-login and ensure a new session ID is issued.
7) Execute integrity verify (baseline compare) and record results.
8) Validate IP-block event appears in network/app audit channels.
9) Simulate low-storage threshold and verify escalation workflow.
10) Archive artifacts: screenshots, logs, SQL query output, final verdict.
==========================================================================
EOF
}

check_backup_configuration() {
    log_info "Checking backup configuration..."

    # Check for backup configuration
    BACKUP_DIR="/var/lib/ovirt-engine-backup"
    if [ -d "$BACKUP_DIR" ]; then
        BACKUP_COUNT=$(find "$BACKUP_DIR" -name "*.tar.gz" -mtime -7 2>/dev/null | wc -l)
        if [ "$BACKUP_COUNT" -gt 0 ]; then
            log_pass "Found $BACKUP_COUNT recent backups (last 7 days)"
        else
            log_warn "No recent backups found (last 7 days)"
        fi
    else
        log_warn "Backup directory not found"
    fi
}

###############################################################################
# Main Execution
###############################################################################

main() {
    exec 8>"$AUDIT_LOCK"
    if ! flock -n 8; then
        echo "Security audit is already running" >&2
        exit 75
    fi

    case "${1:-}" in
        --self-test)
            self_test_security_controls
            exit 0
            ;;
        --integrity-baseline)
            mkdir -p "$(dirname "$AUDIT_LOG")"
            create_integrity_baseline
            exit 0
            ;;
        --integrity-verify)
            mkdir -p "$(dirname "$AUDIT_LOG")"
            verify_integrity_baseline
            exit 0
            ;;
    esac

    echo "========================================================================="
    echo "OVirt Engine Security Audit"
    echo "Date: $(date)"
    echo "========================================================================="
    echo ""

    # Create log directory if it doesn't exist
    mkdir -p "$(dirname $AUDIT_LOG)"

    # Run all security checks
    check_file_permissions
    echo ""
    check_ssl_certificates
    echo ""
    check_database_security
    echo ""
    check_network_security
    echo ""
    check_authentication_settings
    echo ""
    check_auth_failure_controls
    echo ""
    check_session_timeout_controls
    echo ""
    check_audit_logging
    echo ""
    check_audit_query_capability
    echo ""
    check_service_security
    echo ""
    check_integrity_checksums
    echo ""
    verify_integrity_baseline
    echo ""
    check_ip_block_audit_events
    echo ""
    check_audit_storage_capacity
    echo ""
    check_audit_write_failures
    echo ""
    check_backup_configuration
    echo ""

    # Generate summary
    echo "========================================================================="
    echo "Security Audit Summary"
    echo "========================================================================="
    echo -e "${GREEN}Passed: $PASS_COUNT${NC}"
    echo -e "${YELLOW}Warnings: $WARN_COUNT${NC}"
    echo -e "${RED}Failed: $FAIL_COUNT${NC}"
    echo ""
    echo "Detailed log: $AUDIT_LOG"
    echo ""

    # Generate JSON results
    cat > "$AUDIT_RESULTS" << EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "summary": {
    "passed": $PASS_COUNT,
    "warnings": $WARN_COUNT,
    "failed": $FAIL_COUNT,
    "total": $((PASS_COUNT + WARN_COUNT + FAIL_COUNT))
  },
  "status": "$([ $FAIL_COUNT -eq 0 ] && echo "PASS" || echo "FAIL")",
  "log_file": "$AUDIT_LOG"
}
EOF

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
