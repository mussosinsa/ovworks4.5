#!/bin/bash
#
# Stops the engine service at the engine's own request, after a scheduled security verification
# did not pass and ENGINE_SECURITY_VERIFICATION_FAILURE_ACTION is STOP.
#
# Started as root by ovirt-engine-security-halt.path when the engine leaves its request. The
# engine runs unprivileged and cannot stop its own service; this does, and nothing else. By the
# time the request exists the engine has already recorded the failure, raised the alert and
# recorded the halt; the wait below is the time it asked for, so that the event notifier can send
# the alert while the engine is still up.
#
# Removing the request file before the wait is over cancels the stop.

set -u

REQUEST="${SECURITY_HALT_REQUEST:-/var/lib/ovirt-engine/security/halt-request.json}"
ENGINE_SERVICE="${SECURITY_HALT_ENGINE_SERVICE:-ovirt-engine.service}"
SYSTEMCTL_COMMAND="${SYSTEMCTL_COMMAND:-/usr/bin/systemctl}"
LOGGER_COMMAND="${LOGGER_COMMAND:-/usr/bin/logger}"
PYTHON_COMMAND="${PYTHON_COMMAND:-/usr/bin/python3}"
SLEEP_COMMAND="${SLEEP_COMMAND:-sleep}"
# The engine never asks for more than an hour; a request saying otherwise is held to that.
MAX_WAIT_SECONDS=3600

say() {
    local priority="$1"
    shift
    printf '%s\n' "$*"
    "$LOGGER_COMMAND" -p "authpriv.$priority" -t ovirt-engine-security-halt "$*" || true
}

# The time the engine asked to be stopped at, as seconds since the epoch. Only this field is
# taken from the file: the engine's user wrote it, and it says nothing this script acts on beyond
# when to act.
read_not_before() {
    "$PYTHON_COMMAND" - "$REQUEST" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding='utf-8') as stream:
        value = json.load(stream).get('not_before')
    print(int(value))
except (OSError, ValueError, TypeError, AttributeError):
    print('')
PY
}

if [ ! -e "$REQUEST" ]; then
    exit 0
fi

not_before=$(read_not_before)
now=$(date +%s)
if [ -z "$not_before" ]; then
    # Unreadable is still a request: the engine wrote it because a verification failed.
    say warning "Engine stop request $REQUEST is unreadable; stopping without the delay"
    not_before=$now
fi
wait_seconds=$((not_before - now))
if [ "$wait_seconds" -gt "$MAX_WAIT_SECONDS" ]; then
    wait_seconds=$MAX_WAIT_SECONDS
fi

if [ "$wait_seconds" -gt 0 ]; then
    say crit "Scheduled security verification failed: $ENGINE_SERVICE will be stopped in ${wait_seconds}s; remove $REQUEST to cancel"
    while [ "$wait_seconds" -gt 0 ]; do
        if [ ! -e "$REQUEST" ]; then
            say warning "Engine stop cancelled: $REQUEST was removed"
            exit 0
        fi
        step=10
        [ "$wait_seconds" -lt "$step" ] && step=$wait_seconds
        "$SLEEP_COMMAND" "$step"
        wait_seconds=$((wait_seconds - step))
    done
fi

if [ ! -e "$REQUEST" ]; then
    say warning "Engine stop cancelled: $REQUEST was removed"
    exit 0
fi

# Removed before the stop, not after: the path unit starts this again for as long as the file
# exists, and an engine that is stopped has no further use for it.
rm -f "$REQUEST"

say crit "Stopping $ENGINE_SERVICE: a scheduled security verification did not pass (ENGINE_SECURITY_VERIFICATION_FAILURE_ACTION=STOP)"
if ! "$SYSTEMCTL_COMMAND" stop "$ENGINE_SERVICE"; then
    say err "Failed to stop $ENGINE_SERVICE after the scheduled security verification failed"
    exit 1
fi
say crit "$ENGINE_SERVICE stopped after the scheduled security verification failed; start it again once the findings are resolved"
exit 0
