#!/bin/bash
#
# Copyright oVirt Authors
# SPDX-License-Identifier: Apache-2.0
#
# Reports which of the files that are not compiled into the engine's jars differ from, or are
# missing at, their installed locations.
#
# Those files - shell scripts, the setup plugins, the python libraries, the database scripts -
# are deployed separately from engine.ear, and a deployment that carries the jars alone leaves
# the engine calling things that are not there. It has cost three outages already: a verification
# runner older than the engine that read a result nobody wrote, a stored function the engine
# called on every timer tick, and a setup plugin importing a module that had not been copied,
# which stopped engine-setup from running at all.
#
# Reads only. Nothing here changes the installation.
#
# Usage: ovirt-engine-check-deployment.sh [SOURCE_TREE]

set -u

SOURCE="${1:-.}"
ENGINE_USR="${ENGINE_USR:-/usr/share/ovirt-engine}"
ENGINE_EAR="${ENGINE_EAR:-$ENGINE_USR/engine.ear}"
PYTHON_SITELIB="${PYTHON_SITELIB:-}"

missing=0
differ=0
checked=0

# check SOURCE_RELATIVE_PATH INSTALL_DIRECTORY
#
# The second argument is always the directory the file is installed into, and the basename is
# appended here. Testing whether it is a directory would be wrong: on the installation this is
# meant to find, it is exactly the directory that does not exist.
check() {
    local source="$SOURCE/$1"
    local target="$2/$(basename "$1")"

    if [ ! -e "$source" ]; then
        return 0
    fi
    checked=$((checked + 1))

    if [ ! -e "$target" ]; then
        printf 'MISSING  %s\n' "$target"
        missing=$((missing + 1))
    elif ! cmp -s "$source" "$target"; then
        printf 'DIFFERS  %s\n' "$target"
        differ=$((differ + 1))
    fi
}

# The upgrade scripts this product adds, which is the 04_05_03xx range. The ones it inherits
# are not listed: several hundred lines saying that the installation has what it was installed
# with would bury the handful of lines that matter.
check_own_upgrade_scripts() {
    local file
    [ -d "$SOURCE/packaging/dbscripts/upgrade" ] || return 0
    while IFS= read -r file; do
        check "${file#"$SOURCE/"}" "$ENGINE_USR/dbscripts/upgrade"
    done < <(find "$SOURCE/packaging/dbscripts/upgrade" -maxdepth 1 -type f \
        -name '04_05_03*.sql' | sort)
}

if [ -z "$PYTHON_SITELIB" ]; then
    PYTHON_SITELIB="$(python3 -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])' 2>/dev/null)"
fi

echo "# Engine deployment check"
echo "# source: $SOURCE"
echo

# --- Scripts the engine runs ---------------------------------------------
check ov-works-security_audit.sh "$ENGINE_USR/bin"
check ovirt-engine-security-verification-runner.sh "$ENGINE_USR/bin"

# --- The engine's own python library -------------------------------------
check packaging/pythonlib/ovirt_engine/configfile.py "$PYTHON_SITELIB/ovirt_engine"
check packaging/pythonlib/ovirt_engine/cryptoevents.py "$PYTHON_SITELIB/ovirt_engine"

# --- Setup: the shared module and the plugins that import it -------------
check packaging/setup/ovirt_engine_setup/aide.py "$ENGINE_USR/setup/ovirt_engine_setup"
check packaging/setup/plugins/ovirt-engine-setup/ovirt-engine/system/acl.py \
    "$ENGINE_USR/setup/plugins/ovirt-engine-setup/ovirt-engine/system"
check packaging/setup/plugins/ovirt-engine-setup/ovirt-engine/config/aaajdbc.py \
    "$ENGINE_USR/setup/plugins/ovirt-engine-setup/ovirt-engine/config"
check packaging/setup/plugins/ovirt-engine-remove/ovirt-engine/system/aide.py \
    "$ENGINE_USR/setup/plugins/ovirt-engine-remove/ovirt-engine/system"

# --- The encryptor tools -------------------------------------------------
check packaging/encryptor/encrypt_conf_files.py "$ENGINE_USR/encryptor"
check packaging/encryptor/vault_passphrase.py "$ENGINE_USR/encryptor"

# --- Other configuration the engine reads --------------------------------
check packaging/etc/engine-config/engine-config.properties /etc/ovirt-engine/engine-config

# --- Database scripts ----------------------------------------------------
check packaging/dbscripts/user_login_failures_sp.sql "$ENGINE_USR/dbscripts"
check packaging/dbscripts/create_tables.sql "$ENGINE_USR/dbscripts"
check packaging/dbscripts/upgrade/pre_upgrade/0000_config.sql \
    "$ENGINE_USR/dbscripts/upgrade/pre_upgrade"
check_own_upgrade_scripts

# --- The administration application --------------------------------------
#
# Not a file comparison. WebAdmin is Java compiled to JavaScript, so nothing under frontend/ has
# a counterpart on the installation to compare with - what is deployed is a war holding files
# named after a hash of the compilation. What can be said is whether it was built after the
# source it is built from was last changed, and that is the question that matters: a change to a
# screen that is only in the source is a change nobody using the engine can see.
check_webadmin() {
    local war="$ENGINE_EAR/webadmin.war"
    local source_dir="$SOURCE/frontend"
    [ -d "$source_dir" ] || return 0
    checked=$((checked + 1))
    # Either an unpacked directory or the archive itself: both are deployments this has to be
    # able to answer about, and reporting an archive as missing would be a plain wrong answer.
    if [ ! -e "$war" ]; then
        printf 'MISSING  %s\n' "$war"
        missing=$((missing + 1))
        return 0
    fi

    # What the war was built from, rather than the directory holding it. A deployment directory's
    # own timestamp says when something in it was last rearranged; the bootstrap script is written
    # by the GWT compilation itself, so it says when these screens were built.
    local built=""
    if [ -d "$war" ]; then
        built=$(find "$war" -type f -name '*.nocache.js' -print -quit 2>/dev/null)
    fi
    [ -n "$built" ] || built="$war"

    local newer newest
    newer=$(find "$source_dir" -name target -prune -o -type f -newer "$built" -printf '%T@ %p\n' \
        2>/dev/null | sort -n)
    if [ -n "$newer" ]; then
        newest=$(printf '%s\n' "$newer" | tail -1 | cut -d' ' -f2-)
        printf 'STALE    %s\n' "$war"
        printf '         built before %s\n' "${newest#"$SOURCE/"}"
        printf '         and %s other source file(s) under frontend/\n' \
            "$(($(printf '%s\n' "$newer" | wc -l) - 1))"
        differ=$((differ + 1))
    fi
}

check_webadmin

echo
if [ "$checked" -eq 0 ]; then
    # Nothing was found to check, which is not the same as nothing being wrong. It means this was
    # pointed somewhere that is not the source tree - run from a home directory, most often, where
    # every path below is absent and every check quietly skips. Saying that everything is in place
    # would be the most misleading thing this script could do, so it says what actually happened.
    printf 'Nothing was checked: %s does not hold this product'"'"'s source.\n' "$SOURCE"
    echo
    echo "Give it the directory the source was built from, for example:"
    printf '  %s ~/ovirt-engine\n' "$0"
    exit 2
fi
printf '%s file(s) checked; %s missing, %s differing\n' "$checked" "$missing" "$differ"
if [ "$missing" -gt 0 ] || [ "$differ" -gt 0 ]; then
    echo
    echo "Copy them into place, then:"
    echo "  engine-setup                  # database scripts, setup plugins, directory ownership"
    echo "  systemctl restart ovirt-engine"
    echo
    echo "A war reported STALE is not copied into place. It is rebuilt and redeployed:"
    echo "  make clean install-dev PREFIX=/usr   # or rebuild and reinstall the rpm"
    echo "and then a browser holding the old screens is told to fetch them again"
    echo "(ctrl-shift-r), because it caches them."
    exit 1
fi
echo "Everything checked is in place and identical."
