#!/bin/bash
#
# Ownership and mode of the self-test's process files, read as root.
#
# The self-test runs as the engine user, which cannot look into every directory the six
# processes keep their files in (PostgreSQL's data directory is the database account's alone).
# This prints, for each executable and configuration file of
# /usr/share/ovirt-engine/conf/ovworks-process-files.conf, one line:
#
#   PATH <TAB> STATE <TAB> MODE <TAB> UID <TAB> USER <TAB> GROUP <TAB> KIND <TAB> WRITABLE
#
# STATE is present, missing or denied; KIND file, directory or other; WRITABLE, for a directory
# measured as a tree, the first thing in it that its group or others may write, otherwise -.
#
# It takes no arguments and reads only that list, so the sudo rule that lets the engine user run
# it names exactly what it can learn: who owns the listed files and their modes - nothing else.
#

set -u

LIST=/usr/share/ovirt-engine/conf/ovworks-process-files.conf
# A list given in the environment only when not run through sudo, which is what the tests do.
if [ -z "${SUDO_USER:-}" ] && [ -n "${OVWORKS_PROCESS_FILES:-}" ]; then
    LIST="$OVWORKS_PROCESS_FILES"
fi

# denied when the nearest directory above PATH that can be seen cannot be searched: PATH may be
# there, and is only out of sight.
hidden() {
    local dir
    dir=$(dirname "$1")
    while [ "$dir" != "/" ] && [ ! -d "$dir" ]; do
        dir=$(dirname "$dir")
    done
    [ ! -x "$dir" ]
}

if [ ! -r "$LIST" ]; then
    echo "Process file list not readable: $LIST" >&2
    exit 1
fi

while read -r process type flags path; do
    case "$process" in
        ''|'#'*) continue ;;
    esac
    [ "$type" = "unit" ] && continue
    if [ -e "$path" ]; then
        info=$(stat -L -c '%a	%u	%U	%G	%F' "$path" 2>/dev/null) || {
            printf '%s\tdenied\t-\t-\t-\t-\t-\t-\n' "$path"
            continue
        }
        kind=$(printf '%s' "$info" | cut -f5)
        case "$kind" in
            'regular file'|'regular empty file') kind=file ;;
            directory) kind=directory ;;
            *) kind=other ;;
        esac
        writable=-
        case ",$flags," in
            *,tree,*)
                if [ "$kind" = "directory" ]; then
                    found=$(find "$path" -perm /022 ! -type l -print -quit 2>/dev/null)
                    [ -n "$found" ] && writable="$found"
                fi
                ;;
        esac
        printf '%s\tpresent\t%s\t%s\n' "$path" "$(printf '%s' "$info" | cut -f1-4)" "$kind	$writable"
    elif hidden "$path"; then
        printf '%s\tdenied\t-\t-\t-\t-\t-\t-\n' "$path"
    else
        printf '%s\tmissing\t-\t-\t-\t-\t-\t-\n' "$path"
    fi
done < "$LIST"
exit 0
