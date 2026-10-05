package org.ovirt.engine.core.bll;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * What a write of the terminal IP list does to it: which addresses it registers and which it
 * removes.
 *
 * <p>The screen sends the whole list for every operation - registering one address, replacing one,
 * deleting one - so the request alone does not say which of the three it was, and the audit record
 * said only that the list "was updated". It is worked out here instead, from the list the web
 * server configuration holds before the write and the list the write asks for, so the record names
 * the address and the operation whatever the client claims to be doing.</p>
 */
final class TerminalIpChange {

    enum Kind {
        /** Addresses were registered and none removed. */
        ADDED,
        /** One address was replaced by another. */
        CHANGED,
        /** Addresses were removed and none registered. */
        REMOVED,
        /** Nothing changed, or several addresses at once in both directions. */
        OTHER
    }

    /** Always kept on the list by {@link TerminalIpConfigUtils}, so never reported as either. */
    private static final String LOOPBACK = "127.0.0.1"; //$NON-NLS-1$

    private final List<String> added;
    private final List<String> removed;

    private TerminalIpChange(List<String> added, List<String> removed) {
        this.added = Collections.unmodifiableList(added);
        this.removed = Collections.unmodifiableList(removed);
    }

    /**
     * @param registered the addresses the configuration holds now, one per line, or null
     * @param requested the addresses the write asks for, one per line, or null
     */
    static TerminalIpChange between(String registered, String requested) {
        Set<String> before = addresses(registered);
        Set<String> after = addresses(requested);
        List<String> added = new ArrayList<>();
        for (String address : after) {
            if (!before.contains(address) && !LOOPBACK.equals(address)) {
                added.add(address);
            }
        }
        List<String> removed = new ArrayList<>();
        for (String address : before) {
            if (!after.contains(address) && !LOOPBACK.equals(address)) {
                removed.add(address);
            }
        }
        return new TerminalIpChange(added, removed);
    }

    private static Set<String> addresses(String lines) {
        Set<String> addresses = new LinkedHashSet<>();
        if (lines == null) {
            return addresses;
        }
        for (String line : lines.split("\\r?\\n")) { //$NON-NLS-1$
            String address = line.trim();
            if (!address.isEmpty()) {
                addresses.add(address);
            }
        }
        return addresses;
    }

    Kind getKind() {
        if (added.size() == 1 && removed.size() == 1) {
            return Kind.CHANGED;
        }
        if (!added.isEmpty() && removed.isEmpty()) {
            return Kind.ADDED;
        }
        if (added.isEmpty() && !removed.isEmpty()) {
            return Kind.REMOVED;
        }
        return Kind.OTHER;
    }

    List<String> getAdded() {
        return added;
    }

    List<String> getRemoved() {
        return removed;
    }

    /** {@code "added: a, b; removed: c"}, for the records that name more than one address. */
    String describe() {
        if (added.isEmpty() && removed.isEmpty()) {
            return "no address added or removed"; //$NON-NLS-1$
        }
        StringBuilder text = new StringBuilder();
        if (!added.isEmpty()) {
            text.append("added: ").append(String.join(", ", added)); //$NON-NLS-1$ //$NON-NLS-2$
        }
        if (!removed.isEmpty()) {
            if (text.length() > 0) {
                text.append("; "); //$NON-NLS-1$
            }
            text.append("removed: ").append(String.join(", ", removed)); //$NON-NLS-1$ //$NON-NLS-2$
        }
        return text.toString();
    }
}
