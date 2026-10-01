package org.ovirt.engine.core.bll;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.ovirt.engine.core.common.utils.Ipv4AddressUtils;

public final class TerminalIpConfigUtils {
    private static final Pattern REQUIRE_IP_PATTERN =
            Pattern.compile("(?m)^(\\s*Require\\s+ip\\s+)(.*)$"); //$NON-NLS-1$

    /**
     * Kept on the list whatever is registered, as engine-setup keeps it there. The engine's own
     * components reach the web server over the loopback interface, and the block these lines go
     * into no longer carries an unconditional allow to fall back on.
     */
    private static final String LOOPBACK_ADDRESS = "127.0.0.1"; //$NON-NLS-1$

    private TerminalIpConfigUtils() {
    }

    public static Path getConfigPath() {
        return Path.of("/etc/httpd/conf.d/z-ovirt-engine-proxy.conf"); //$NON-NLS-1$
    }

    public static String readRequireIp() throws IOException {
        String content = Files.readString(getConfigPath(), StandardCharsets.UTF_8);
        return readRequireIpFromContent(content);
    }

    /**
     * The registered terminals, each once, in the order they first appear.
     *
     * <p>The configuration carries the list in more than one block - the engine's address space and
     * the page shown while the engine is not running - and both are one setting, written together.
     * Reading every line of every block showed each terminal once per block; deleting one of the
     * copies then wrote back the other, so the address stayed registered and the screen looked as
     * if nothing had been applied. A block that was edited by hand and differs from the others
     * contributes its extra addresses, so the next write brings every block to the same list
     * without losing any of them.</p>
     */
    static String readRequireIpFromContent(String content) {
        Matcher matcher = REQUIRE_IP_PATTERN.matcher(content);
        Set<String> addresses = new LinkedHashSet<>();
        while (matcher.find()) {
            String address = matcher.group(2).trim();
            if (!address.isEmpty()) {
                addresses.add(address);
            }
        }
        return addresses.isEmpty() ? null : String.join("\n", addresses); //$NON-NLS-1$
    }

    /** @return the addresses the configuration currently carries, empty when it carries none */
    private static List<String> registeredAddresses(String content) {
        String registered = readRequireIpFromContent(content);
        if (registered == null) {
            return List.of();
        }
        List<String> addresses = new ArrayList<>();
        for (String line : registered.split("\\r?\\n")) { //$NON-NLS-1$
            String candidate = line.trim();
            if (!candidate.isEmpty()) {
                addresses.add(candidate);
            }
        }
        return addresses;
    }

    public static void updateRequireIp(String ipValue) throws IOException {
        Path configPath = getConfigPath();
        String content = Files.readString(configPath, StandardCharsets.UTF_8);
        String updatedContent = updateRequireIpInContent(content, ipValue);
        if (!updatedContent.equals(content)) {
            Files.writeString(configPath, updatedContent, StandardCharsets.UTF_8, StandardOpenOption.TRUNCATE_EXISTING);
        }
    }

    static String updateRequireIpInContent(String content, String ipValue) throws IOException {
        // What the configuration already holds. These have been accepted once, so they are not
        // judged again - see the refusal below for why that matters.
        List<String> alreadyRegistered = registeredAddresses(content);

        String normalizedValue = ipValue == null ? "" : ipValue.trim(); //$NON-NLS-1$
        List<String> addresses = new ArrayList<>();
        for (String line : normalizedValue.split("\\r?\\n")) { //$NON-NLS-1$
            String candidate = line.trim();
            if (candidate.isEmpty()) {
                continue;
            }
            if (!alreadyRegistered.contains(candidate) && !Ipv4AddressUtils.isSingleAddress(candidate)) {
                // A range admits machines nobody approved, so one terminal is one address here.
                //
                // Only what is being registered now has to satisfy that. A range already in the
                // configuration is left alone, because the alternative is worse than the range:
                // the whole list is written in one go, so refusing it would refuse every edit
                // while it is there - including the edit that removes it. An administrator
                // upgrading into this rule would find the list frozen exactly as they left it,
                // with no way to bring it into line.
                throw new IOException(
                        "Only a single IPv4 address can be registered for terminal IP auth, " //$NON-NLS-1$
                                + "not a range: " //$NON-NLS-1$
                                + candidate);
            }
            if (!alreadyRegistered.contains(candidate) && !Ipv4AddressUtils.isUsableTerminalAddress(candidate)) {
                // Written into the web server this would read as a restriction while restricting
                // nothing, or would name an address no terminal can be reached at.
                throw new IOException(
                        "An address that matches every terminal, or that no terminal can have, " //$NON-NLS-1$
                                + "cannot be registered for terminal IP auth: " //$NON-NLS-1$
                                + candidate);
            }
            if (!addresses.contains(candidate)) {
                addresses.add(candidate);
            }
        }

        if (addresses.isEmpty()) {
            // The block these lines live in has no unconditional allow behind them any more, so an
            // empty list is not "no restriction" - it is a web server that answers nobody at all,
            // including whoever emptied it. Refusing here is the only point at which that is still
            // recoverable from the browser.
            throw new IOException(
                    "At least one terminal IP address must stay registered; " //$NON-NLS-1$
                            + "an empty list would refuse every terminal, this one included"); //$NON-NLS-1$
        }
        if (!addresses.contains(LOOPBACK_ADDRESS)) {
            addresses.add(0, LOOPBACK_ADDRESS);
        }

        String[] lines = content.split("\\r?\\n", -1); //$NON-NLS-1$
        StringBuilder updated = new StringBuilder();
        boolean replacedAny = false;
        // Each run of these lines is rewritten, not only the first.
        //
        // The configuration carries more than one block of them: the engine's own address space,
        // and the page the web server shows while the engine is not running. Writing the list into
        // the first block and dropping every line of the others left those blocks empty - and an
        // empty RequireAny answers nobody, so the first terminal registered after an upgrade would
        // have silently shut off whatever the later blocks guard. Every block wants the same list
        // of terminals, so every block gets it.
        boolean insideRun = false;
        for (String line : lines) {
            Matcher lineMatcher = REQUIRE_IP_PATTERN.matcher(line);
            if (lineMatcher.matches()) {
                if (!insideRun) {
                    // Each block keeps its own indentation.
                    if (updated.length() > 0) {
                        updated.append("\n"); //$NON-NLS-1$
                    }
                    updated.append(requireLines(lineMatcher.group(1), addresses));
                }
                insideRun = true;
                replacedAny = true;
                continue;
            }
            insideRun = false;
            if (updated.length() > 0) {
                updated.append("\n"); //$NON-NLS-1$
            }
            updated.append(line);
        }
        if (!replacedAny) {
            throw new IOException("Require ip line not found in z-ovirt-engine-proxy.conf"); //$NON-NLS-1$
        }
        return updated.toString();
    }

    private static String requireLines(String prefix, List<String> addresses) {
        StringBuilder lines = new StringBuilder();
        for (String address : addresses) {
            if (lines.length() > 0) {
                lines.append('\n');
            }
            lines.append(prefix).append(address);
        }
        return lines.toString();
    }
}
