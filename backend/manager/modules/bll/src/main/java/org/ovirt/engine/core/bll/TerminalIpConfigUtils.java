package org.ovirt.engine.core.bll;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
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

    static String readRequireIpFromContent(String content) {
        Matcher matcher = REQUIRE_IP_PATTERN.matcher(content);
        StringBuilder result = new StringBuilder();
        while (matcher.find()) {
            if (result.length() > 0) {
                result.append('\n');
            }
            result.append(matcher.group(2).trim());
        }
        return result.length() == 0 ? null : result.toString();
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
        String requireIpPrefix = "Require ip "; //$NON-NLS-1$
        Matcher prefixMatcher = REQUIRE_IP_PATTERN.matcher(content);
        if (prefixMatcher.find()) {
            requireIpPrefix = prefixMatcher.group(1);
        }
        String normalizedValue = ipValue == null ? "" : ipValue.trim(); //$NON-NLS-1$
        List<String> addresses = new ArrayList<>();
        for (String line : normalizedValue.split("\\r?\\n")) { //$NON-NLS-1$
            String candidate = line.trim();
            if (candidate.isEmpty()) {
                continue;
            }
            if (!Ipv4AddressUtils.isSingleAddress(candidate)) {
                // A range admits machines nobody approved, so one terminal is one address here.
                // Ranges already in the configuration keep working; none is written from now on.
                throw new IOException(
                        "Only a single IPv4 address can be registered for terminal IP auth, " //$NON-NLS-1$
                                + "not a range: " //$NON-NLS-1$
                                + candidate);
            }
            if (!Ipv4AddressUtils.isUsableTerminalAddress(candidate)) {
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

        StringBuilder replacement = new StringBuilder();
        for (String address : addresses) {
            if (replacement.length() > 0) {
                replacement.append('\n');
            }
            replacement.append(requireIpPrefix).append(address);
        }

        String[] lines = content.split("\\r?\\n", -1); //$NON-NLS-1$
        StringBuilder updated = new StringBuilder();
        boolean replaced = false;
        for (String line : lines) {
            if (REQUIRE_IP_PATTERN.matcher(line).matches()) {
                if (!replaced && replacement.length() > 0) {
                    if (updated.length() > 0) {
                        updated.append("\n"); //$NON-NLS-1$
                    }
                    updated.append(replacement);
                }
                replaced = true;
                continue;
            }
            if (updated.length() > 0) {
                updated.append("\n"); //$NON-NLS-1$
            }
            updated.append(line);
        }
        if (!replaced) {
            throw new IOException("Require ip line not found in z-ovirt-engine-proxy.conf"); //$NON-NLS-1$
        }
        return updated.toString();
    }
}
