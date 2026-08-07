package org.ovirt.engine.core.bll;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.ovirt.engine.core.utils.EngineLocalConfig;

public final class TerminalAuthConfigUtils {
    private static final Pattern SERIAL_PATTERN =
            Pattern.compile("(\"serialNum\"\\s*:\\s*\")([^\"]*)(\")"); //$NON-NLS-1$

    private TerminalAuthConfigUtils() {
    }

    public static Path getConfigPath() {
        return EngineLocalConfig.getInstance()
                .getEtcDir()
                .toPath()
                .resolve("encryptor") //$NON-NLS-1$
                .resolve("config.json"); //$NON-NLS-1$
    }

    public static String readSerialNumber() throws IOException {
        String content = Files.readString(getConfigPath(), StandardCharsets.UTF_8);
        Matcher matcher = SERIAL_PATTERN.matcher(content);
        return matcher.find() ? matcher.group(2) : null;
    }

    public static void updateSerialNumber(String serialNumber) throws IOException {
        Path configPath = getConfigPath();
        String content = Files.readString(configPath, StandardCharsets.UTF_8);
        Matcher matcher = SERIAL_PATTERN.matcher(content);
        if (!matcher.find()) {
            throw new IOException("serialNum field not found in config.json"); //$NON-NLS-1$
        }
        String updated = matcher.replaceFirst("$1" + Matcher.quoteReplacement(serialNumber) + "$3"); //$NON-NLS-1$ //$NON-NLS-2$
        if (!updated.equals(content)) {
            Files.writeString(configPath, updated, StandardCharsets.UTF_8, StandardOpenOption.TRUNCATE_EXISTING);
        }
    }
}
