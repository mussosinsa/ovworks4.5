package org.ovirt.engine.core.uutils.config;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class ShellLikeConfdTest {

    private static ShellLikeConfd config;

    @BeforeAll
    public static void beforeClass() throws Exception {
        config = new ShellLikeConfd();

        config.loadConfig(
                URLDecoder.decode(ClassLoader.getSystemResource("config.conf").getPath(), "UTF-8"),
                "/dev/null"
        );
    }

    @Test
    public void testValid() throws Exception {
        Object[] res = config.getProperties()
                .entrySet().stream().map(e -> String.format("%s=%s", e.getKey(), e.getValue())).sorted().toArray();

        String reference;
        try (InputStream in =
             new FileInputStream(URLDecoder.decode(ClassLoader.getSystemResource("config.conf.ref").getPath(), "UTF-8"))) {

            byte[] buffer = new byte[2048];
            int size = in.read(buffer);
            reference = new String(buffer, 0, size, StandardCharsets.UTF_8);
        }
        assertArrayEquals(reference.split("\n"), res);
    }

    @Test
    public void testGetSuffixedProperty() {
        assertEquals("value0", config.getProperty("key00", "non_existent", false));
        assertEquals("suffixed val", config.getProperty("key01", "suffixed", false));
        assertThrows(IllegalArgumentException.class, () -> config.getProperty("non_existent", "non_existent", false));
    }

    @Test
    public void testEncryptedSensitiveConfigFileIsSkipped() throws Exception {
        Path directory = Files.createTempDirectory("shell-like-confd");
        Path vars = directory.resolve("engine.conf");
        Path varsDirectory = directory.resolve("engine.conf.d");
        Files.createDirectories(varsDirectory);
        Files.writeString(vars, "key00=value0\n", StandardCharsets.UTF_8);
        Files.write(varsDirectory.resolve("10-setup-database.conf"), "OVENC001encrypted".getBytes(StandardCharsets.US_ASCII));
        Files.write(varsDirectory.resolve("10-setup-dwh-database.conf"), "OVVLT001encrypted".getBytes(StandardCharsets.US_ASCII));

        ShellLikeConfd localConfig = new ShellLikeConfd();
        localConfig.loadConfig(null, vars.toString());

        assertEquals("value0", localConfig.getProperty("key00"));
    }
}
