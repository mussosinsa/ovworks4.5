package org.ovirt.engine.core.common.action;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.ovirt.engine.core.common.action.CommandBlacklist.Problem;

public class CommandBlacklistTest {

    @Test
    void anEntryBecomesTheProgramItRuns() {
        // A rule names a file, so the arguments are dropped rather than pretended to.
        assertEquals("netstat.exe", CommandBlacklist.normalize("netstat -a"));
        assertEquals("rm.exe", CommandBlacklist.normalize("rm -rf"));
        assertEquals("cmd.exe", CommandBlacklist.normalize("  CMD  "));
        assertEquals("cmd.exe", CommandBlacklist.normalize("C:\\Windows\\System32\\cmd.exe /c dir"));
        assertEquals("cmd.exe", CommandBlacklist.normalize("\"C:\\Windows\\System32\\cmd.exe\" /k"));
        assertEquals("script.ps1", CommandBlacklist.normalize("script.ps1"));
    }

    @Test
    void theCommandsWindowsShipsAsComAreBlockedAsComs() {
        assertEquals("format.com", CommandBlacklist.normalize("format c:"));
        assertEquals("more.com", CommandBlacklist.normalize("more"));
        assertEquals("tree.com", CommandBlacklist.normalize("tree"));
    }

    @Test
    void whatIsNotAProgramIsRefused() {
        for (String entry : Arrays.asList(null, "", "   ", "notes.txt", "a;b", "$(x)", "-rf", "..exe", "a'b")) {
            assertNull(CommandBlacklist.normalize(entry), String.valueOf(entry));
            assertEquals(Problem.INVALID, CommandBlacklist.check(entry, null), String.valueOf(entry));
        }
    }

    @Test
    void whatSignsAUserInCannotBeBlacklisted() {
        assertEquals(Problem.PROTECTED, CommandBlacklist.check("explorer", null));
        assertEquals(Problem.PROTECTED, CommandBlacklist.check("C:\\Windows\\System32\\winlogon.exe", null));
        assertEquals(Problem.PROTECTED, CommandBlacklist.check("qemu-ga", null));
        assertNull(CommandBlacklist.check("powershell", null));
    }

    @Test
    void aDescriptionIsOptionalButBounded() {
        assertNull(CommandBlacklist.check("netstat", ""));
        assertNull(CommandBlacklist.check("netstat", "네트워크 스캔 시도"));
        assertEquals(Problem.INVALID_DESCRIPTION, CommandBlacklist.check("netstat", "a\tb"));
        assertEquals(Problem.INVALID_DESCRIPTION, CommandBlacklist.check("netstat", "a\nb"));
        assertEquals(Problem.INVALID_DESCRIPTION,
                CommandBlacklist.check("netstat", String.join("", Collections.nCopies(101, "x"))));
    }

    @Test
    void aListSurvivesTheWayToTheGuestAndBack() {
        List<String[]> entries = Arrays.asList(
                new String[] { "netstat.exe", "네트워크 스캔 시도" },
                new String[] { "format.com", "" });

        List<String[]> decoded = CommandBlacklist.decode(CommandBlacklist.encode(entries));

        assertEquals(2, decoded.size());
        assertArrayEquals(entries.get(0), decoded.get(0));
        assertArrayEquals(entries.get(1), decoded.get(1));
        // What the guest writes: Windows line endings, and blank lines between.
        assertEquals(2, CommandBlacklist.decode("cmd.exe\t\r\n\r\nnetstat.exe\tscan\r\n").size());
        assertTrue(CommandBlacklist.decode(null).isEmpty());
        assertTrue(CommandBlacklist.decode("").isEmpty());
    }

    @Test
    void onlyAListAsTheDialogMakesItIsApplied() {
        assertTrue(CommandBlacklist.isApplicable(Collections.emptyList()));
        assertTrue(CommandBlacklist.isApplicable(Arrays.<String[]>asList(new String[] { "cmd.exe", "" })));
        // Not normalised, twice, protected, or one too many.
        assertFalse(CommandBlacklist.isApplicable(Arrays.<String[]>asList(new String[] { "cmd", "" })));
        assertFalse(CommandBlacklist.isApplicable(Arrays.asList(
                new String[] { "cmd.exe", "" }, new String[] { "cmd.exe", "x" })));
        assertFalse(CommandBlacklist.isApplicable(Arrays.<String[]>asList(new String[] { "explorer.exe", "" })));
        List<String[]> tooMany = new ArrayList<>();
        for (int i = 0; i <= CommandBlacklist.MAX_ENTRIES; i++) {
            tooMany.add(new String[] { "tool" + i + ".exe", "" });
        }
        assertFalse(CommandBlacklist.isApplicable(tooMany));
    }
}
