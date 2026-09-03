package org.ovirt.engine.core.dal.dbbroker.auditloghandling;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.RETURNS_DEFAULTS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.ovirt.engine.core.common.AuditLogType;

public class MessageResolverTest {

    @Test
    public void testResolveUnknownVariable() {
        final String message = "This is my ${Variable}";
        final String expectedResolved = String.format("This is my %1s", MessageResolver.UNKNOWN_VARIABLE_VALUE);
        Map<String, String> values = Collections.emptyMap();
        String resolvedMessage = MessageResolver.resolveMessage(message, values);
        assertEquals(expectedResolved, resolvedMessage);
    }

    @Test
    public void testResolveKnownVariable() {
        final String message = "This is my ${Variable}";
        final String expectedResolved = "This is my value";
        Map<String, String> values = Collections.singletonMap("variable", "value");
        String resolvedMessage = MessageResolver.resolveMessage(message, values);
        assertEquals(expectedResolved, resolvedMessage);
    }

    @Test
    public void testResolveCombinedMessage() {
        final String message =
                "${first} equals one, ${second} equals two, '${blank}' equals blank and ${nonExist} is unknown";
        final String expectedResolved =
                String.format("one equals one, two equals two, ' ' equals blank and %1s is unknown",
                        MessageResolver.UNKNOWN_VARIABLE_VALUE);
        Map<String, String> values = new HashMap<>();
        values.put("first", "one");
        values.put("second", "two");
        values.put("blank", " ");
        String resolvedMessage = MessageResolver.resolveMessage(message, values);
        assertEquals(expectedResolved, resolvedMessage);
    }

    @Test
    public void testResolveAuditLogableBase() {
        final String vdsName = "TestVDS";
        final String vmName = "TestVM";
        final String message =
                "The VM name is ${vmName}, the VDS name is ${vdsName} and the template name is ${vmTemplateName}";
        final String expectedResolved =
                String.format("The VM name is %1s, the VDS name is %2s and the template name is %3s",
                        vmName,
                        vdsName,
                        MessageResolver.UNKNOWN_VARIABLE_VALUE);

        AuditLogableBase logable = mock(AuditLogableBase.class, RETURNS_DEFAULTS);
        when(logable.getVdsName()).thenReturn("TestVDS");
        when(logable.getVmName()).thenReturn("TestVM");

        String resolvedMessage = MessageResolver.resolveMessage(message, logable);
        assertEquals(expectedResolved, resolvedMessage);
    }

    @Test
    public void testPasswordResetAuditIdentifiesTargetActorAndSourceIp() {
        assertEquals(
                "Password for selected local user 'target@internal' was reset by operator@internal from 192.0.2.10.",
                resolveUserSecurityEvent(AuditLogType.LOCAL_USER_PASSWORD_RESET));
    }

    @Test
    public void testUnlockAuditIdentifiesTargetActorAndSourceIp() {
        assertEquals(
                "Selected user account 'target@internal' was unlocked by operator@internal from 192.0.2.10.",
                resolveUserSecurityEvent(AuditLogType.USER_ACCOUNT_UNLOCKED));
    }

    private String resolveUserSecurityEvent(AuditLogType type) {
        Map<String, String> values = new HashMap<>();
        values.put("TargetUser", "target@internal");
        values.put("UserName", "operator@internal");
        values.put("SourceIP", "192.0.2.10");
        return MessageResolver.resolveMessage(MessageBundler.getMessage(type), values);
    }
}
