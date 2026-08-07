package org.ovirt.engine.core.bll.aaa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.ovirt.engine.core.bll.NonTransactiveCommandAttribute;

class UnlockUserCommandTest {

    @Test
    void buildUnlockCandidatesWithSimpleLoginName() {
        List<String> candidates = new ArrayList<>(
                UnlockUserCommand.buildUnlockCandidates("admin", "internal-authz", "ovirt-engine"));

        assertEquals(List.of("admin", "admin@internal-authz", "admin@ovirt-engine"), candidates);
    }

    @Test
    void buildUnlockCandidatesWithQualifiedLoginName() {
        List<String> candidates = new ArrayList<>(
                UnlockUserCommand.buildUnlockCandidates("admin@internal-authz", "internal-authz", "ovirt-engine"));

        assertEquals(List.of("admin@internal-authz", "admin", "admin@ovirt-engine"), candidates);
    }

    @Test
    void buildUnlockCandidatesSkipsWildcardNamespace() {
        List<String> candidates = new ArrayList<>(
                UnlockUserCommand.buildUnlockCandidates("admin", "internal-authz", "*"));

        assertEquals(List.of("admin", "admin@internal-authz"), candidates);
    }

    @Test
    void unlockUserCommandIsNonTransactive() {
        assertNotNull(UnlockUserCommand.class.getAnnotation(NonTransactiveCommandAttribute.class));
    }
}
