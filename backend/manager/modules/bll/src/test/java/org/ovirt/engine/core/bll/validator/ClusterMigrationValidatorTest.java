package org.ovirt.engine.core.bll.validator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.junit.jupiter.MockitoExtension;
import org.ovirt.engine.core.bll.ValidationResult;
import org.ovirt.engine.core.common.businessentities.VDS;
import org.ovirt.engine.core.common.config.ConfigValues;
import org.ovirt.engine.core.common.errors.EngineMessage;
import org.ovirt.engine.core.compat.Guid;
import org.ovirt.engine.core.dao.VdsDao;
import org.ovirt.engine.core.utils.MockConfigDescriptor;
import org.ovirt.engine.core.utils.MockConfigExtension;

/** How many hosts a cluster needs before a migration within it is allowed. */
@ExtendWith({ MockitoExtension.class, MockConfigExtension.class })
public class ClusterMigrationValidatorTest {

    private static final Guid A_CLUSTER = Guid.newGuid();

    /** What the setting is set to for these tests unless one of them says otherwise. */
    private static final int THREE = 3;

    private VdsDao vdsDao;

    private ClusterMigrationValidator validator;

    public static Stream<MockConfigDescriptor<?>> mockConfiguration() {
        return Stream.of(MockConfigDescriptor.of(ConfigValues.MinimumHostsForMigration, THREE));
    }

    @BeforeEach
    public void setUp() {
        vdsDao = mock(VdsDao.class);
        validator = new ClusterMigrationValidator(A_CLUSTER) {
            @Override
            protected VdsDao getVdsDao() {
                return vdsDao;
            }
        };
    }

    private void clusterHolds(int hosts) {
        List<VDS> found = new ArrayList<>();
        for (int i = 0; i < hosts; i++) {
            found.add(new VDS());
        }
        when(vdsDao.getAllForCluster(A_CLUSTER)).thenReturn(found);
    }

    /**
     * What was asked for: two hosts or fewer and the migration is refused. Two can move a machine
     * between them and nothing else here refuses it, so this is a decision about how the estate is
     * run - and it is one setting away from being the other decision.
     */
    @ParameterizedTest
    @CsvSource({ "0,false", "1,false", "2,false", "3,true", "9,true" })
    public void aClusterOfTwoIsNotAllowedAMigration(int hosts, boolean allowed) {
        clusterHolds(hosts);

        assertEquals(allowed, validator.hasEnoughHostsToMigrateWithin().isValid());
    }

    @Test
    public void andSaysWhatIsMissingWhenItRefuses() {
        clusterHolds(2);

        ValidationResult refused = validator.hasEnoughHostsToMigrateWithin();

        assertTrue(refused.getMessages().contains(
                EngineMessage.ACTION_TYPE_FAILED_NOT_ENOUGH_HOSTS_FOR_MIGRATION));
        assertTrue(refused.getVariableReplacements().contains("$minimumHosts 3"), //$NON-NLS-1$
                refused.getVariableReplacements().toString());
        assertTrue(refused.getVariableReplacements().contains("$clusterHosts 2"), //$NON-NLS-1$
                refused.getVariableReplacements().toString());
    }

    /**
     * One or less is no rule at all rather than a rule that always passes: an installation wanting
     * the engine's own judgement back sets it there, and then there is nothing to count.
     */
    @Test
    public void oneIsNoRuleAtAllAndCostsNoQuery() {
        assertTrue(new OneHostIsEnough().hasEnoughHostsToMigrateWithin().isValid());

        verify(vdsDao, never()).getAllForCluster(A_CLUSTER);
    }

    private class OneHostIsEnough extends ClusterMigrationValidator {

        OneHostIsEnough() {
            super(A_CLUSTER);
        }

        @Override
        protected VdsDao getVdsDao() {
            return vdsDao;
        }

        @Override
        protected int minimumHosts() {
            return 1;
        }
    }
}
