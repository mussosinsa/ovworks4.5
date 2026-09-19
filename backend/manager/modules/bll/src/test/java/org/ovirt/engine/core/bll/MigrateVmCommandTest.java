package org.ovirt.engine.core.bll;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.ovirt.engine.core.bll.validator.ClusterMigrationValidator;
import org.ovirt.engine.core.bll.validator.VmValidator;
import org.ovirt.engine.core.common.action.MigrateVmParameters;
import org.ovirt.engine.core.common.businessentities.VM;
import org.ovirt.engine.core.common.errors.EngineMessage;
import org.ovirt.engine.core.compat.Guid;

@ExtendWith(MockitoExtension.class)
public class MigrateVmCommandTest {

    private Guid vmId = Guid.newGuid();

    private Guid aCluster = Guid.newGuid();

    @Mock
    VmValidator vmValidator;

    @Mock
    ClusterMigrationValidator clusterMigrationValidator;

    @Spy
    private MigrateVmCommand<MigrateVmParameters> command = new MigrateVmCommand<>(new MigrateVmParameters(false, vmId), null);


    @BeforeEach
    public void setUp() {
        VM vm = new VM();
        vm.setId(vmId);
        command.setVm(vm);
    }

    @Test
    public void testValidationFailsWhenVmHasDisksPluggedWithScsiReservation() {
        doNothing().when(command).logValidationFailed();
        doReturn(false).when(command).isVmDuringBackup();
        doReturn(vmValidator).when(command).getVmValidator();
        when(vmValidator.isVmPluggedDiskNotUsingScsiReservation()).
                thenReturn(new ValidationResult(EngineMessage.ACTION_TYPE_FAILED_VM_USES_SCSI_RESERVATION));

        ValidateTestUtils.runAndAssertValidateFailure(command,
                EngineMessage.ACTION_TYPE_FAILED_VM_USES_SCSI_RESERVATION);
    }

    @Test
    public void testValidationFailsWhenVmIsDuringBackup() {
        doNothing().when(command).logValidationFailed();
        doReturn(true).when(command).isVmDuringBackup();
        ValidateTestUtils.runAndAssertValidateFailure(command,
                EngineMessage.ACTION_TYPE_FAILED_VM_IS_DURING_BACKUP);
    }

    /* How many hosts a cluster needs before a migration within it is allowed */

    /**
     * Taking a host into maintenance evacuates it by running this command, and the scheduler
     * balances by running it too. Both are internal, and a machine on a host that is being taken
     * down has to move whatever the cluster looks like - a pair of hosts is exactly when it has to.
     */
    @Test
    public void theSizeOfTheClusterIsBesideThePointWhenTheEngineAsked() {
        command.setInternalExecution(true);

        assertTrue(command.clusterIsBigEnoughToMigrateWithin());

        verify(command, never()).getClusterMigrationValidator();
    }

    /**
     * A migration may name another cluster to move the machine to. Whether there is anywhere to
     * put it is then a question about that cluster, not about the one it is leaving.
     */
    @Test
    public void theClusterInQuestionIsTheOneTheMachineWouldLandIn() {
        Guid somewhereElse = Guid.newGuid();
        command.getParameters().setTargetClusterId(somewhereElse);

        assertEquals(somewhereElse, command.getClusterMigrationValidator().getClusterId());
    }

    @Test
    public void andTheOneItIsAlreadyInWhenNoOtherIsNamed() {
        command.getVm().setClusterId(aCluster);

        assertEquals(aCluster, command.getClusterMigrationValidator().getClusterId());
    }

    /** And it is the point when a person asked, whether from the screen, the API or the SDK. */
    @Test
    public void andIsThePointWhenAPersonAsked() {
        doReturn(clusterMigrationValidator).when(command).getClusterMigrationValidator();
        when(clusterMigrationValidator.hasEnoughHostsToMigrateWithin()).thenReturn(
                new ValidationResult(EngineMessage.ACTION_TYPE_FAILED_NOT_ENOUGH_HOSTS_FOR_MIGRATION));

        assertFalse(command.clusterIsBigEnoughToMigrateWithin());
        assertTrue(command.getReturnValue().getValidationMessages().contains(
                EngineMessage.ACTION_TYPE_FAILED_NOT_ENOUGH_HOSTS_FOR_MIGRATION.name()));
    }
}
