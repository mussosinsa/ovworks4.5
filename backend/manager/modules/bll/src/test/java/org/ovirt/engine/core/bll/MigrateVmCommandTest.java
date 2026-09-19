package org.ovirt.engine.core.bll;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.ovirt.engine.core.bll.validator.VmValidator;
import org.ovirt.engine.core.common.action.MigrateVmParameters;
import org.ovirt.engine.core.common.businessentities.VM;
import org.ovirt.engine.core.common.errors.EngineMessage;
import org.ovirt.engine.core.compat.Guid;

@ExtendWith(MockitoExtension.class)
public class MigrateVmCommandTest {

    private Guid vmId = Guid.newGuid();

    @Mock
    VmValidator vmValidator;

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

    /* How many hosts a cluster needs before migration within it is offered */

    @Test
    public void aClusterOfTwoIsNotOfferedAMigration() {
        // What was asked for: two hosts or fewer, and the action is not offered. Two can move a
        // VM between them and nothing else here refuses it, so this is a decision about how the
        // estate is run - and it is one setting away from being the other decision.
        int minimum = 3;

        assertAll(
                () -> assertFalse(MigrateVmCommand.enoughHosts(minimum, 0)),
                () -> assertFalse(MigrateVmCommand.enoughHosts(minimum, 1)),
                () -> assertFalse(MigrateVmCommand.enoughHosts(minimum, 2)),
                () -> assertTrue(MigrateVmCommand.enoughHosts(minimum, 3)),
                () -> assertTrue(MigrateVmCommand.enoughHosts(minimum, 9)));
    }

    @Test
    public void aPairIsPutBackByTheSetting() {
        assertAll(
                () -> assertFalse(MigrateVmCommand.enoughHosts(2, 1)),
                () -> assertTrue(MigrateVmCommand.enoughHosts(2, 2)));
    }

    @Test
    public void oneOrLessIsNoRuleAtAll() {
        // Not a rule that always passes: an installation wanting the engine's own judgement back
        // sets it here, and a cluster of none is a cluster this command has nothing to say about.
        assertAll(
                () -> assertTrue(MigrateVmCommand.enoughHosts(1, 0)),
                () -> assertTrue(MigrateVmCommand.enoughHosts(0, 0)),
                () -> assertTrue(MigrateVmCommand.enoughHosts(-1, 0)));
    }
}
