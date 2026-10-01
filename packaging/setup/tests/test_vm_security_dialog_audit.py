import re
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
COMMAND = (
    'backend/manager/modules/bll/src/main/java'
    '/org/ovirt/engine/core/bll/ExecuteVmGuestCommandCommand.java'
)
TYPES = 'backend/manager/modules/common/src/main/java/org/ovirt/engine/core/common/AuditLogType.java'
MESSAGES = 'backend/manager/modules/dal/src/main/resources/bundles/AuditLogMessages.properties'

DIALOG_EVENTS = (
    'VM_GUEST_NETWORK_SETTINGS_APPLIED',
    'VM_GUEST_NETWORK_SETTINGS_FAILED',
    'VM_GUEST_FILE_SHARING_POLICY_APPLIED',
    'VM_GUEST_FILE_SHARING_POLICY_FAILED',
    'VM_GUEST_COMMAND_BLOCKED',
    'VM_GUEST_COMMAND_UNBLOCKED',
    'VM_GUEST_COMMAND_BLOCK_FAILED',
    'VM_GUEST_COMMAND_UNBLOCK_FAILED',
    'VM_GUEST_EVENTS_VIEWED',
    'VM_GUEST_EVENTS_VIEW_FAILED',
    'VM_GUEST_SCRIPT_EXECUTED',
    'VM_GUEST_SCRIPT_EXECUTION_FAILED',
)


def read(relative):
    return (ROOT / relative).read_text(encoding='utf-8')


class VmSecurityDialogAuditTest(unittest.TestCase):
    def test_every_event_has_a_type_and_a_message(self):
        types = read(TYPES)
        messages = read(MESSAGES)

        for event in DIALOG_EVENTS:
            self.assertRegex(types, r'\b' + event + r'\(\d+')
            self.assertIn(event + '=', messages)

    def test_the_failures_are_recorded_as_failures(self):
        types = read(TYPES)

        for event in DIALOG_EVENTS:
            if not event.endswith('FAILED'):
                continue
            declaration = re.search(r'\b' + event + r'\([^)]*\)', types).group(0)
            self.assertIn('AuditLogSeverity.ERROR', declaration, event)

    def test_the_command_decides_which_of_them_to_record(self):
        command = read(COMMAND)

        self.assertIn('public AuditLogType getAuditLogTypeValue()', command)
        for event in DIALOG_EVENTS:
            self.assertIn('AuditLogType.' + event, command)

    def test_the_collectors_own_polling_is_not_recorded(self):
        command = read(COMMAND)

        # It runs against every Windows VM every few minutes; an event for each poll would
        # bury the guest events it exists to write.
        polling = command.index('getCriticalEventsRequested()', command.index('auditLogTypeOf'))
        self.assertIn('AuditLogType.UNASSIGNED', command[polling:polling + 200])

    def test_what_was_asked_for_is_recorded_even_when_the_guest_never_answered(self):
        command = read(COMMAND)

        # Described where the command is built, not where it is carried out: a request that
        # never reached the guest is still worth an event saying what was attempted.
        self.assertLess(command.index('describeRequest();'), command.index('protected boolean validate()'))

    def test_a_block_and_its_release_name_what_they_covered(self):
        messages = read(MESSAGES)
        command = read(COMMAND)

        for event in ('VM_GUEST_COMMAND_BLOCKED', 'VM_GUEST_COMMAND_UNBLOCKED',
                      'VM_GUEST_COMMAND_BLOCK_FAILED', 'VM_GUEST_COMMAND_UNBLOCK_FAILED'):
            line = re.search(r'^' + event + r'=.*$', messages, re.M).group(0)
            self.assertIn('${GuestTargets}', line)
            self.assertIn('${UserName}', line)
        # Every menu of the whitelist tab says what it blocked, the user writable folders too.
        self.assertEqual(3, command.count('addCustomValue("GuestTargets"'))
        self.assertIn('getUserPathExecutionBlocked()', command[command.index('auditLogTypeOf('):])

    def test_lifting_a_block_is_a_warning(self):
        types = read(TYPES)

        self.assertRegex(types, r'VM_GUEST_COMMAND_UNBLOCKED\(\d+, AuditLogSeverity\.WARNING\)')
        self.assertRegex(types, r'VM_GUEST_COMMAND_BLOCKED\(\d+\)')


if __name__ == '__main__':
    unittest.main()
