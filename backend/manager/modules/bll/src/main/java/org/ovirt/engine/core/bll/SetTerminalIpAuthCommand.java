/*
 * Copyright 새올정보기술 (OV-Works), 2026
 * SPDX-License-Identifier: Apache-2.0
 */
package org.ovirt.engine.core.bll;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import javax.inject.Inject;

import org.ovirt.engine.core.bll.context.CommandContext;
import org.ovirt.engine.core.bll.utils.PermissionSubject;
import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.VdcObjectType;
import org.ovirt.engine.core.common.action.TerminalIpAuthParameters;
import org.ovirt.engine.core.dao.RoleDao;
import org.ovirt.engine.core.dao.UserProfileDao;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@NonTransactiveCommandAttribute
public class SetTerminalIpAuthCommand extends CommandBase<TerminalIpAuthParameters> {

    private static final Logger log = LoggerFactory.getLogger(SetTerminalIpAuthCommand.class);

    /**
     * What this write registers and removes, worked out before it is made so that a write that
     * fails is recorded as the registration, change or removal that was refused.
     */
    private TerminalIpChange change = TerminalIpChange.between(null, null);

    @Inject
    private UserProfileDao userProfileDao;

    @Inject
    private RoleDao roleDao;

    public SetTerminalIpAuthCommand(TerminalIpAuthParameters parameters, CommandContext cmdContext) {
        super(parameters, cmdContext);
    }

    @Override
    protected void executeCommand() {
        // The screen does not show the dedicated login addresses of users who are not
        // administrators, so the list it sends lacks them: they are compared against what the
        // screen showed and kept on the web server.
        Set<String> dedicated = SetUserDedicatedIpCommand.addressesHiddenFromTerminalScreen(
                userProfileDao.getAllByName(SetUserDedicatedIpCommand.DEDICATED_LOGIN_IP_PROPERTY),
                userId -> !roleDao.getAnyAdminRoleForUserAndGroups(userId, "").isEmpty()); //$NON-NLS-1$
        try {
            change = TerminalIpChange.between(TerminalIpConfigUtils.readVisibleRequireIp(dedicated),
                    getParameters().getIpAddress());
        } catch (IOException | RuntimeException ex) {
            // Only the record loses detail; the write below reads the file again and reports its own
            // failure.
            log.warn("Unable to read the registered terminal IP addresses: {}", ex.getMessage()); //$NON-NLS-1$
        }
        addChangeValues();
        try {
            if (TerminalIpConfigUtils.updateVisibleRequireIp(getParameters().getIpAddress(), dedicated)) {
                applyToWebServer();
            }
            addCustomValue("CustomData", change.describe()); //$NON-NLS-1$
            setSucceeded(true);
        } catch (IOException ex) {
            log.error("Failed to update terminal IP auth config", ex); //$NON-NLS-1$
            getReturnValue().getExecuteFailedMessages().add(ex.getMessage());
            addCustomValue("CustomData", ex.getMessage()); //$NON-NLS-1$
            setSucceeded(false);
        }
    }

    /**
     * Has the web server apply the list now, without a restart. The list is already written, so a
     * reload that fails is reported but does not undo it: the next reload or restart applies it.
     */
    private void applyToWebServer() {
        try {
            TerminalIpConfigUtils.reloadWebServerGracefully();
        } catch (IOException ex) {
            log.error("Terminal IP list written but the web server could not reload it: {}", //$NON-NLS-1$
                    ex.getMessage());
            log.debug("Exception", ex); //$NON-NLS-1$
        }
    }

    /**
     * The addresses the record names. Set whatever the outcome, and never left empty: an empty
     * value is printed as {@code <UNKNOWN>} in the event list.
     */
    private void addChangeValues() {
        List<String> added = change.getAdded();
        List<String> removed = change.getRemoved();
        String none = "-"; //$NON-NLS-1$
        switch (change.getKind()) {
        case CHANGED:
            addCustomValue("TerminalIp", added.get(0)); //$NON-NLS-1$
            addCustomValue("OldTerminalIp", removed.get(0)); //$NON-NLS-1$
            break;
        case ADDED:
            addCustomValue("TerminalIp", String.join(", ", added)); //$NON-NLS-1$ //$NON-NLS-2$
            addCustomValue("OldTerminalIp", none); //$NON-NLS-1$
            break;
        case REMOVED:
            addCustomValue("TerminalIp", String.join(", ", removed)); //$NON-NLS-1$ //$NON-NLS-2$
            addCustomValue("OldTerminalIp", none); //$NON-NLS-1$
            break;
        default:
            addCustomValue("TerminalIp", none); //$NON-NLS-1$
            addCustomValue("OldTerminalIp", none); //$NON-NLS-1$
            break;
        }
    }

    @Override
    public List<PermissionSubject> getPermissionCheckSubjects() {
        return Collections.singletonList(new PermissionSubject(MultiLevelAdministrationHandler.SYSTEM_OBJECT_ID,
                VdcObjectType.System,
                getActionType().getActionGroup()));
    }

    @Override
    public AuditLogType getAuditLogTypeValue() {
        return auditLogTypeOf(change.getKind(), getSucceeded());
    }

    /** Registration, change and removal each have their own record, and so does each failure. */
    static AuditLogType auditLogTypeOf(TerminalIpChange.Kind kind, boolean succeeded) {
        switch (kind) {
        case ADDED:
            return succeeded ? AuditLogType.TERMINAL_IP_AUTH_ADDED : AuditLogType.TERMINAL_IP_AUTH_ADD_FAILED;
        case CHANGED:
            return succeeded ? AuditLogType.TERMINAL_IP_AUTH_CHANGED : AuditLogType.TERMINAL_IP_AUTH_CHANGE_FAILED;
        case REMOVED:
            return succeeded ? AuditLogType.TERMINAL_IP_AUTH_REMOVED : AuditLogType.TERMINAL_IP_AUTH_REMOVE_FAILED;
        default:
            return succeeded
                    ? AuditLogType.TERMINAL_IP_AUTH_CONFIG_UPDATED
                    : AuditLogType.TERMINAL_IP_AUTH_CONFIG_UPDATE_FAILED;
        }
    }
}
