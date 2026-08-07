package org.ovirt.engine.core.bll;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.ovirt.engine.core.bll.context.CommandContext;
import org.ovirt.engine.core.bll.utils.PermissionSubject;
import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.VdcObjectType;
import org.ovirt.engine.core.common.action.ActionParametersBase;
import org.ovirt.engine.core.common.businessentities.ActionGroup;
import org.ovirt.engine.core.compat.Guid;

public class ListEngineConfigPropertiesCommand<T extends ActionParametersBase> extends CommandBase<T> {

    private static final String[] PROPERTIES_CANDIDATES = {
            "/usr/share/ovirt-engine/dbscripts/engine-config.properties", //$NON-NLS-1$
            "/usr/share/ovirt-engine/engine-config.properties", //$NON-NLS-1$
            "/etc/ovirt-engine/engine-config.properties", //$NON-NLS-1$
            "/etc/ovirt-engine/engine-config/engine-config.properties" //$NON-NLS-1$
    };

    public ListEngineConfigPropertiesCommand(T parameters, CommandContext cmdContext) {
        super(parameters, cmdContext);
    }

    @Override
    protected boolean validate() {
        return true;
    }

    @Override
    protected void executeCommand() {
        try {
            File propertiesFile = resolvePropertiesFile();
            if (propertiesFile == null) {
                getReturnValue().getExecuteFailedMessages()
                        .add("engine-config.properties 파일을 찾을 수 없습니다."); //$NON-NLS-1$
                setSucceeded(false);
                return;
            }

            List<String> entries = new ArrayList<>();
            try (BufferedReader reader = new BufferedReader(new FileReader(propertiesFile))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String trimmed = line.trim();
                    if (trimmed.isEmpty() || trimmed.startsWith("#")) { //$NON-NLS-1$
                        continue;
                    }
                    int idx = trimmed.indexOf(".description="); //$NON-NLS-1$
                    if (idx <= 0) {
                        continue;
                    }
                    String name = trimmed.substring(0, idx);
                    String description = trimmed.substring(idx + ".description=".length())
                            .replaceAll("^\"|\"$", ""); //$NON-NLS-1$ //$NON-NLS-2$
                    entries.add(name + "\t" + description); //$NON-NLS-1$
                }
            }

            Collections.sort(entries, String.CASE_INSENSITIVE_ORDER);
            getReturnValue().setActionReturnValue(entries);
            setSucceeded(true);
        } catch (Exception e) {
            log.error("Failed to list engine-config properties", e); //$NON-NLS-1$
            getReturnValue().getExecuteFailedMessages().add(e.getMessage());
            setSucceeded(false);
        }
    }

    private File resolvePropertiesFile() {
        for (String path : PROPERTIES_CANDIDATES) {
            File f = new File(path);
            if (f.exists() && f.isFile()) {
                return f;
            }
        }
        return null;
    }


    @Override
    public List<PermissionSubject> getPermissionCheckSubjects() {
        return Collections.singletonList(new PermissionSubject(Guid.SYSTEM, VdcObjectType.System,
                ActionGroup.CONFIGURE_ENGINE));
    }

    @Override
    public AuditLogType getAuditLogTypeValue() {
        return AuditLogType.UNASSIGNED;
    }
}
