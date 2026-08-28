package org.ovirt.engine.core.bll;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import javax.inject.Inject;

import org.apache.commons.lang.StringUtils;
import org.ovirt.engine.core.bll.context.CommandContext;
import org.ovirt.engine.core.bll.utils.EngineSSHClient;
import org.ovirt.engine.core.common.action.ExecuteVmGuestCommandParameters;
import org.ovirt.engine.core.common.businessentities.VDS;
import org.ovirt.engine.core.common.errors.EngineMessage;
import org.ovirt.engine.core.dao.VdsDao;
import org.ovirt.engine.core.utils.JsonHelper;

/** Executes a Windows batch file on the VM's current VDSM host and returns guest-exec output. */
public class ExecuteVmGuestCommandCommand<T extends ExecuteVmGuestCommandParameters>
        extends VmOperationCommandBase<T> {
    private static final int POLL_ATTEMPTS = 60;
    private static final long POLL_INTERVAL_MILLIS = 1000;

    @Inject
    private VdsDao vdsDao;

    public ExecuteVmGuestCommandCommand(T parameters, CommandContext commandContext) {
        super(parameters, commandContext);
    }

    @Override
    protected boolean validate() {
        if (getVm() == null) {
            return failValidation(EngineMessage.ACTION_TYPE_FAILED_VM_NOT_FOUND);
        }
        if (!getVm().isRunning() || getVm().getRunOnVds() == null) {
            return failVmStatusIllegal();
        }
        String path = getParameters().getPath();
        if (StringUtils.isBlank(path) || !path.matches("(?i)^[a-z]:\\\\[^\\r\\n'\"]+\\.bat$")) {
            return failValidation(EngineMessage.ACTION_TYPE_FAILED_INVALID_CUSTOM_PROPERTIES_INVALID_SYNTAX);
        }
        return true;
    }

    @Override
    protected void perform() {
        VDS host = vdsDao.get(getVm().getRunOnVds());
        if (host == null) {
            setSucceeded(false);
            return;
        }
        try (EngineSSHClient ssh = new EngineSSHClient()) {
            ssh.setVds(host);
            ssh.useDefaultKeyPair();
            ssh.connect();
            ssh.authenticate();

            String request = "{\"execute\":\"guest-exec\",\"arguments\":{\"path\":\""
                    + jsonEscape(getParameters().getPath())
                    + "\",\"args\":[],\"capture-output\":true}}";
            Map<String, Object> start = execute(ssh, request);
            Object pid = ((Map<?, ?>) start.get("return")).get("pid");
            if (pid == null) {
                throw new IllegalStateException("QEMU guest agent did not return a process id");
            }

            for (int attempt = 0; attempt < POLL_ATTEMPTS; attempt++) {
                Map<String, Object> status = execute(ssh,
                        "{\"execute\":\"guest-exec-status\",\"arguments\":{\"pid\":" + pid + "}}");
                Map<?, ?> result = (Map<?, ?>) status.get("return");
                if (Boolean.TRUE.equals(result.get("exited"))) {
                    String output = decode(result.get("out-data"));
                    String error = decode(result.get("err-data"));
                    String value = "exit-code=" + result.get("exitcode") + "\nstdout:\n" + output
                            + (error.isEmpty() ? "" : "\nstderr:\n" + error);
                    getReturnValue().setActionReturnValue(value);
                    setSucceeded(((Number) result.get("exitcode")).intValue() == 0);
                    return;
                }
                Thread.sleep(POLL_INTERVAL_MILLIS);
            }
            throw new IllegalStateException("Timed out waiting for guest command result");
        } catch (Exception e) {
            log.error("Failed to execute guest command on VM '{}' through host '{}': {}",
                    getVm().getName(), getVm().getRunOnVdsName(), e.getMessage());
            getReturnValue().getExecuteFailedMessages().add(e.getMessage());
            setSucceeded(false);
        }
    }

    private Map<String, Object> execute(EngineSSHClient ssh, String request) throws Exception {
        try (ByteArrayOutputStream out = new ByteArrayOutputStream();
                ByteArrayOutputStream err = new ByteArrayOutputStream()) {
            String command = "virsh qemu-agent-command " + shellQuote(getVm().getName())
                    + " --command " + shellQuote(request);
            ssh.executeCommand(command, null, out, err);
            String response = out.toString(StandardCharsets.UTF_8.name()).trim();
            if (response.isEmpty()) {
                throw new IllegalStateException(err.toString(StandardCharsets.UTF_8.name()).trim());
            }
            return JsonHelper.jsonToMap(response);
        }
    }

    static String shellQuote(String value) {
        return "'" + value.replace("'", "'\\\"'\\\"'") + "'";
    }

    private static String jsonEscape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static String decode(Object value) {
        return value == null ? "" : new String(Base64.getDecoder().decode(value.toString()), StandardCharsets.UTF_8);
    }
}
