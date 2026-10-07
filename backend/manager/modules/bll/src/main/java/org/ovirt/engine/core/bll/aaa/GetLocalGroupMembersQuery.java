package org.ovirt.engine.core.bll.aaa;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.ovirt.engine.core.bll.QueriesCommandBase;
import org.ovirt.engine.core.bll.context.EngineContext;
import org.ovirt.engine.core.common.queries.NameQueryParameters;

/**
 * The users in a group of the internal authorization provider, by name, as the provider's own
 * tool ({@code ovirt-aaa-jdbc-tool group-manage show}) lists them.
 *
 * <p>Fails, saying what the tool said, when the group is not one the tool knows - an empty list
 * would read as a group with no members.</p>
 */
public class GetLocalGroupMembersQuery<P extends NameQueryParameters> extends QueriesCommandBase<P> {

    /** {@code   User: user01} on a line of its own; the tool lists member groups as {@code Group:}. */
    private static final Pattern MEMBER_USER = Pattern.compile("(?m)^\\s*User:\\s*(\\S+)\\s*$"); //$NON-NLS-1$

    public GetLocalGroupMembersQuery(P parameters, EngineContext engineContext) {
        super(parameters, engineContext);
    }

    @Override
    protected void executeQueryCommand() {
        String group = getParameters().getName() == null ? "" : getParameters().getName().trim(); //$NON-NLS-1$
        if (!group.matches(UpdateLocalGroupMembersCommand.NAME_PATTERN)) {
            getQueryReturnValue().setSucceeded(false);
            getQueryReturnValue().setExceptionString("Invalid group name: " + group); //$NON-NLS-1$
            return;
        }
        try {
            Result result = run("group-manage", "show", group); //$NON-NLS-1$ //$NON-NLS-2$
            if (result.exitCode != 0) {
                getQueryReturnValue().setSucceeded(false);
                getQueryReturnValue().setExceptionString(result.output);
                return;
            }
            getQueryReturnValue().setReturnValue(membersIn(result.output));
        } catch (Exception e) {
            log.error("그룹 구성원 조회 실패; group='{}'; error='{}'", group, e.getMessage());
            getQueryReturnValue().setSucceeded(false);
            getQueryReturnValue().setExceptionString(e.getMessage());
        }
    }

    /** @return the user names the tool listed, in its order */
    static ArrayList<String> membersIn(String output) {
        ArrayList<String> users = new ArrayList<>();
        if (output == null) {
            return users;
        }
        Matcher matcher = MEMBER_USER.matcher(output);
        while (matcher.find()) {
            users.add(matcher.group(1));
        }
        return users;
    }

    protected Result run(String... arguments) throws Exception {
        List<String> command = new ArrayList<>();
        command.add("ovirt-aaa-jdbc-tool"); //$NON-NLS-1$
        for (String argument : arguments) {
            command.add(argument);
        }
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append('\n');
            }
        }
        return new Result(process.waitFor(), output.toString().trim());
    }

    protected static class Result {
        protected final int exitCode;
        protected final String output;

        protected Result(int exitCode, String output) {
            this.exitCode = exitCode;
            this.output = output;
        }
    }
}
