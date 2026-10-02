package org.ovirt.engine.core.sso.service;

import java.util.Optional;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.ovirt.engine.core.sso.api.SsoContext;
import org.ovirt.engine.core.uutils.security.LoginInputPolicy;
import org.ovirt.engine.core.uutils.security.LoginInputPolicy.Refusal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Turns away a login whose ID or password {@link LoginInputPolicy} does not allow, and records it.
 *
 * <p>The login page refuses such input as it is typed; this is the same check on the server, for
 * a request that did not come from the page. The credentials are never handed to an extension,
 * so the refusal neither counts towards locking the account nor reaches any path that records a
 * failed login - which is why it is sent to the engine's audit log here, under an event type of
 * its own.</p>
 *
 * <p>What was typed is never recorded: a password, obviously, and not a refused ID either, which
 * is attacker supplied text. The field and the reason are.</p>
 */
public final class LoginInputAudit {

    /** The engine event this is recorded as; the engine accepts it by this name. */
    public static final String AUDIT_LOG_TYPE = "USER_VDC_LOGIN_INPUT_REJECTED"; //$NON-NLS-1$

    private static final Logger log = LoggerFactory.getLogger(LoginInputAudit.class);

    private LoginInputAudit() {
    }

    /**
     * Checks the ID and the password, and records a refusal.
     *
     * @return the refusal, or empty when the login may go on to be checked
     */
    public static Optional<Refusal> check(
            SsoContext ssoContext,
            HttpServletRequest request,
            String userName,
            String password,
            LoginReplayAudit.Channel channel) {
        Optional<Refusal> refusal = LoginInputPolicy.check(userName, password);
        refusal.ifPresent(r -> report(ssoContext, request, recordedUserName(userName, r), channel, r));
        return refusal;
    }

    /** The ID as it may be recorded: not at all when it is the field that was refused. */
    public static String recordedUserName(String userName, Refusal refusal) {
        return refusal.getField() == LoginInputPolicy.Field.USER_NAME || StringUtils.isEmpty(userName)
                ? "N/A" //$NON-NLS-1$
                : userName;
    }

    private static void report(
            SsoContext ssoContext,
            HttpServletRequest request,
            String userName,
            LoginReplayAudit.Channel channel,
            Refusal refusal) {
        String sourceAddress = AuthenticationService.resolveSourceAddress(request);
        String message = describe(userName, sourceAddress, channel, refusal);
        log.warn(message);
        try {
            SsoService.notifyClientOfAuditLogEvent(
                    ssoContext,
                    sourceAddress,
                    ssoContext.getSsoLocalConfig().getProperty("ENGINE_SSO_CLIENT_ID"), //$NON-NLS-1$
                    userName,
                    message,
                    AUDIT_LOG_TYPE);
        } catch (Exception exception) {
            log.error("Unable to record the refused login input in the audit log", exception);
        }
    }

    static String describe(String userName, String sourceAddress, LoginReplayAudit.Channel channel, Refusal refusal) {
        return String.format(
                "LOGIN_INPUT_REJECTED user=%s sourceIp=%s channel=%s field=%s reason=%s",
                userName,
                sourceAddress,
                channel,
                refusal.getField(),
                refusal.getProblem());
    }
}
