package org.ovirt.engine.core.sso.service;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.ovirt.engine.core.sso.api.SsoContext;
import org.ovirt.engine.core.sso.service.LoginReplayGuard.LoginEnvelopeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Records a login refused because its credentials were a copy of an earlier login's.
 *
 * <p>The refusal happens before the credentials are ever checked, so none of the paths that record
 * a failed login is reached: the client was told "login failed", the engine log had a warning, and
 * the audit log had nothing - a replay attempt, which is exactly what an audit trail is for, left
 * no trace in it. It is sent to the engine the way a failed login is, under an event type of its
 * own so that it is not read as a wrong password. It does not count towards locking the account:
 * whoever holds a copy of a request could otherwise lock its owner out by sending it again.</p>
 */
public final class LoginReplayAudit {

    /** The engine event this is recorded as; the engine accepts it by this name. */
    public static final String AUDIT_LOG_TYPE = "USER_VDC_LOGIN_REPLAY_BLOCKED"; //$NON-NLS-1$

    /** Where the refused credentials were presented. */
    public enum Channel {
        /** The SSO token endpoint a REST client or application logs in through. */
        API,
        /** The login page in a browser. */
        LOGIN_PAGE
    }

    private static final Logger log = LoggerFactory.getLogger(LoginReplayAudit.class);

    private LoginReplayAudit() {
    }

    /**
     * Sends the refusal to the engine's audit log. A failure to send is logged and swallowed: the
     * login has been refused either way, and recording it must not change that.
     *
     * @param userName the user the credentials name, or null when not even that could be read
     */
    public static void report(
            SsoContext ssoContext,
            HttpServletRequest request,
            String userName,
            Channel channel,
            LoginEnvelopeException refusal) {
        String sourceAddress = AuthenticationService.resolveSourceAddress(request);
        String message = describe(userName, sourceAddress, channel, refusal);
        log.warn(message);
        try {
            SsoService.notifyClientOfAuditLogEvent(
                    ssoContext,
                    sourceAddress,
                    ssoContext.getSsoLocalConfig().getProperty("ENGINE_SSO_CLIENT_ID"), //$NON-NLS-1$
                    StringUtils.defaultIfEmpty(userName, "N/A"), //$NON-NLS-1$
                    message,
                    AUDIT_LOG_TYPE);
        } catch (Exception exception) {
            log.error("Unable to record the refused login replay in the audit log", exception);
        }
    }

    static String describe(String userName, String sourceAddress, Channel channel, LoginEnvelopeException refusal) {
        return String.format(
                "LOGIN_REPLAY_BLOCKED user=%s sourceIp=%s channel=%s reason=%s",
                StringUtils.defaultIfEmpty(userName, "N/A"), //$NON-NLS-1$
                sourceAddress,
                channel,
                refusal.getReason());
    }
}
