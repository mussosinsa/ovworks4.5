package org.ovirt.engine.core.aaa;

import javax.servlet.http.HttpServletRequest;

import org.ovirt.engine.core.uutils.security.ClientSerialCheck;
import org.ovirt.engine.core.uutils.security.ClientSerialCheck.Refusal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Decides whether a request came from a registered terminal, and records it in the audit log when
 * it did not.
 *
 * <p>For the parts of the engine outside the SSO: the welcome page and the REST API. They refused
 * such a request with a warning in the engine log and nothing in the audit log, so an engine being
 * probed from an unregistered machine left no event behind. At most one event a minute is written
 * per source, place and reason - nobody has to log in to be refused, so anyone could otherwise fill
 * the event table with it - while the engine log has a line for every refusal.</p>
 */
public final class TerminalAccessAudit {

    private static final Logger log = LoggerFactory.getLogger(TerminalAccessAudit.class);

    private TerminalAccessAudit() {
    }

    /** @return why the request is refused, already recorded; null when it may go on */
    public static Refusal check(HttpServletRequest request) {
        Refusal refusal = ClientSerialCheck.check(request.getHeader(ClientSerialCheck.HEADER));
        if (refusal != null) {
            report(request, refusal);
        }
        return refusal;
    }

    /** Records a refusal. Never fails: the request is refused either way. */
    static void report(HttpServletRequest request, Refusal refusal) {
        try {
            String source = request.getRemoteAddr();
            String path = request.getRequestURI();
            String description = ClientSerialCheck.describe(path, refusal);
            log.warn("CLIENT_SERIAL_REJECTED sourceIp={} {}", source, description);
            if (ClientSerialCheck.shouldReport(source, path, refusal)) {
                SsoOAuthServiceUtils.reportAuditEvent(ClientSerialCheck.AUDIT_LOG_TYPE, source, description);
            }
        } catch (Exception exception) {
            log.error("Unable to record the refused terminal in the audit log: {}", exception.getMessage());
            log.debug("Exception", exception);
        }
    }
}
