package org.ovirt.engine.core.sso.service;

import javax.servlet.http.HttpServletRequest;

import org.ovirt.engine.core.sso.api.ClientSerialRejectedException;
import org.ovirt.engine.core.sso.api.SsoContext;
import org.ovirt.engine.core.uutils.security.ClientSerialCheck;
import org.ovirt.engine.core.uutils.security.ClientSerialCheck.Refusal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Turns away a request that did not come from a registered terminal, and records that it did.
 *
 * <p>Refusing was already done in places; recording was done nowhere, so the audit log of an
 * engine being probed from an unregistered machine was empty. It is sent to the engine the way a
 * failed login is, under an event of its own, and at most once a minute per source, place and
 * reason: nobody has to log in to be refused, so anyone could otherwise fill the event table with
 * it. Engine log lines are written for every refusal.</p>
 */
public final class ClientSerialAudit {

    private static final Logger log = LoggerFactory.getLogger(ClientSerialAudit.class);

    private ClientSerialAudit() {
    }

    /**
     * Lets the request go on, or records and throws why it may not.
     *
     * @throws ClientSerialRejectedException when the request did not come from a registered terminal
     */
    public static void require(HttpServletRequest request) {
        Refusal refusal = ClientSerialCheck.check(request.getHeader(ClientSerialCheck.HEADER));
        if (refusal != null) {
            if (fromThisHost(request)) {
                return;
            }
            report(request, refusal);
            throw new ClientSerialRejectedException(refusal);
        }
    }

    /**
     * Whether the request comes from the engine host itself, which is not a terminal and is let
     * through without one's serial (see {@link ClientSerialCheck#isThisHost}).
     *
     * <p>Judged by the address the request is for: the connection's, or - for a REST API login
     * the engine passes on - the address of the client the engine is serving, which it names only
     * with its own client secret. So a remote client's login does not become the engine's own
     * because the engine forwarded it.</p>
     */
    static boolean fromThisHost(HttpServletRequest request) {
        try {
            String source = ClientAddress.of(request);
            if (ClientSerialCheck.isThisHost(source)) {
                log.info("X-Client-Serial not required: request from the engine host itself; sourceIp={} path={}",
                        source, request.getRequestURI());
                return true;
            }
        } catch (Exception exception) {
            log.debug("Unable to tell whether the request comes from the engine host", exception);
        }
        return false;
    }

    /**
     * Records a refusal. Never fails: the request has been refused either way, and recording it
     * must not change that.
     */
    public static void report(HttpServletRequest request, Refusal refusal) {
        try {
            // The terminal's address, also when the engine is asking on its behalf (REST API).
            String source = ClientAddress.of(request);
            String path = request.getRequestURI();
            String description = ClientSerialCheck.describe(path, refusal);
            log.warn("CLIENT_SERIAL_REJECTED sourceIp={} {}", source, description);
            if (ClientSerialCheck.shouldReport(source, path, refusal)) {
                SsoContext ssoContext = SsoService.getSsoContext(request);
                SsoService.notifyClientOfAuditLogEvent(
                        ssoContext,
                        source,
                        ssoContext.getSsoLocalConfig().getProperty("ENGINE_SSO_CLIENT_ID"), //$NON-NLS-1$
                        "N/A", //$NON-NLS-1$
                        description,
                        ClientSerialCheck.AUDIT_LOG_TYPE);
            }
        } catch (Exception exception) {
            log.error("Unable to record the refused terminal in the audit log: {}", exception.getMessage());
            log.debug("Exception", exception);
        }
    }
}
