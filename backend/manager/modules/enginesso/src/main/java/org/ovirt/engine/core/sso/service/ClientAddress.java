package org.ovirt.engine.core.sso.service;

import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.ovirt.engine.core.sso.api.ClientInfo;
import org.ovirt.engine.core.sso.api.SsoConstants;
import org.ovirt.engine.core.sso.api.SsoContext;
import org.ovirt.engine.core.sso.api.SsoSession;
import org.ovirt.engine.core.uutils.crypto.EnvelopePBE;

/**
 * The address of the client a request to the SSO is made for: what the audit records of a login
 * - refused, failed, locked - name as its source.
 *
 * <p>A browser talks to the SSO itself, and its connection is the client's. The REST API does
 * not: a request with a Basic header is authenticated by the engine, which posts the credentials
 * to the SSO from the engine host - so the SSO's connection is the engine's own, and every REST
 * login refused was recorded as coming from the server. The engine now sends the address of the
 * request it is serving as {@code source_addr}, and that is taken as the client's - but only from
 * the engine: the request has to carry the engine's own client id and secret. Anybody else could
 * name any address they liked.</p>
 */
public final class ClientAddress {

    /** Set once the address of a request has been worked out, so it is worked out once. */
    static final String ATTRIBUTE = ClientAddress.class.getName();

    /**
     * An IPv4 or IPv6 literal (with an interface zone), and nothing that could carry anything else
     * - a space, a line break, markup - into a record.
     */
    private static final Pattern ADDRESS = Pattern.compile("^[0-9A-Za-z:.%_-]{2,64}$"); //$NON-NLS-1$

    private ClientAddress() {
    }

    /** @return the address of the client this request is for */
    public static String of(HttpServletRequest request) {
        Object known = request.getAttribute(ATTRIBUTE);
        if (known instanceof String) {
            return (String) known;
        }
        String address = forwardedByEngine(request);
        if (address == null) {
            SsoSession ssoSession = SsoService.getSsoSession(request, false);
            address = ssoSession == null ? null : ssoSession.getSourceAddr();
        }
        if (!isAddress(address)) {
            address = request.getRemoteAddr();
        }
        request.setAttribute(ATTRIBUTE, address);
        return address;
    }

    /**
     * The address of a browser starting an interactive login: its own connection to the SSO.
     *
     * <p>Not the {@code source_addr} the application put in the address it redirected to, which
     * the browser carries and anybody can rewrite; the connection is the same client's, through
     * the same web server, and cannot be.</p>
     */
    public static String ofBrowser(HttpServletRequest request, String named) {
        String connection = request.getRemoteAddr();
        return isAddress(connection) ? connection : named;
    }

    /** @return the address the engine says it is serving, or null when the request is not the engine's */
    static String forwardedByEngine(HttpServletRequest request) {
        String forwarded = request.getParameter(SsoConstants.HTTP_PARAM_SOURCE_ADDR);
        if (!isAddress(forwarded) || !fromEngine(request)) {
            return null;
        }
        return forwarded;
    }

    static boolean isAddress(String address) {
        return address != null && ADDRESS.matcher(address).matches();
    }

    /** Whether the request carries the engine's own client id and secret. */
    static boolean fromEngine(HttpServletRequest request) {
        try {
            String[] idAndSecret = SsoService.getClientIdClientSecretFromHeader(request);
            if (StringUtils.isEmpty(idAndSecret[0])) {
                idAndSecret = new String[] {
                        request.getParameter(SsoConstants.HTTP_PARAM_CLIENT_ID),
                        request.getParameter(SsoConstants.HTTP_PARAM_CLIENT_SECRET) };
            }
            SsoContext ssoContext = SsoService.getSsoContext(request);
            String engineClient = ssoContext.getSsoLocalConfig().getProperty("ENGINE_SSO_CLIENT_ID"); //$NON-NLS-1$
            if (StringUtils.isEmpty(idAndSecret[1]) || !StringUtils.equals(engineClient, idAndSecret[0])) {
                return false;
            }
            ClientInfo clientInfo = ssoContext.getClienInfo(engineClient);
            return clientInfo != null && EnvelopePBE.check(clientInfo.getClientSecret(), idAndSecret[1]);
        } catch (Exception e) {
            return false;
        }
    }
}
