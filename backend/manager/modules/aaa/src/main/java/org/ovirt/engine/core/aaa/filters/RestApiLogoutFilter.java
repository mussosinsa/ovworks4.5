package org.ovirt.engine.core.aaa.filters;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.ovirt.engine.core.common.constants.SessionConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Ends the session a REST API client holds, on request.
 *
 * <p>Until this existed there was no way for a client to say it was done. The API keeps a session
 * for a request that carries {@code Prefer: persistent-auth} and ends it for one that does not, so
 * the obvious move was to send a last request without that header - but it does not work. The
 * filter that acts on its absence, {@link RestApiSessionValidationFilter}, runs at the start of
 * the request and only drops the HTTP session; by the time anything could end the engine session
 * the request has been authenticated afresh and holds a different one, and that is the session
 * that gets ended. The session the client meant to close stays open until it times out.</p>
 *
 * <p>So logging out is its own request, {@code POST /ovirt-engine/api/logout}, answered here. The
 * filter is mapped ahead of the ones that would re-authenticate the request, and it does not pass
 * the request on: nothing else runs, no new session is created, and one logout leaves one entry in
 * the audit log rather than a login and two logouts.</p>
 *
 * <p>The session cookie is what authorises this. Holding it is what it means to be in the session,
 * and ending the session you are in needs nothing further; no credentials are asked for, and none
 * would let a caller end anybody else's session. The reply is the same whether or not a session
 * was found, so it says nothing about whether a cookie is still good.</p>
 *
 * <p>Cross site request forgery is left to the mechanism the rest of the API uses: this filter is
 * mapped after {@code CSRFProtectionFilter}, so a client that asked for that protection keeps it
 * here too, and a client that did not is no more exposed on this request than on any other. What a
 * forged logout costs is the session, which the user can simply open again.</p>
 */
public class RestApiLogoutFilter implements Filter {

    private static final Logger log = LoggerFactory.getLogger(RestApiLogoutFilter.class);

    /** Path of the logout resource, below the context root of the REST API webapp. */
    private static final String LOGOUT_PATH = "/logout";

    private static final String POST = "POST";

    @Override
    public void init(FilterConfig filterConfig) {
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;

        if (!isLogoutRequest(req)) {
            chain.doFilter(request, response);
            return;
        }

        HttpServletResponse res = (HttpServletResponse) response;

        // Logging out changes what the server holds, so it is not something a link or an image can
        // be made to do.
        if (!POST.equalsIgnoreCase(req.getMethod())) {
            res.setHeader("Allow", POST);
            res.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
            return;
        }

        HttpSession session = req.getSession(false);
        String engineSessionId = session == null
                ? null
                : (String) session.getAttribute(SessionConstants.HTTP_SESSION_ENGINE_SESSION_ID_KEY);

        FiltersHelper.logoutEngineSession(engineSessionId);

        if (session != null) {
            try {
                session.invalidate();
            } catch (IllegalStateException e) {
                // already invalid, which is the state we were after
            }
        }

        log.debug("REST API logout, session ended: {}", engineSessionId != null);

        // The same answer whether a session was ended or there was none to end, so that logging out
        // twice is not an error and the reply reports nothing about the cookie that was presented.
        res.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    /**
     * @return true when the request is addressed to the logout resource itself. The request URI is
     *         compared rather than the servlet path, because everything in this webapp is mapped to
     *         one servlet and the servlet path is therefore not the part that identifies it.
     */
    private boolean isLogoutRequest(HttpServletRequest req) {
        String uri = req.getRequestURI();
        if (uri == null) {
            return false;
        }
        if (uri.length() > 1 && uri.endsWith("/")) {
            uri = uri.substring(0, uri.length() - 1);
        }
        return (req.getContextPath() + LOGOUT_PATH).equals(uri);
    }

    @Override
    public void destroy() {
    }
}
