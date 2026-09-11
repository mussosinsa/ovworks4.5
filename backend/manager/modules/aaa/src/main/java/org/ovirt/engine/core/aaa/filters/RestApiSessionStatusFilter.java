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

import org.ovirt.engine.core.common.businessentities.aaa.SessionEndReason;
import org.ovirt.engine.core.common.constants.SessionConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tells a REST API client whether the session it holds is still its session, and why not when it
 * is not.
 *
 * <p>A client only finds out that its session is gone by being refused, and it is only refused
 * when it asks for something. One that is sitting on an open console asks for nothing, so an
 * administrator can end its session and it will carry on showing a desktop to someone who has
 * been logged out. {@code GET /ovirt-engine/api/session} is what such a client polls so that
 * ending a session actually reaches it.</p>
 *
 * <p>Asking must not itself keep the session alive. Every other request refreshes the idle
 * timeout, which is right - a client making requests is a client that is there - but a client
 * polling this would then never time out, and the poll exists to enforce the ending of sessions,
 * not to prevent it. {@code GetSessionStatus} is the query that answers without refreshing.</p>
 *
 * <p>The session cookie is the whole of what this reads. No credentials are accepted and none
 * would help: the answer is about the session the caller is in, and a caller not in one is told
 * exactly that. This matters more than it looks - the client must be able to ask without the
 * asking being able to log it in, or the very request meant to notice the session ending would
 * quietly start a new one.</p>
 *
 * <p>Like {@link RestApiLogoutFilter}, this does not pass the request on: mapped ahead of the
 * filters that authenticate and of the one that drops the HTTP session of an ended session, it
 * both sees the session id it needs and leaves everything as it found it. So the same answer comes
 * back to every poll rather than only to the first.</p>
 *
 * <p>Three answers, and the third is the one worth being careful about:</p>
 * <ul>
 *   <li>{@code 204} - the session is live.</li>
 *   <li>{@code 401} with {@code X-OVirt-Session-End-Reason} - it is not, and the header says why,
 *       so a client can tell a user whose session an administrator ended from one whose session
 *       timed out. There is deliberately no {@code WWW-Authenticate}: this is a report, not a
 *       challenge, and a client that answered a challenge here would log itself back in.</li>
 *   <li>{@code 503} - the engine could not say. Not the same as the session being over, and a
 *       client must not treat it as such; it should keep what it has and ask again.</li>
 * </ul>
 */
public class RestApiSessionStatusFilter implements Filter {

    private static final Logger log = LoggerFactory.getLogger(RestApiSessionStatusFilter.class);

    /** Path of the session status resource, below the context root of the REST API webapp. */
    private static final String SESSION_PATH = "/session";

    private static final String GET = "GET";
    private static final String HEAD = "HEAD";

    @Override
    public void init(FilterConfig filterConfig) {
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;

        if (!isSessionStatusRequest(req)) {
            // Read here, and only here, because this is the last point at which it can be read:
            // the filters after this one invalidate the HTTP session of a session that has ended,
            // and with it goes the only record of which session the request was carrying. A
            // request that is about to be refused needs that to be able to say why it was refused.
            // See EnforceAuthFilter.
            String presented = presentedEngineSessionId(req);
            if (presented != null) {
                req.setAttribute(SessionConstants.REQUEST_PRESENTED_ENGINE_SESSION_ID, presented);
            }
            chain.doFilter(request, response);
            return;
        }

        HttpServletResponse res = (HttpServletResponse) response;

        // Reading a status changes nothing, so only the methods that mean "read" are answered.
        if (!GET.equalsIgnoreCase(req.getMethod()) && !HEAD.equalsIgnoreCase(req.getMethod())) {
            res.setHeader("Allow", GET);
            res.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
            return;
        }

        String engineSessionId = presentedEngineSessionId(req);

        if (engineSessionId == null) {
            ended(res, SessionEndReason.NO_SESSION);
            return;
        }

        SessionEndReason reason;
        try {
            reason = FiltersHelper.sessionEndReason(engineSessionId);
        } catch (RuntimeException e) {
            // Nothing was learned about the session, so nothing is claimed about it. Saying it had
            // ended would log out every client polling while the engine is having trouble.
            log.error("Unable to report the status of a session: {}", e.getMessage());
            log.debug("Exception", e);
            res.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
            return;
        }

        if (reason == null) {
            res.setStatus(HttpServletResponse.SC_NO_CONTENT);
        } else {
            ended(res, reason);
        }
    }

    /**
     * @return the engine session the request arrived carrying, or null when it carried none.
     *
     *         <p>getSession(false): a client asking whether it has a session must not be given one
     *         by asking.</p>
     */
    private static String presentedEngineSessionId(HttpServletRequest req) {
        HttpSession session = req.getSession(false);
        return session == null
                ? null
                : (String) session.getAttribute(SessionConstants.HTTP_SESSION_ENGINE_SESSION_ID_KEY);
    }

    /**
     * Reports that the session is over, and why.
     *
     * <p>setStatus rather than sendError: sendError hands the response to the container's error
     * page, and what this reply carries is the header. There is no body to send - the header is
     * the whole answer - so there is nothing an error page would add.</p>
     */
    private void ended(HttpServletResponse res, SessionEndReason reason) {
        res.setHeader(SessionConstants.SESSION_END_REASON_HEADER, reason.getWireName());
        res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }

    /**
     * @return true when the request is addressed to the session status resource itself. The request
     *         URI is compared rather than the servlet path, because everything in this webapp is
     *         mapped to one servlet and the servlet path is therefore not the part that identifies
     *         it.
     */
    private boolean isSessionStatusRequest(HttpServletRequest req) {
        String uri = req.getRequestURI();
        if (uri == null) {
            return false;
        }
        if (uri.length() > 1 && uri.endsWith("/")) {
            uri = uri.substring(0, uri.length() - 1);
        }
        return (req.getContextPath() + SESSION_PATH).equals(uri);
    }

    @Override
    public void destroy() {
    }
}
