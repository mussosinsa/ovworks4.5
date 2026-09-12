package org.ovirt.engine.core.aaa.filters;

import java.io.IOException;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.ovirt.engine.core.common.action.ActionReturnValue;
import org.ovirt.engine.core.common.action.ActionType;
import org.ovirt.engine.core.common.action.BlockReplayedSessionParameters;
import org.ovirt.engine.core.common.constants.SessionConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Refuses a request that presents the session identifier of a session already ended.
 *
 * <p>Encrypting the credentials stops a copy of a request from being read; the wrapper inside the
 * encryption stops one from logging in again later. Neither says anything about a copy of a request
 * from a session that was already open - it carries no login to check, only a cookie. Until now
 * such a copy was answered the way a client that has yet to log in is answered, "not
 * authenticated", and then, if it happened to carry credentials as well, it was allowed to
 * authenticate itself afresh and carry on. Logging out did not end what a copy of the traffic could
 * do.</p>
 *
 * <p>A request naming a session that was deliberately ended - logged out, or terminated by an
 * administrator - cannot be a request of that session's. The client that held it let go of it at
 * that moment. So it is refused here, before anything can authenticate it, and the refusal is
 * recorded against the session it named: who held it, from where, and what the copy was asking
 * for.</p>
 *
 * <p>Only sessions ended deliberately are judged this way. A session that timed out was not ended
 * by anyone; its client was still using it when it ran out, and a stale cookie from one of those is
 * an ordinary thing to see rather than evidence of a copy.</p>
 *
 * <p>Placed after the filters that drop the HTTP session of a session that has ended and before the
 * ones that authenticate, which is the only window in which both halves are true: the request no
 * longer resolves to a session, and nothing has yet given it a new one.</p>
 *
 * <p>The engine is asked only about a request that presents a session identifier and has no session
 * - the rare case, and the only one that can be a replay. A request on a live session, and one that
 * presents no identifier at all, cost nothing here.</p>
 */
public class RestApiReplayGuardFilter implements Filter {

    private static final Logger log = LoggerFactory.getLogger(RestApiReplayGuardFilter.class);

    @Override
    public void init(FilterConfig filterConfig) {
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;

        // getSession(false): asking must not create the session whose absence is the question.
        String presented = req.getRequestedSessionId();
        if (StringUtils.isEmpty(presented) || req.getSession(false) != null) {
            chain.doFilter(request, response);
            return;
        }

        if (isReplay(req)) {
            HttpServletResponse res = (HttpServletResponse) response;
            // Said plainly, because "not authenticated" is what a client that has yet to log in is
            // told and this is not that. No WWW-Authenticate: there is nothing to try again with.
            res.setHeader(SessionConstants.SESSION_REPLAY_HEADER, "true");
            res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        chain.doFilter(request, response);
    }

    /**
     * @return true when the engine recognises the presented identifier as one it ended. A question
     *         it cannot answer is answered no: refusing a request because the engine is having
     *         trouble would turn a moment of trouble into everybody being locked out, and the
     *         request still has to authenticate itself before it gets anywhere.
     */
    private boolean isReplay(HttpServletRequest req) {
        try {
            InitialContext ctx = new InitialContext();
            try {
                ActionReturnValue returnValue = FiltersHelper.getBackend(ctx).runAction(
                        ActionType.BlockReplayedSession,
                        new BlockReplayedSessionParameters(
                                req.getRequestedSessionId(),
                                req.getRemoteAddr(),
                                req.getMethod() + " " + req.getRequestURI()));
                return returnValue != null
                        && returnValue.getSucceeded()
                        && Boolean.TRUE.equals(returnValue.getActionReturnValue());
            } finally {
                ctx.close();
            }
        } catch (NamingException | RuntimeException e) {
            log.error("Unable to check whether a request replays an ended session: {}", e.getMessage());
            log.debug("Exception", e);
            return false;
        }
    }

    @Override
    public void destroy() {
    }
}
