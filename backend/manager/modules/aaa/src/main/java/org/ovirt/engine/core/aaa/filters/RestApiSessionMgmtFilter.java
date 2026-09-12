package org.ovirt.engine.core.aaa.filters;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.ovirt.engine.core.common.action.ActionParametersBase;
import org.ovirt.engine.core.common.action.ActionReturnValue;
import org.ovirt.engine.core.common.action.ActionType;
import org.ovirt.engine.core.common.action.RegisterRestApiSessionParameters;
import org.ovirt.engine.core.common.action.SetSesssionSoftLimitCommandParameters;
import org.ovirt.engine.core.common.constants.SessionConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RestApiSessionMgmtFilter implements Filter {

    private static final Logger log = LoggerFactory.getLogger(RestApiSessionMgmtFilter.class);

    private static final int MINIMAL_SESSION_TTL = 1;

    /** How a client asks for a session timeout shorter than the configured one. */
    private static final String SESSION_TTL_HEADER = "Session-TTL"; //$NON-NLS-1$
    private static final String BEARER = "Bearer";

    @Override
    public void init(FilterConfig filterConfig) {
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException,
            ServletException {

        try {
            HttpServletRequest req = (HttpServletRequest) request;

            String engineSessionId = (String) request.getAttribute(SessionConstants.HTTP_SESSION_ENGINE_SESSION_ID_KEY);
            if (engineSessionId == null) {
                HttpSession session = req.getSession(false);
                if (session != null) {
                    engineSessionId =
                            (String) session.getAttribute(SessionConstants.HTTP_SESSION_ENGINE_SESSION_ID_KEY);
                    if (engineSessionId != null) {
                        request.setAttribute(SessionConstants.HTTP_SESSION_ENGINE_SESSION_ID_KEY, engineSessionId);
                    }
                }
            }

            if (engineSessionId == null) {
                throw new ServletException("No engine session");
            }

            int prefer = FiltersHelper.getPrefer(req);
            if ((prefer & FiltersHelper.PREFER_PERSISTENCE_AUTH) != 0) {
                HttpSession session = req.getSession(true);
                session.setAttribute(SessionConstants.HTTP_SESSION_ENGINE_SESSION_ID_KEY, engineSessionId);
                if (isNewSession(req)) {
                    // The engine decides the timeout: it caps what Session-TTL asks for at
                    // UserSessionTimeOutInterval, and when the header asks for nothing it answers
                    // with the configured timeout the session already carries. Either way the HTTP
                    // session is given that same timeout, so the two end together.
                    //
                    // This used to happen only for a request that carried a usable Session-TTL.
                    // Without one the HTTP session kept the web application's own default - three
                    // hours, unrelated to anything configured - and outlived the engine session it
                    // was there to carry.
                    int appliedMinutes = setEngineSessionSoftLimit(engineSessionId, requestedTtlMinutes(req));
                    if (appliedMinutes > 0) {
                        session.setMaxInactiveInterval((int) TimeUnit.MINUTES.toSeconds(appliedMinutes));
                    }
                    registerHttpSession(engineSessionId, session.getId());
                }
            }

            chain.doFilter(request, response);

            if (FiltersHelper.isAuthenticated(req)) {
                String headerValue = req.getHeader(FiltersHelper.Constants.HEADER_AUTHORIZATION);
                if ((headerValue == null || !headerValue.startsWith(BEARER)) &&
                        (prefer & FiltersHelper.PREFER_PERSISTENCE_AUTH) == 0) {
                    logSessionNotKept(req);
                    InitialContext ctx = new InitialContext();
                    try {
                        FiltersHelper.getBackend(ctx).runAction(
                                ActionType.LogoutSession,
                                new ActionParametersBase(engineSessionId)
                                );
                        HttpSession session = req.getSession(false);
                        if (session != null) {
                            try {
                                session.invalidate();
                            } catch (IllegalStateException e) {
                                // ignore
                            }
                        }
                    } finally {
                        ctx.close();
                    }
                }
            }
        } catch (NamingException e) {
            log.error("REST-API session failed: {}", e.getMessage());
            log.debug("Exception", e);
            throw new ServletException(e);
        }
    }

    /*
     * A session is considered new if this request has resulted in a log-in. At this point in time we are after the
     * log-in, but we can know if it took place by the value of 'ovirt_aaa_login_filter_authentication_done' attribute.
     * LoginFilter sets 'true' for this attribute and when a log-in is performed.
     */
    /**
     * @return the timeout in minutes the request asked for with {@code Session-TTL}, or 0 when it
     *         asked for none. A value below {@link #MINIMAL_SESSION_TTL}, or one that is not a
     *         number, is treated as asking for none rather than as asking for that value: it says
     *         nothing usable, and the configured timeout is the right answer to no request.
     */
    static int requestedTtlMinutes(HttpServletRequest req) {
        try {
            int ttlMinutes = Integer.parseInt(req.getHeader(SESSION_TTL_HEADER));
            return ttlMinutes >= MINIMAL_SESSION_TTL ? ttlMinutes : 0;
        } catch (NumberFormatException ex) {
            return 0;
        }
    }

    private boolean isNewSession(HttpServletRequest req) {
        return req.getAttribute(FiltersHelper.Constants.REQUEST_LOGIN_FILTER_AUTHENTICATION_DONE) != null
                && (boolean) req.getAttribute(FiltersHelper.Constants.REQUEST_LOGIN_FILTER_AUTHENTICATION_DONE);
    }

    /**
     * Records what the request carried when its session is ended rather than kept.
     *
     * <p>A REST session is kept only for a request that asks for it with {@code Prefer:
     * persistent-auth}. When a client is certain it sends that header and its sessions end anyway,
     * the question is what reached the engine rather than what left the client - a proxy in
     * between, or a request built on a different code path than the one that was checked - and
     * this reports the Prefer headers exactly as received so the two can be compared. An empty
     * list means the header did not arrive at all; a list that does contain persistent-auth would
     * mean the engine failed to parse what it received.</p>
     *
     * <p>A request that presents a session cookie is asking to continue a session while not
     * asking for the session to be kept, which contradicts itself and is worth reporting on its
     * own; that case is logged whatever the configured level is. A client that keeps no session
     * at all is behaving as designed, so it is only reported when this class is set to debug.</p>
     *
     * <p>Only the presence of the session cookie is reported, never its value: that value is the
     * session credential.</p>
     */
    private void logSessionNotKept(HttpServletRequest req) {
        boolean sessionCookiePresented = req.getRequestedSessionId() != null;
        if (!sessionCookiePresented && !log.isDebugEnabled()) {
            return;
        }
        List<String> preferHeaders = Collections.list(req.getHeaders(FiltersHelper.Constants.HEADER_PREFER));
        Object[] details = {
            req.getMethod(),
            req.getRequestURI(),
            preferHeaders.isEmpty() ? "<none>" : preferHeaders,
            sessionCookiePresented
        };
        if (sessionCookiePresented) {
            log.info("Ending the REST session of '{} {}': the request presents a session cookie but carries no"
                    + " 'Prefer: persistent-auth', so the session it continues is closed once this request is"
                    + " served. Prefer header(s) as received: {}. Session cookie presented: {}.", details);
        } else {
            log.debug("Ending the REST session of '{} {}': the request carries no 'Prefer: persistent-auth'."
                    + " Prefer header(s) as received: {}. Session cookie presented: {}.", details);
        }
    }

    /**
     * Tells the engine which HTTP session carries this one, while both still exist.
     *
     * <p>It is the only moment the pairing can be taken down. A request replayed after the session
     * has ended presents the cookie and nothing else, and by then the HTTP session it names has
     * been thrown away - so without this the engine cannot tell such a request from one sent by a
     * client that has yet to log in, and RestApiReplayGuardFilter has nothing to go on.</p>
     *
     * <p>Failing is not worth refusing the login over. What is lost is the ability to recognise a
     * copy of this session's traffic later, and the session itself is in every other way sound.</p>
     */
    private void registerHttpSession(String engineSessionId, String httpSessionId) {
        try {
            InitialContext ctx = new InitialContext();
            try {
                FiltersHelper.getBackend(ctx).runAction(
                        ActionType.RegisterRestApiSession,
                        new RegisterRestApiSessionParameters(engineSessionId, httpSessionId));
            } finally {
                ctx.close();
            }
        } catch (NamingException | RuntimeException e) {
            log.error("Unable to record which HTTP session carries a REST session: {}", e.getMessage());
            log.debug("Exception", e);
        }
    }

    /**
     * @return the timeout in minutes the engine applied, which is {@code ttlValue} capped at
     *         {@code UserSessionTimeOutInterval}. When the engine did not apply one - there is no
     *         such engine session - the requested value is returned, leaving the behaviour of the
     *         HTTP session as it was.
     */
    private int setEngineSessionSoftLimit(String engineSessionId, int ttlValue) throws IOException, NamingException {

        InitialContext context = new InitialContext();
        try {
            ActionReturnValue returnValue = FiltersHelper.getBackend(context).runAction(
                    ActionType.SetSesssionSoftLimit,
                    new SetSesssionSoftLimitCommandParameters(engineSessionId, ttlValue));
            if (returnValue != null && returnValue.getSucceeded()) {
                Integer applied = returnValue.getActionReturnValue();
                if (applied != null) {
                    return applied;
                }
            }
            return ttlValue;
        } finally {
            try {
                context.close();
            } catch (NamingException e) {
                log.error("Error in REST-API session management. 'Context' object could not be manually closed. " +
                        "This is a cleanup error only; it does not disturb application flow", e);
            }
        }
    }

    @Override
    public void destroy() {
    }

}
