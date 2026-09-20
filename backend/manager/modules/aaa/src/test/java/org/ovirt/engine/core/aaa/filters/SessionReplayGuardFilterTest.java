package org.ovirt.engine.core.aaa.filters;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.SessionCookieConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.ovirt.engine.core.common.constants.SessionConstants;

/**
 * When the guard refuses a request, and - the question this was written to answer - when it must
 * not.
 */
public class SessionReplayGuardFilterTest {

    /** A guard that is told what the engine would say, rather than asking it. */
    private static class Guard extends SessionReplayGuardFilter {

        private boolean engineSaysReplay;

        private int timesAsked;

        @Override
        boolean isReplay(HttpServletRequest req) {
            timesAsked++;
            return engineSaysReplay;
        }
    }

    private Guard guard;

    private HttpServletRequest request;

    private HttpServletResponse response;

    private FilterChain chain;

    @BeforeEach
    public void setUp() {
        guard = new Guard();
        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        chain = mock(FilterChain.class);

        ServletContext context = mock(ServletContext.class);
        SessionCookieConfig cookies = mock(SessionCookieConfig.class);
        when(context.getSessionCookieConfig()).thenReturn(cookies);
        when(request.getServletContext()).thenReturn(context);
        when(request.getContextPath()).thenReturn("/ovirt-engine/webadmin"); //$NON-NLS-1$
    }

    private void aRequestTo(String servletPath) {
        when(request.getServletPath()).thenReturn(servletPath);
    }

    private void presenting(String sessionId) {
        when(request.getRequestedSessionId()).thenReturn(sessionId);
    }

    private void withALiveSession() {
        when(request.getSession(false)).thenReturn(mock(HttpSession.class));
    }

    private void run() throws IOException, ServletException {
        guard.doFilter(request, response, chain);
    }

    private void assertRefused() throws IOException, ServletException {
        verify(chain, never()).doFilter(request, response);
        verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }

    private void assertLetThrough() throws IOException, ServletException {
        verify(chain).doFilter(request, response);
        verify(response, never()).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }

    @Test
    public void aBrowserThatHasNeverBeenHereIsNotAsked() throws Exception {
        aRequestTo("/GenericApiGWTService"); //$NON-NLS-1$
        presenting(null);

        run();

        assertLetThrough();
        assertEquals(0, guard.timesAsked);
    }

    @Test
    public void aRequestOnALiveSessionIsNotAsked() throws Exception {
        aRequestTo("/GenericApiGWTService"); //$NON-NLS-1$
        presenting("A-LIVE-ONE"); //$NON-NLS-1$
        withALiveSession();

        run();

        assertLetThrough();
        assertEquals(0, guard.timesAsked);
    }

    @Test
    public void aStaleCookieFromASessionThatMerelyRanOutIsLetThrough() throws Exception {
        aRequestTo("/GenericApiGWTService"); //$NON-NLS-1$
        presenting("TIMED-OUT"); //$NON-NLS-1$
        guard.engineSaysReplay = false;

        run();

        assertLetThrough();
        assertEquals(1, guard.timesAsked);
    }

    /** What the guard is for: a copy of a request from a session somebody deliberately ended. */
    @Test
    public void aCopyOfARequestFromAnEndedSessionIsRefused() throws Exception {
        aRequestTo("/GenericApiGWTService"); //$NON-NLS-1$
        presenting("SIGNED-OUT"); //$NON-NLS-1$
        guard.engineSaysReplay = true;

        run();

        assertRefused();
    }

    /**
     * And what it must not do.
     *
     * <p>Signing out ends the session and leaves the browser on the login page. Signing in again
     * goes through these paths, and the browser presents the cookie it has until it is given
     * another - which is the identifier of the session it just ended. Judged as a replay, the
     * request that would establish the new session is refused, and the person who signed out
     * cannot sign back in.</p>
     */
    @Test
    public void theRequestThatSignsSomebodyBackInIsNotACopyOfAnything() throws Exception {
        aRequestTo("/sso/oauth2-callback"); //$NON-NLS-1$
        presenting("SIGNED-OUT"); //$NON-NLS-1$
        guard.engineSaysReplay = true;

        run();

        assertLetThrough();
        assertEquals(0, guard.timesAsked, "the engine was asked about a request it cannot judge"); //$NON-NLS-1$
    }

    @Test
    public void norIsTheRequestThatSendsThemToTheLoginPage() throws Exception {
        aRequestTo("/sso/login"); //$NON-NLS-1$
        presenting("SIGNED-OUT"); //$NON-NLS-1$
        guard.engineSaysReplay = true;

        run();

        assertLetThrough();
    }

    /** Signing out of a session already ended is not worth refusing, and refusing it strands them. */
    @Test
    public void norTheRequestThatSignsThemOut() throws Exception {
        aRequestTo("/sso/logout"); //$NON-NLS-1$
        presenting("SIGNED-OUT"); //$NON-NLS-1$
        guard.engineSaysReplay = true;

        run();

        assertLetThrough();
    }

    /** The exemption is the login flow, not everything with a similar-looking name. */
    @Test
    public void andNothingElseIsExempt() throws Exception {
        aRequestTo("/ssoSomethingElse"); //$NON-NLS-1$
        presenting("SIGNED-OUT"); //$NON-NLS-1$
        guard.engineSaysReplay = true;

        run();

        assertRefused();
    }

    @Test
    public void aRefusalSaysWhatItIsAndClearsTheIdentifier() throws Exception {
        aRequestTo("/GenericApiGWTService"); //$NON-NLS-1$
        presenting("SIGNED-OUT"); //$NON-NLS-1$
        guard.engineSaysReplay = true;

        run();

        verify(response).setHeader(SessionConstants.SESSION_REPLAY_HEADER, "true"); //$NON-NLS-1$
        verify(response).addCookie(ArgumentMatchers.argThat(cookie -> cookie.getMaxAge() == 0));
    }
}
