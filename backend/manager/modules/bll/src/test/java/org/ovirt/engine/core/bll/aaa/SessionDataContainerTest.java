package org.ovirt.engine.core.bll.aaa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.Date;
import java.util.stream.Stream;

import org.apache.commons.lang.time.DateUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.ovirt.engine.core.common.businessentities.aaa.DbUser;
import org.ovirt.engine.core.common.businessentities.aaa.SessionEndReason;
import org.ovirt.engine.core.common.config.ConfigValues;
import org.ovirt.engine.core.dao.EngineSessionDao;
import org.ovirt.engine.core.utils.MockConfigDescriptor;
import org.ovirt.engine.core.utils.MockConfigExtension;

/**
 * A test case for the {@link SessionDataContainer} class.
 */
@ExtendWith({MockitoExtension.class, MockConfigExtension.class})
@MockitoSettings(strictness = Strictness.LENIENT)
public class SessionDataContainerTest {

    private static final String TEST_KEY = "someKey";
    private static final String TEST_VALUE = "someValue";
    private static final String TEST_SESSION_ID = "someSession";
    private static final String TEST_SSO_TOKEN = "someToken";
    private static final String USER = "user";
    private static final String SOFT_LIMIT = "soft_limit";
    private static final String SOFT_LIMIT_INTERVAL = "soft_limit_interval";

    /** The UserSessionTimeOutInterval the tests run with. */
    private static final int CONFIGURED_TIMEOUT = 30;
    private static final int LONGER_THAN_CONFIGURED = 600;
    private static final int SHORTER_THAN_CONFIGURED = 5;

    public static Stream<MockConfigDescriptor<?>> mockConfiguration() {
        return Stream.of(MockConfigDescriptor.of(ConfigValues.UserSessionTimeOutInterval, CONFIGURED_TIMEOUT));
    }

    @Mock
    private EngineSessionDao engineSessionDao;

    @InjectMocks
    private SessionDataContainer container;

    @Mock
    private SessionDataContainer.SsoSessionValidator ssoSessionValidator;

    @Mock
    private SsoSessionUtils ssoSessionUtils;

    @BeforeEach
    public void setUpContainer() {
        when(engineSessionDao.remove(anyLong())).thenReturn(1);
        when(ssoSessionValidator.getSessionStatuses(any())).thenReturn(Collections.singletonMap(TEST_SSO_TOKEN, true));
        when(ssoSessionUtils.isSessionInUse(anyLong())).thenReturn(false);

        DbUser user = mock(DbUser.class);
        container.setUser(TEST_SESSION_ID, user);
        container.setSsoAccessToken(TEST_SESSION_ID, TEST_SSO_TOKEN);
    }

    public void clearSession() {
        container.removeSessionOnLogout(TEST_SESSION_ID);
    }

    @Test
    public void testGetDataAndSetDataWithEmptySession() {
        assertNull(container.getData("", TEST_KEY, false), "Get should return null with an empty session");
        clearSession();
    }

    @Test
    public void testGetDataAndSetDataWithFullSession() {
        container.setData(TEST_SESSION_ID, TEST_KEY, TEST_VALUE);
        assertEquals(TEST_VALUE, container.getData(TEST_SESSION_ID, TEST_KEY, false),
                "Get should return the value with a given session");
        clearSession();
    }

    @Test
    public void testGetUserAndSetUserWithSessionParam() {
        DbUser user = mock(DbUser.class);
        container.setUser(TEST_SESSION_ID, user);
        assertEquals(user, container.getUser(TEST_SESSION_ID, false),
                "Get should return the value with a given session");
        clearSession();
    }

    /* Tests for session management */

    @Test
    public void testRemoveWithParam() {
        // Set some data on the test sessions
        container.setData(TEST_SESSION_ID, TEST_KEY, TEST_VALUE);
        container.removeSessionOnLogout(TEST_SESSION_ID);
        assertNull(container.getData(TEST_SESSION_ID, TEST_KEY, false),
                "Get should return null since the session was removed");
    }
    /* Tests for clearedExpiredSessions */

    @Test
    public void testCleanExpiredSessions() {
        initDataForClearTest(TEST_KEY);
        // Clear expired sessions - data is moved to older generation
        // nothing should happen as far as the user is concerned
        container.cleanExpiredUsersSessions();
        assertNull(container.getData(TEST_SESSION_ID, TEST_KEY, false), "Get not find the session");
    }

    @Test
    public void testCleanExpiredSessionsWithRunningCommands() {
        when(ssoSessionUtils.isSessionInUse(anyLong())).thenReturn(true);

        initDataForClearTest(TEST_KEY);
        // Clear expired sessions - data is moved to older generation
        // nothing should happen as far as the user is concerned
        container.cleanExpiredUsersSessions();
        assertNotNull(container.getData(TEST_SESSION_ID, TEST_KEY, false), "Get found the session");
    }

    /** Initializes the {@link #key} data */
    private void initDataForClearTest(String key) {
        container.setData(TEST_SESSION_ID, key, mock(DbUser.class));
        container.setData(TEST_SESSION_ID, SOFT_LIMIT, DateUtils.addMinutes(new Date(), -1));
    }

    /* What the sweep does when it cannot reach single sign-on */

    @Test
    public void testEndedSessionIsRemovedEvenWhenSsoDoesNotAnswer() {
        // getSessionStatuses answers with nothing when the call to sso fails
        when(ssoSessionValidator.getSessionStatuses(any())).thenReturn(Collections.emptyMap());
        container.setSessionValid(TEST_SESSION_ID, false);

        container.cleanExpiredUsersSessions();

        // Whether an administrator has ended a session is something this engine knows on its own.
        // It used to be reached only for a session whose sso status had come back, so terminating
        // a session where that call was failing wrote the audit entry and changed nothing else.
        assertNull(container.getData(TEST_SESSION_ID, USER, false),
                "A session ended by an administrator should be removed whatever sso answered");
    }

    @Test
    public void testExpiredSessionIsRemovedEvenWhenSsoDoesNotAnswer() {
        when(ssoSessionValidator.getSessionStatuses(any())).thenReturn(Collections.emptyMap());
        container.setData(TEST_SESSION_ID, SOFT_LIMIT, DateUtils.addMinutes(new Date(), -1));

        container.cleanExpiredUsersSessions();

        assertNull(container.getData(TEST_SESSION_ID, USER, false),
                "A session past its idle timeout should be removed whatever sso answered");
    }

    @Test
    public void testLiveSessionIsKeptWhenSsoDoesNotAnswer() {
        when(ssoSessionValidator.getSessionStatuses(any())).thenReturn(Collections.emptyMap());

        container.cleanExpiredUsersSessions();

        // sso not answering is not a reason to end a session that has no reason of its own to end
        assertNotNull(container.getData(TEST_SESSION_ID, USER, false),
                "A session with nothing wrong with it should survive sso being unreachable");
        clearSession();
    }

    @Test
    public void testHalfBuiltSessionDoesNotStopTheSweep() {
        // setSourceIp runs before setUser, so a session can be in the map with no validity flag.
        // Reading that as a boolean threw, and the throw ended the sweep for everything behind it.
        container.setSourceIp("sessionBeingBuilt", "192.0.2.1");
        container.setData(TEST_SESSION_ID, SOFT_LIMIT, DateUtils.addMinutes(new Date(), -1));

        container.cleanExpiredUsersSessions();

        assertNull(container.getData(TEST_SESSION_ID, USER, false),
                "A session being built should not stop the sweep from reaching the others");
    }

    /* What a client is told about why its session is no longer usable */

    @Test
    public void testLiveSessionHasNoEndReason() {
        assertNull(container.getSessionEndReason(TEST_SESSION_ID),
                "A session that has not ended has no reason for having ended");
        clearSession();
    }

    @Test
    public void testSessionNobodyKnowsAboutIsReportedAsNoSession() {
        assertEquals(SessionEndReason.NO_SESSION, container.getSessionEndReason("neverHeardOfIt"),
                "A session this engine has no record of is not the same as one that ended");
        clearSession();
    }

    @Test
    public void testTerminatedSessionReportsTheAdministratorBeforeTheSweepRuns() {
        // What TerminateSessionCommand does: record why, then end it. The sweep that removes it
        // runs once a minute, and a client asking in between has to get the same answer.
        container.setSessionEndReason(TEST_SESSION_ID, SessionEndReason.TERMINATED_BY_ADMIN);
        container.setSessionValid(TEST_SESSION_ID, false);

        assertEquals(SessionEndReason.TERMINATED_BY_ADMIN, container.getSessionEndReason(TEST_SESSION_ID));
        clearSession();
    }

    @Test
    public void testTerminatedSessionStillReportsTheAdministratorAfterItIsRemoved() {
        // Nothing here is about sso, and a token it says is live is revoked as the session goes.
        when(ssoSessionValidator.getSessionStatuses(any())).thenReturn(Collections.emptyMap());
        container.setSessionEndReason(TEST_SESSION_ID, SessionEndReason.TERMINATED_BY_ADMIN);
        container.setSessionValid(TEST_SESSION_ID, false);

        container.cleanExpiredUsersSessions();

        assertNull(container.getData(TEST_SESSION_ID, USER, false), "The sweep should have removed it");
        // The session is gone; why it went is what its client still has to be told, and a client
        // that was unreachable for a moment would otherwise be told only what it already knows.
        assertEquals(SessionEndReason.TERMINATED_BY_ADMIN, container.getSessionEndReason(TEST_SESSION_ID));
    }

    @Test
    public void testSessionPastItsIdleTimeoutReportsTheTimeout() {
        when(ssoSessionValidator.getSessionStatuses(any())).thenReturn(Collections.emptyMap());
        container.setData(TEST_SESSION_ID, SOFT_LIMIT, DateUtils.addMinutes(new Date(), -1));

        container.cleanExpiredUsersSessions();

        // Told apart from an administrator ending it because the user has to do something
        // different about each: nothing, or ask somebody.
        assertEquals(SessionEndReason.IDLE_TIMEOUT, container.getSessionEndReason(TEST_SESSION_ID));
    }

    @Test
    public void testSessionEndedWithoutAReasonIsReportedAsALogout() {
        // LogoutSession is reached both from the logout a user asked for and from an administrator
        // ending the session, and only the latter records a reason.
        container.setSessionValid(TEST_SESSION_ID, false);

        assertEquals(SessionEndReason.SIGNED_OUT, container.getSessionEndReason(TEST_SESSION_ID));
        clearSession();
    }

    @Test
    public void testSessionBeingBuiltHasNotEnded() {
        // setSourceIp runs before setUser, so a session can be in the map with no validity flag.
        // That is a session on its way in, not one on its way out.
        container.setSourceIp("sessionBeingBuilt", "192.0.2.1");

        assertFalse(container.isSessionEnded("sessionBeingBuilt"),
                "A session still being built has not ended");
        clearSession();
    }

    @Test
    public void testEndReasonIsNotRecordedForASessionThatDoesNotExist() {
        // setData creates the session it is given when there is none, which would conjure an empty
        // session carrying nothing but a reason for having ended.
        container.setSessionEndReason("neverHeardOfIt", SessionEndReason.TERMINATED_BY_ADMIN);

        assertNull(container.getData("neverHeardOfIt", USER, false),
                "Recording a reason should not bring a session into being");
        clearSession();
    }

    /* Tests for the idle timeout */

    @Test
    public void testSoftLimitIntervalIsCappedAtTheConfiguredTimeout() {
        assertEquals(CONFIGURED_TIMEOUT,
                container.setSoftLimitInterval(TEST_SESSION_ID, LONGER_THAN_CONFIGURED),
                "A timeout longer than UserSessionTimeOutInterval should not be applied");
        assertEquals(CONFIGURED_TIMEOUT,
                container.getData(TEST_SESSION_ID, SOFT_LIMIT_INTERVAL, false),
                "The capped timeout should be the one recorded on the session");
        clearSession();
    }

    @Test
    public void testSoftLimitIntervalShorterThanTheConfiguredTimeoutIsKept() {
        assertEquals(SHORTER_THAN_CONFIGURED,
                container.setSoftLimitInterval(TEST_SESSION_ID, SHORTER_THAN_CONFIGURED),
                "Asking for a shorter timeout asks for less exposure and should be honoured");
        clearSession();
    }

    @Test
    public void testSoftLimitIntervalOfASessionThatAskedForNothingIsTheConfiguredTimeout() {
        // Every session is given the configured timeout when it is created. The REST API reads it
        // back here to give its own HTTP session the same one, so that a client that sends no
        // Session-TTL still times out when the configuration says rather than when the web
        // application's unrelated default says.
        container.setData(TEST_SESSION_ID, USER, mock(DbUser.class));

        assertEquals(CONFIGURED_TIMEOUT, container.getSoftLimitInterval(TEST_SESSION_ID),
                "A session that asked for no particular timeout answers to the configured one");
        clearSession();
    }

    @Test
    public void testSoftLimitIntervalIsReportedAsCappedForASessionThatAskedForLonger() {
        container.setData(TEST_SESSION_ID, SOFT_LIMIT_INTERVAL, LONGER_THAN_CONFIGURED);

        assertEquals(CONFIGURED_TIMEOUT, container.getSoftLimitInterval(TEST_SESSION_ID),
                "Reading the timeout back should cap it just as applying it does");
        clearSession();
    }

    @Test
    public void testSoftLimitIntervalKeepsAShorterTimeoutWhenReadBack() {
        container.setData(TEST_SESSION_ID, SOFT_LIMIT_INTERVAL, SHORTER_THAN_CONFIGURED);

        assertEquals(SHORTER_THAN_CONFIGURED, container.getSoftLimitInterval(TEST_SESSION_ID),
                "A session that asked for less exposure keeps what it asked for");
        clearSession();
    }

    @Test
    public void testRefreshAppliesATimeoutShortenedAfterTheSessionStarted() {
        // a session opened while the timeout was longer carries the interval it started with
        container.setData(TEST_SESSION_ID, SOFT_LIMIT_INTERVAL, LONGER_THAN_CONFIGURED);

        container.getData(TEST_SESSION_ID, USER, true);

        Date softLimit = (Date) container.getData(TEST_SESSION_ID, SOFT_LIMIT, false);
        assertNotNull(softLimit, "Refreshing the session should have set an expiry");
        assertTrue(softLimit.before(DateUtils.addMinutes(new Date(), CONFIGURED_TIMEOUT + 1)),
                "The session should expire within the configured timeout, not the one it opened with");
        clearSession();
    }

    @Test
    public void testRefreshUserSession() {
        // refresh the old session (refresh = true)
        container.getData(TEST_SESSION_ID, USER, true);

        // cleared expired session
        container.cleanExpiredUsersSessions();

        Object obj = container.getData(TEST_SESSION_ID, USER, false);

        // session should be already refreshed -> not null
        assertNotNull(container.getData(TEST_SESSION_ID, USER, false),
                "Get should return null since the session wasn't refresh");
        clearSession();
    }

    @Test
    public void testRefreshUserSessionAfterExpiration() {
        initDataForClearTest(USER);

        // Clear expired sessions twice - data is moved to older generation, then removed
        container.cleanExpiredUsersSessions();
        container.cleanExpiredUsersSessions();

        // refresh the old session (refresh = true)
        // -> the user session is already expired so couldn't refresh it
        container.getData(TEST_SESSION_ID, USER, true);

        // no session available
        assertNull(container.getData(TEST_SESSION_ID, USER, false),
                "Get should return null since the session wasn't refresh");
    }

}
