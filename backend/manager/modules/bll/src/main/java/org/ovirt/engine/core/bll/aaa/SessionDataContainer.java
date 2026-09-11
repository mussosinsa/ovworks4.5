package org.ovirt.engine.core.bll.aaa;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import javax.annotation.PostConstruct;
import javax.enterprise.concurrent.ManagedScheduledExecutorService;
import javax.inject.Inject;
import javax.inject.Singleton;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.apache.commons.lang.time.DateUtils;
import org.ovirt.engine.api.extensions.aaa.Acct;
import org.ovirt.engine.core.aaa.AcctUtils;
import org.ovirt.engine.core.aaa.AuthenticationProfile;
import org.ovirt.engine.core.aaa.AuthenticationProfileRepository;
import org.ovirt.engine.core.aaa.SsoOAuthServiceUtils;
import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.businessentities.EngineSession;
import org.ovirt.engine.core.common.businessentities.aaa.DbUser;
import org.ovirt.engine.core.common.businessentities.aaa.SessionEndReason;
import org.ovirt.engine.core.common.config.Config;
import org.ovirt.engine.core.common.config.ConfigValues;
import org.ovirt.engine.core.dal.dbbroker.auditloghandling.AuditLogDirector;
import org.ovirt.engine.core.dal.dbbroker.auditloghandling.AuditLogable;
import org.ovirt.engine.core.dal.dbbroker.auditloghandling.AuditLogableImpl;
import org.ovirt.engine.core.dao.EngineSessionDao;
import org.ovirt.engine.core.utils.threadpool.ThreadPools;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Singleton
public class SessionDataContainer {

    SsoSessionValidator ssoSessionValidator = new SsoSessionValidator();

    @Inject
    SsoSessionUtils ssoSessionUtils;

    @Inject
    private AuditLogDirector auditLogDirector;

    @Inject
    @ThreadPools(ThreadPools.ThreadPoolType.EngineScheduledThreadPool)
    private ManagedScheduledExecutorService scheduledExecutorService;

    private static class SessionInfo {
        private ConcurrentMap<String, Object> contentOfSession = new ConcurrentHashMap<>();

    }

    protected Logger log = LoggerFactory.getLogger(getClass());

    private ConcurrentMap<String, SessionInfo> sessionInfoMap = new ConcurrentHashMap<>();

    /**
     * Why each recently ended session ended, kept after the session itself is gone.
     *
     * <p>A client asks what became of its session, and the answer it needs - an administrator
     * ended this, or it timed out - stops being available the moment the session is removed from
     * {@link #sessionInfoMap}. A client that was briefly unreachable would then be told only that
     * its session is gone, which is the one thing it already knows. So the reason outlives the
     * session, for long enough that a client which missed the moment can still be told what
     * happened, and no longer.</p>
     *
     * <p>It holds nothing but the session id, a reason and a time. The session id is the session's
     * credential, and this map is the reason a used-up one is worth keeping for a while; nothing
     * here can authorise anything, and the ids are never handed out - a caller has to already hold
     * the id to ask about it.</p>
     */
    private final ConcurrentMap<String, EndedSession> endedSessions = new ConcurrentHashMap<>();

    /** How long the reason a session ended is kept after it ends. */
    private static final int ENDED_SESSION_RECORD_MINUTES = 30;

    /**
     * At most this many ended sessions are remembered. The time limit is what normally bounds the
     * map; this bounds it too when sessions are being created and destroyed fast enough that the
     * time limit alone would let it grow without a ceiling.
     */
    private static final int ENDED_SESSION_RECORD_LIMIT = 10_000;

    private static class EndedSession {
        private final SessionEndReason reason;
        private final Date endedAt;

        EndedSession(SessionEndReason reason, Date endedAt) {
            this.reason = reason;
            this.endedAt = endedAt;
        }
    }

    private static final String USER_PARAMETER_NAME = "user";
    private static final String SOURCE_IP = "source_ip";
    private static final String PROFILE_PARAMETER_NAME = "profile";
    private static final String HARD_LIMIT_PARAMETER_NAME = "hard_limit";
    private static final String SOFT_LIMIT_PARAMETER_NAME = "soft_limit";
    private static final String ENGINE_SESSION_SEQ_ID = "engine_session_seq_id";
    private static final String ENGINE_SESSION_ID = "engine_session_id";
    private static final String PRINCIPAL_PARAMETER_NAME = "username";
    private static final String SSO_ACCESS_TOKEN_PARAMETER_NAME = "sso_access_token";
    private static final String SSO_IS_OVIRT_APP_API_SCOPE_PARAMETER_NAME = "sso_is_ovirt_app_api_scope";
    private static final String SESSION_VALID_PARAMETER_NAME = "session_valid";
    private static final String SESSION_END_REASON_PARAMETER_NAME = "session_end_reason";
    private static final String SOFT_LIMIT_INTERVAL_PARAMETER_NAME = "soft_limit_interval";
    private static final String SESSION_START_TIME = "session_start_time";
    private static final String SESSION_LAST_ACTIVE_TIME = "session_last_active_time";
    private static final String OVIRT_APP_API_SCOPE = "ovirt-app-api";
    private static final String OVIRT_APP_ADMIN_SCOPE = "ovirt-app-admin";
    private static final String OVIRT_APP_PORTAL_SCOPE = "ovirt-app-portal";

    @Inject
    private EngineSessionDao engineSessionDao;

    @PostConstruct
    private void init() {
        scheduledExecutorService.scheduleAtFixedRate(this::cleanExpiredUsersSessions,
                1,
                1, TimeUnit.MINUTES);

    }

    public String generateEngineSessionId() {
        String engineSessionId;
        byte[] s = new byte[64];
        new SecureRandom().nextBytes(s);
        engineSessionId = new Base64(0).encodeToString(s);
        return engineSessionId;
    }

    /**
     * Get data by session and internal key
     *
     * @param sessionId
     *            - id of session
     * @param key
     *            - the internal key
     * @param refresh
     *            - if perform refresh of session
     */
    public final Object getData(String sessionId, String key, boolean refresh) {
        if (sessionId == null) {
            return null;
        }
        SessionInfo sessionInfo = getSessionInfo(sessionId);
        Object value = null;
        if (sessionInfo != null) {
            if (refresh) {
                refresh(sessionInfo);

            }
            value = sessionInfo.contentOfSession.get(key);
        }
        return value;
    }

    public final void setData(String sessionId, String key, Object value) {
        SessionInfo sessionInfo = getSessionInfo(sessionId);
        if (sessionInfo == null) {
            sessionInfo = new SessionInfo();
            sessionInfo.contentOfSession.put(ENGINE_SESSION_ID, sessionId);
            // Add default soft-limit interval for new sessions
            sessionInfo.contentOfSession.put(SOFT_LIMIT_INTERVAL_PARAMETER_NAME,
                    Config.<Integer> getValue(ConfigValues.UserSessionTimeOutInterval));
            SessionInfo oldSessionInfo = sessionInfoMap.putIfAbsent(sessionId, sessionInfo);
            if (oldSessionInfo != null) {
                sessionInfo = oldSessionInfo;
            }
        }
        sessionInfo.contentOfSession.put(key, value);
    }

    private SessionInfo getSessionInfo(String sessionId) {
        return sessionInfoMap.get(sessionId);
    }

    private void persistEngineSession(String sessionId) {
        SessionInfo sessionInfo = getSessionInfo(sessionId);
        if (sessionInfo != null) {
            sessionInfo.contentOfSession.put(ENGINE_SESSION_SEQ_ID,
                    engineSessionDao.save(new EngineSession(getUser(sessionId, false), sessionId, getSourceIp(sessionId))));
            setSessionStartTime(sessionId);
        }
    }

    public long getEngineSessionSeqId(String sessionId) {
        if (!sessionInfoMap.containsKey(sessionId)) {
            throw new RuntimeException("Session not found for sessionId " + sessionId);
        }
        return (Long) sessionInfoMap.get(sessionId).contentOfSession.get(ENGINE_SESSION_SEQ_ID);
    }

    public String getSessionIdBySeqId(long sessionSequenceId) {
        String sessionId = null;
        for (SessionInfo sessionInfo : sessionInfoMap.values()) {
            if (Long.valueOf(sessionSequenceId).equals(sessionInfo.contentOfSession.get(ENGINE_SESSION_SEQ_ID))) {
                sessionId = (String) sessionInfo.contentOfSession.get(ENGINE_SESSION_ID);
                break;
            }
        }
        return sessionId;
    }

    public String getSessionIdBySsoAccessToken(String ssoToken) {
        String sessionId = null;
        if (StringUtils.isNotEmpty(ssoToken)) {
            for (SessionInfo sessionInfo : sessionInfoMap.values()) {
                if (ssoToken.equals(sessionInfo.contentOfSession.get(SSO_ACCESS_TOKEN_PARAMETER_NAME))) {
                    sessionId = (String) sessionInfo.contentOfSession.get(ENGINE_SESSION_ID);
                    break;
                }
            }
        }
        return sessionId;
    }

    public void cleanupEngineSessionsOnStartup() {
        engineSessionDao.removeAll();
    }

    public void cleanupEngineSessionsForSsoAccessToken(String ssoAccessToken) {
        if (StringUtils.isNotEmpty(ssoAccessToken)) {
            Iterator<Entry<String, SessionInfo>> iter = sessionInfoMap.entrySet().iterator();
            while (iter.hasNext()) {
                Entry<String, SessionInfo> entry = iter.next();
                ConcurrentMap<String, Object> sessionMap = entry.getValue().contentOfSession;
                if (ssoAccessToken.equals(sessionMap.get(SSO_ACCESS_TOKEN_PARAMETER_NAME))) {
                    removeSessionImpl(entry.getKey(),
                            Acct.ReportReason.PRINCIPAL_SESSION_EXPIRED,
                            SessionEndReason.SINGLE_SIGN_ON_ENDED,
                            SINGLE_SIGN_ON_ENDED,
                            "Session has expired for principal %1$s",
                            getUserName(entry.getKey()));
                }
            }
        }
    }

    /**
     * Remove the cached data of current session
     *
     * @param sessionId
     *            - id of current session
     */
    public final void removeSessionOnLogout(String sessionId) {
        // No audit entry: a logout the user asked for is reported by USER_VDC_LOGOUT, and this
        // is the same event reaching its end rather than a second thing that happened.
        removeSessionImpl(sessionId,
                Acct.ReportReason.PRINCIPAL_LOGOUT,
                endReasonOf(sessionId, SessionEndReason.SIGNED_OUT),
                null,
                "Prinicial %1$s has performed logout",
                getUserName(sessionId));
    }

    /**
     * Will run the process of cleaning expired sessions.
     */
    public final void cleanExpiredUsersSessions() {
        try {
            cleanExpiredUsersSessionsImpl();
        } catch (Throwable t) {
            log.error("Exception in cleanExpiredUsersSessions: {}", ExceptionUtils.getRootCauseMessage(t));
            log.debug("Exception", t);
        }
    }

    public final void cleanExpiredUsersSessionsImpl() {
        Date now = new Date();
        pruneEndedSessions(now);
        Iterator<Entry<String, SessionInfo>>  iter = sessionInfoMap.entrySet().iterator();
        Set<String> tokens = sessionInfoMap.values().stream()
                .map(sessionInfo -> (String) sessionInfo.contentOfSession.get(SSO_ACCESS_TOKEN_PARAMETER_NAME))
                .collect(Collectors.toSet());
        // retrieve session statues from SSO
        Map<String, Boolean> sessionStatuses = ssoSessionValidator.getSessionStatuses(tokens);

        while (iter.hasNext()) {
            Entry<String, SessionInfo> entry = iter.next();
            ConcurrentMap<String, Object> sessionMap = entry.getValue().contentOfSession;
            Date hardLimit = (Date) sessionMap.get(HARD_LIMIT_PARAMETER_NAME);
            Date softLimit = (Date) sessionMap.get(SOFT_LIMIT_PARAMETER_NAME);
            String token = (String) sessionMap.get(SSO_ACCESS_TOKEN_PARAMETER_NAME);

            // What sso says about the token, when sso answered at all. A session whose status did
            // not come back is not torn down on that account: it may have been created after the
            // statuses were fetched, and it is looked at again on the next sweep.
            boolean statusKnown = sessionStatuses.containsKey(token);
            boolean ssoSessionAlive = statusKnown && Boolean.TRUE.equals(sessionStatuses.get(token));

            // A session still being built carries no validity flag yet - setSourceIp runs before
            // setUser - and is not a session to end. Reading it as a boolean threw there, and the
            // throw aborted the sweep for every session behind it.
            Object valid = sessionMap.get(SESSION_VALID_PARAMETER_NAME);
            boolean loggedOut = valid != null && !(boolean) valid;

            boolean pastItsLimit = hardLimit != null && hardLimit.before(now)
                    || softLimit != null && softLimit.before(now);

            // Whether a session has outlived its limits, and whether an administrator or the user
            // has ended it, are things this engine already knows. They used to be reached only for
            // a session whose sso status had come back, so a deployment where that call was
            // failing kept every session open: terminating one from the administration portal
            // wrote the audit entry and then nothing happened, however long one waited. Only the
            // remaining reason - that sso itself has ended the session - needs sso to have
            // answered.
            if (!pastItsLimit && !loggedOut && !(statusKnown && !ssoSessionAlive)) {
                continue;
            }

            removeSessionImpl(entry.getKey(),
                    Acct.ReportReason.PRINCIPAL_SESSION_EXPIRED,
                    endReason(entry.getKey(), hardLimit, softLimit, now, loggedOut),
                    releaseReason(hardLimit, softLimit, now, loggedOut),
                    "Session has expired for principal %1$s",
                    getUserName(entry.getKey()));
            if (ssoSessionAlive) {
                // the engine is done with it, so the token it was issued against goes too
                SsoOAuthServiceUtils.revoke(token, "");
            }
        }
    }

    /**
     * Sets the user for the given session Id
     * @param sessionId The session to set
     * @param user The user to set
     */
    public final void setUser(String sessionId, DbUser user) {
        setData(sessionId, USER_PARAMETER_NAME, user);
        setSessionValid(sessionId, true);
        persistEngineSession(sessionId);
    }

    public final void setSessionValid(String sessionId, boolean valid) {
        setData(sessionId, SESSION_VALID_PARAMETER_NAME, valid);
    }

    public final void setSessionStartTime(String sessionId) {
        setData(sessionId, SESSION_START_TIME, new Date());
    }

    public final Date getSessionStartTime(String sessionId) {
        return (Date) getData(sessionId, SESSION_START_TIME, false);
    }

    public final void updateSessionLastActiveTime(String sessionId) {
        if (isSessionExists(sessionId)) {
            setData(sessionId, SESSION_LAST_ACTIVE_TIME, new Date());
            refresh(sessionId);
        }
    }

    public final Date getSessionLastActiveTime(String sessionId) {
        return (Date) getData(sessionId, SESSION_LAST_ACTIVE_TIME, false);
    }

    public boolean getSessionValid(String sessionId, boolean refresh) {
        Object obj = getData(sessionId, SESSION_VALID_PARAMETER_NAME, refresh);
        return obj == null ? false : (boolean) obj;
    }

    /**
     * Records why a session is ending, so that the client holding it can be told.
     *
     * <p>Set this before the session is marked invalid or removed: everything that ends a session
     * goes on to do one of those, and once either has happened the reason can no longer be
     * attached to the session it belongs to.</p>
     */
    public final void setSessionEndReason(String sessionId, SessionEndReason reason) {
        // setData creates the session it is given when there is none, which is right for building
        // one up and wrong here: a reason for a session that no longer exists would conjure an
        // empty session carrying nothing but that reason.
        if (!isSessionExists(sessionId)) {
            return;
        }
        setData(sessionId, SESSION_END_REASON_PARAMETER_NAME, reason);
    }

    /**
     * Whether this session has been ended but not yet removed.
     *
     * <p>Ending a session marks it and leaves the removal to the sweep, so for up to a minute an
     * ended session is still in the map. It is not a session anything may act on, and asking this
     * is how the difference is told.</p>
     *
     * <p>A missing flag is not an ended session: it is a session still being built, since
     * {@code setSourceIp} runs before {@code setUser}. Only an explicit false means ended.</p>
     */
    public final boolean isSessionEnded(String sessionId) {
        Object valid = getData(sessionId, SESSION_VALID_PARAMETER_NAME, false);
        return valid != null && !(boolean) valid;
    }

    /**
     * @return why the session named is no longer usable, or null while it still is. A session this
     *         engine has no record of - never seen, or ended longer ago than the reason is kept -
     *         answers {@link SessionEndReason#NO_SESSION}.
     */
    public final SessionEndReason getSessionEndReason(String sessionId) {
        if (StringUtils.isEmpty(sessionId)) {
            return SessionEndReason.NO_SESSION;
        }
        if (isSessionExists(sessionId)) {
            if (!isSessionEnded(sessionId)) {
                return null;
            }
            SessionEndReason recorded =
                    (SessionEndReason) getData(sessionId, SESSION_END_REASON_PARAMETER_NAME, false);
            // Nothing named a reason, and the one thing that ends a session without naming one is
            // the user logging out: LogoutSession is reached both from the logout the user asked
            // for and from the administrator terminating the session, and only the latter says so.
            return recorded == null ? SessionEndReason.SIGNED_OUT : recorded;
        }
        EndedSession ended = endedSessions.get(sessionId);
        return ended == null ? SessionEndReason.NO_SESSION : ended.reason;
    }

    /**
     * Discards the reasons that have been kept for longer than they are useful, and, if sessions
     * are ending faster than that limit alone can contain, the oldest of what is left.
     */
    private void pruneEndedSessions(Date now) {
        Date keepFrom = DateUtils.addMinutes(now, -ENDED_SESSION_RECORD_MINUTES);
        endedSessions.values().removeIf(ended -> ended.endedAt.before(keepFrom));

        int excess = endedSessions.size() - ENDED_SESSION_RECORD_LIMIT;
        if (excess > 0) {
            endedSessions.entrySet().stream()
                    .sorted(Comparator.comparing(
                            (Entry<String, EndedSession> entry) -> entry.getValue().endedAt))
                    .limit(excess)
                    .map(Entry::getKey)
                    .collect(Collectors.toList())
                    .forEach(endedSessions::remove);
        }
    }

    public final void setHardLimit(String sessionId, Date hardLimit) {
        setData(sessionId, HARD_LIMIT_PARAMETER_NAME, hardLimit);
    }

    public final void setSoftLimit(String sessionId, Date softLimit) {
        setData(sessionId, SOFT_LIMIT_PARAMETER_NAME, softLimit);
    }

    /**
     * Sets how long the session may stay idle before it expires, never beyond what
     * {@code UserSessionTimeOutInterval} allows.
     *
     * @return the interval actually applied, which is the requested one when it is within the
     *         configured timeout and the configured timeout otherwise
     */
    public final int setSoftLimitInterval(String sessionId, int softLimitInterval) {
        int effective = withinConfiguredSoftLimit(softLimitInterval);
        setData(sessionId, SOFT_LIMIT_INTERVAL_PARAMETER_NAME, effective);
        return effective;
    }

    /**
     * @return how long this session may stay idle, in minutes. Every session is given
     *         {@code UserSessionTimeOutInterval} when it is created, so this is that timeout
     *         unless the session asked for a shorter one. A caller that has to time something of
     *         its own out alongside the session - the REST API's HTTP session does - reads it
     *         here rather than deciding for itself.
     */
    public final int getSoftLimitInterval(String sessionId) {
        Integer recorded = (Integer) getData(sessionId, SOFT_LIMIT_INTERVAL_PARAMETER_NAME, false);
        int configured = Config.<Integer> getValue(ConfigValues.UserSessionTimeOutInterval);
        // A timeout shortened since the session was created applies to it too, which is what the
        // capping is for; a session with nothing recorded answers to the configured timeout.
        return recorded == null ? configured : withinConfiguredSoftLimit(recorded);
    }

    /**
     * Caps an idle timeout at {@code UserSessionTimeOutInterval}.
     *
     * <p>The configured timeout is the security policy for how long a session may stay idle, so a
     * caller that asks for longer - the {@code Session-TTL} header of the REST API is the one that
     * can - gets the configured timeout instead. Only longer is capped: a caller asking for a
     * shorter timeout is asking for less exposure, not more, and keeps what it asked for.</p>
     *
     * <p>A configured timeout of zero or less means no timeout is in force, so there is nothing to
     * cap against and the requested interval stands.</p>
     */
    public static int withinConfiguredSoftLimit(int softLimitInterval) {
        int configured = Config.<Integer> getValue(ConfigValues.UserSessionTimeOutInterval);
        return configured > 0 && softLimitInterval > configured ? configured : softLimitInterval;
    }

    /**
     * @param sessionId The session to get the user for
     * @param refresh Whether refreshing the session is needed
     * @return The user set for the given {@link #session}
     */
    public DbUser getUser(String sessionId, boolean refresh) {
        return (DbUser) getData(sessionId, USER_PARAMETER_NAME, refresh);
    }

    public long getNumUserSessions(DbUser user) {
        return sessionInfoMap.keySet()
                .stream()
                .filter(sessionId -> getUser(sessionId, false).getId().equals(user.getId()))
                .filter(sessionId -> getSessionValid(sessionId, false))
                .count();
    }

    public void refresh(String sessionId) {
        refresh(getSessionInfo(sessionId));
    }

    public void setProfile(String sessionId, AuthenticationProfile profile) {
        setData(sessionId, PROFILE_PARAMETER_NAME, profile);
    }

    public AuthenticationProfile getProfile(String sessionId) {
        AuthenticationProfile profile = (AuthenticationProfile) getData(sessionId, PROFILE_PARAMETER_NAME, false);
        if (profile == null) {
            profile = getProfileFromUser(getUser(sessionId, false));
        }
        return profile;
    }

    private AuthenticationProfile getProfileFromUser(DbUser user) {
        AuthenticationProfile retVal = null;
        if (user != null) {
            for (AuthenticationProfile profile : AuthenticationProfileRepository.getInstance().getProfiles()) {
                if (profile.getAuthzName().equals(user.getDomain())) {
                    retVal = profile;
                    break;
                }
            }
        }
        return retVal;
    }

    public String getPrincipalName(String sessionId) {
        return (String) getData(sessionId, PRINCIPAL_PARAMETER_NAME, false);
    }

    public String getUserName(String sessionId) {
        return String.format(
                "%s@%s",
                getPrincipalName(sessionId),
                getProfile(sessionId) != null ? getProfile(sessionId).getAuthzName() : "N/A");
    }

    public void setPrincipalName(String engineSessionId, String name) {
        setData(engineSessionId, PRINCIPAL_PARAMETER_NAME, name);
    }

    public void setSsoAccessToken(String engineSessionId, String ssoToken) {
        setData(engineSessionId, SSO_ACCESS_TOKEN_PARAMETER_NAME, ssoToken);
    }

    public String getSsoAccessToken(String engineSessionId) {
        return (String) getData(engineSessionId, SSO_ACCESS_TOKEN_PARAMETER_NAME, false);
    }

    public String getSsoAccessToken(String engineSessionId, boolean mustBeValid) {
        String ssoToken = getSsoAccessToken(engineSessionId);
        if (StringUtils.isNotEmpty(ssoToken) && mustBeValid) {
            ssoToken = getSessionValid(engineSessionId, false) ? ssoToken : null;
        }
        return ssoToken;
    }

    public void setSsoOvirtAppApiScope(String engineSessionId, String scope) {
        List<String> scopes = StringUtils.isEmpty(scope) ?
                Collections.emptyList() :
                Arrays.asList(scope.trim().split("\\s *"));
        setData(engineSessionId, SSO_IS_OVIRT_APP_API_SCOPE_PARAMETER_NAME,
                scopes.contains(OVIRT_APP_API_SCOPE) &&
                        !scopes.contains(OVIRT_APP_ADMIN_SCOPE) &&
                        !scopes.contains(OVIRT_APP_PORTAL_SCOPE));
    }

    public boolean isSsoOvirtAppApiScope(String engineSessionId) {
        return isSessionExists(engineSessionId) ?
                (boolean) getData(engineSessionId, SSO_IS_OVIRT_APP_API_SCOPE_PARAMETER_NAME, false):
                false;
    }

    public void setSourceIp(String engineSessionId, String sourceIp) {
        setData(engineSessionId, SOURCE_IP, sourceIp);
    }

    public String getSourceIp(String engineSessionId) {
        return (String) getData(engineSessionId, SOURCE_IP, false);
    }

    private void refresh(SessionInfo sessionInfo) {
        // the interval was recorded when the session was created, so a timeout shortened since then
        // has to be applied here as well - otherwise the sessions already open would keep the older,
        // longer timeout until each of them ends
        Integer recorded = (Integer) sessionInfo.contentOfSession.get(SOFT_LIMIT_INTERVAL_PARAMETER_NAME);
        int softLimitValue = withinConfiguredSoftLimit(recorded);
        if (softLimitValue > 0) {
            sessionInfo.contentOfSession.put(SOFT_LIMIT_PARAMETER_NAME,
                    DateUtils.addMinutes(new Date(), softLimitValue));
        }
    }

    public boolean isSessionExists(String sessionId) {
        return StringUtils.isEmpty(sessionId) ? false : sessionInfoMap.containsKey(sessionId);
    }

    /** Reported when the single sign-on service, rather than this engine, ended the session. */
    private static final String SINGLE_SIGN_ON_ENDED = "the single sign-on session ended"; //$NON-NLS-1$

    /** Stands in for a detail the session no longer carries by the time it is released. */
    private static final String UNKNOWN = "UNKNOWN"; //$NON-NLS-1$

    /**
     * @return why the session is being released, in words, or null when it is the tail of a logout
     *         the user performed - USER_VDC_LOGOUT already reports that and a second entry would
     *         say nothing more
     */
    private static String releaseReason(Date hardLimit, Date softLimit, Date now, boolean loggedOut) {
        if (hardLimit != null && hardLimit.before(now)) {
            return "it reached the end of its allowed lifetime"; //$NON-NLS-1$
        }
        if (softLimit != null && softLimit.before(now)) {
            return "it was idle longer than the configured session timeout"; //$NON-NLS-1$
        }
        if (loggedOut) {
            return null;
        }
        // nothing this engine holds ended it, so the sweep is acting on what sso reported
        return SINGLE_SIGN_ON_ENDED;
    }

    /** @return the reason recorded on the session, or {@code fallback} when nothing recorded one. */
    private SessionEndReason endReasonOf(String sessionId, SessionEndReason fallback) {
        SessionEndReason recorded =
                (SessionEndReason) getData(sessionId, SESSION_END_REASON_PARAMETER_NAME, false);
        return recorded == null ? fallback : recorded;
    }

    /**
     * @return why the session ended, in the terms its client is told.
     *
     *         <p>This asks the same question as {@link #releaseReason} and answers it in a
     *         different order, because the two are read by different people. The audit entry says
     *         what happened to a session, so it leads with the limit that ran out. The client says
     *         what happened to the person using it, and "an administrator ended your session" is
     *         what they need to hear even if a limit had quietly run out first - it is the
     *         deliberate act, and the one they may need to ask somebody about.</p>
     */
    private SessionEndReason endReason(String sessionId, Date hardLimit, Date softLimit, Date now,
            boolean loggedOut) {
        if (loggedOut) {
            return endReasonOf(sessionId, SessionEndReason.SIGNED_OUT);
        }
        if (hardLimit != null && hardLimit.before(now)) {
            return SessionEndReason.MAX_DURATION;
        }
        if (softLimit != null && softLimit.before(now)) {
            return SessionEndReason.IDLE_TIMEOUT;
        }
        return SessionEndReason.SINGLE_SIGN_ON_ENDED;
    }

    /**
     * Records in the audit log that a session ended without its user asking it to.
     *
     * <p>Sessions were released silently: the removal was reported to the accounting extension,
     * which an administrator reading the engine's audit log never sees. An idle session timing
     * out, a session reaching the end of its life, and a single sign-on session being ended
     * elsewhere all left the same gap in the record - a user with an open session, and then no
     * user, with nothing in between.</p>
     *
     * <p>The session's sequence number identifies it here rather than its id. The id is the
     * credential a REST client presents to continue the session, and the audit log is readable by
     * anyone who can read the audit log; the sequence number names the same row of
     * {@code engine_sessions} without being usable as a key to it.</p>
     */
    private void auditSessionReleased(String sessionId, String releaseReason) {
        if (releaseReason == null) {
            return;
        }
        try {
            AuditLogable event = new AuditLogableImpl();
            DbUser user = getUser(sessionId, false);
            if (user != null) {
                event.setUserId(user.getId());
                event.setUserName(user.getLoginName() + "@" + user.getDomain()); //$NON-NLS-1$
            }
            Object sequenceId = getSessionInfo(sessionId) == null
                    ? null
                    : getSessionInfo(sessionId).contentOfSession.get(ENGINE_SESSION_SEQ_ID);
            event.addCustomValue("SessionID", sequenceId == null ? UNKNOWN : String.valueOf(sequenceId)); //$NON-NLS-1$
            String sourceIp = getSourceIp(sessionId);
            event.addCustomValue("SourceIP", StringUtils.isEmpty(sourceIp) ? UNKNOWN : sourceIp); //$NON-NLS-1$
            event.addCustomValue("ReleaseReason", releaseReason); //$NON-NLS-1$
            auditLogDirector.log(event, AuditLogType.USER_VDC_SESSION_RELEASED);
        } catch (RuntimeException e) {
            // Failing to write the record must not leave the session in place; it is the session
            // that is being released, and the release is the thing that has to happen.
            log.error("Unable to audit the release of a session: {}", e.getMessage());
            log.debug("Exception", e);
        }
    }

    private void removeSessionImpl(String sessionId, int reason, SessionEndReason endReason,
            String releaseReason, String message, Object... msgArgs) {

        // Only remove session if there are no running commands for this session
        if (ssoSessionUtils.isSessionInUse(getEngineSessionSeqId(sessionId))) {
            DbUser dbUser = getUser(sessionId, false);
            log.info("Not removing session '{}', session has running commands{}",
                    sessionId,
                    dbUser == null ? "." : String.format(" for user '%s@%s'.", dbUser.getLoginName(), dbUser.getDomain()));
            return;
        }

        /*
         * So we won't need to add profile to tests
         */
        String authzName = null;
        if (getProfile(sessionId) != null) {
            authzName = getProfile(sessionId).getAuthzName();
        }

        AcctUtils.reportRecords(reason,
                authzName,
                getPrincipalName(sessionId),
                message,
                msgArgs
                );
        auditSessionReleased(sessionId, releaseReason);

        engineSessionDao.remove(getEngineSessionSeqId(sessionId));

        // Recorded before the session goes rather than after, so that there is no instant in which
        // neither the session nor the record can say what happened. Why it went is what its client
        // still has to be told. See endedSessions.
        endedSessions.put(sessionId, new EndedSession(endReason, new Date()));
        sessionInfoMap.remove(sessionId);
    }

    class SsoSessionValidator {
        /**
         * @return what single sign-on says about each token, empty when it did not say. An empty
         *         answer used to be silent unless the call threw: single sign-on replying with an
         *         error is a reply, not an exception, and that branch said nothing at all. The
         *         sweep then had no status for any session and, until this was separated from the
         *         reasons the engine decides on its own, quietly stopped ending sessions entirely
         *         - so the one thing that would have explained it was the one thing not logged.
         */
        public Map<String, Boolean> getSessionStatuses(Set<String> tokens) {
            Map<String, Boolean> sessionStatuses = Collections.emptyMap();
            if (!tokens.isEmpty()) {
                try {
                    Map<String, Object> response = SsoOAuthServiceUtils.getSessionStatues(tokens);
                    Object error = response.get("error");
                    if (error != null) {
                        log.error("Single sign-on refused to report session statuses: {}. Sessions it"
                                + " alone knows about will not be ended until it answers again.", error);
                    } else {
                        Map<String, Boolean> result = (Map<String, Boolean>) response.get("result");
                        if (result == null) {
                            log.error("Single sign-on reported no session statuses and no error."
                                    + " Sessions it alone knows about will not be ended this time.");
                        } else {
                            sessionStatuses = result;
                        }
                    }
                } catch (Exception e) {
                    log.error("Unable to retrieve session statuses." + e.getMessage());
                }
            }
            return sessionStatuses;
        }
    }
}
