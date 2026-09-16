package org.ovirt.engine.core.bll.aaa;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.annotation.PostConstruct;
import javax.enterprise.concurrent.ManagedScheduledExecutorService;
import javax.inject.Inject;
import javax.inject.Singleton;

import org.apache.commons.lang.exception.ExceptionUtils;
import org.ovirt.engine.core.common.AuditLogType;
import org.ovirt.engine.core.common.BackendService;
import org.ovirt.engine.core.dal.dbbroker.auditloghandling.AuditLogDirector;
import org.ovirt.engine.core.dal.dbbroker.auditloghandling.AuditLogable;
import org.ovirt.engine.core.dal.dbbroker.auditloghandling.AuditLogableImpl;
import org.ovirt.engine.core.dao.UserLoginFailuresDao;
import org.ovirt.engine.core.utils.threadpool.ThreadPools;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Releases a locked account when its lock period runs out, and records that it did.
 *
 * <p>The login path releases a lock as well, but only when the account comes back: an account
 * nobody tries to log in to again stays locked in the table, and the audit log shows the lock with
 * nothing after it. That is not what the policy says happens - the lock lifts after
 * {@code ENGINE_SSO_USER_LOCK_MINUTES}, whether or not anybody is watching - so the release is
 * made to happen on its own here, at the time it is due, with the audit event that says so.</p>
 *
 * <p>Only accounts whose locks are written down are released here, which is every account other
 * than the protected administrator: that one's lock is held in the SSO process's memory and lifts
 * on its next login attempt.</p>
 */
@Singleton
public class UserLoginLockoutExpiryManager implements BackendService {

    private static final Logger log = LoggerFactory.getLogger(UserLoginLockoutExpiryManager.class);

    /**
     * How often expired locks are looked for.
     *
     * <p>A minute, against a shortest possible lock of five: near enough that the audit log reads
     * as the release having happened when it was due, and seldom enough to be one indexed delete
     * against a table holding a row per account that has recently failed to log in.</p>
     */
    private static final long CHECK_INTERVAL_SECONDS = 60;

    @Inject
    @ThreadPools(ThreadPools.ThreadPoolType.EngineScheduledThreadPool)
    private ManagedScheduledExecutorService executor;

    @Inject
    private UserLoginFailuresDao userLoginFailuresDao;

    @Inject
    private AuditLogDirector auditLogDirector;

    @PostConstruct
    private void init() {
        log.info("Start initializing {}", getClass().getSimpleName());
        executor.scheduleWithFixedDelay(this::releaseExpiredLocks,
                CHECK_INTERVAL_SECONDS,
                CHECK_INTERVAL_SECONDS,
                TimeUnit.SECONDS);
        log.info("Finished initializing {}", getClass().getSimpleName());
    }

    void releaseExpiredLocks() {
        try {
            Instant now = Instant.now();
            List<String> released = userLoginFailuresDao.releaseExpired(Date.from(now));
            for (String principal : released) {
                log.info("사용자 계정 잠금 자동 해제; target='{}'; unlockAt='{}'", principal, now);
                auditLogDirector.log(unlockEvent(principal, now), AuditLogType.USER_ACCOUNT_AUTO_UNLOCKED);
            }
        } catch (Throwable t) {
            // The next run tries again, and a lock left in place expires no later than it would
            // have; losing the release must not take the scheduled task down with it.
            log.error("Exception in releasing expired account locks: {}", ExceptionUtils.getRootCauseMessage(t));
            log.debug("Exception", t);
        }
    }

    /**
     * The audit record of one release, worded as the login path words the one it writes so that
     * the two read alike however the lock came to be lifted.
     */
    static AuditLogable unlockEvent(String principal, Instant unlockAt) {
        AuditLogable event = new AuditLogableImpl();
        event.setUserName(principal);
        event.addCustomValue("LoginErrMsg", String.format(" : 'USER_ACCOUNT_UNLOCKED user=%s unlockAt=%s'", //$NON-NLS-1$
                principal, unlockAt));
        return event;
    }
}
