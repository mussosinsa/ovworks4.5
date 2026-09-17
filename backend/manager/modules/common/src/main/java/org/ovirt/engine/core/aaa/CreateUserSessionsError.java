package org.ovirt.engine.core.aaa;

public enum CreateUserSessionsError {
    /**
     * User is not authorized to login
     */
    USER_NOT_AUTHORIZED,

    /**
     * Maximum number of sessions exceeded
     */
    NUM_OF_SESSIONS_EXCEEDED,

    /**
     * Another super user is logged in.
     *
     * <p>Only one of the accounts that hold the super-user role may be logged in at a time, so a
     * second one is refused for as long as the first holds a session.</p>
     */
    SUPER_USER_SESSION_ACTIVE;
}
