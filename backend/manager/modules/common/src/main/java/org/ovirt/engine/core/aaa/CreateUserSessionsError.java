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
    SUPER_USER_SESSION_ACTIVE,

    /**
     * The request did not come from the user's dedicated login IP.
     *
     * <p>An internal user may be restricted to a single login address. A login from any other
     * address - or, for a non-admin internal user, with no dedicated address registered at all -
     * is refused and recorded.</p>
     */
    LOGIN_IP_NOT_ALLOWED,

    /**
     * The request did not carry the terminal serial the user logs in with: config.json's for an
     * administrator, the user's own for anyone else.
     */
    CLIENT_SERIAL_NOT_ALLOWED;
}
