package org.ovirt.engine.core.common.businessentities.aaa;

/**
 * Why a session is no longer usable, told to the client whose session it was.
 *
 * <p>A client that is put back at its login screen has to say why, and the two answers a user acts
 * on differently are these: an administrator ended the session, so logging back in is expected to
 * work and somebody decided it should be interrupted; or the session timed out, so nothing is
 * wrong and logging back in is all there is to do. Reporting one as the other is worse than
 * reporting neither, so the engine says which it was rather than leaving the client to guess from
 * how long it has been idle.</p>
 *
 * <p>Each constant carries the token that goes on the wire. It is what the client matches on, so
 * it is written out here rather than derived from the constant's name: renaming a constant should
 * not silently change what clients see.</p>
 */
public enum SessionEndReason {

    /** An administrator ended it from the administration portal. */
    TERMINATED_BY_ADMIN("terminated-by-admin"),

    /** It was idle for longer than the session timeout allows. */
    IDLE_TIMEOUT("idle-timeout"),

    /** It reached the end of its allowed lifetime, however active it was. */
    MAX_DURATION("max-duration"),

    /** The user logged out, from this client or another holding the same session. */
    SIGNED_OUT("signed-out"),

    /** Single sign-on ended the session, so everything holding that token is now logged out. */
    SINGLE_SIGN_ON_ENDED("single-sign-on-ended"),

    /**
     * There is no session and no record of one ending. A client that never logged in gets this,
     * and so does one whose session ended so long ago that the record of it has been discarded.
     */
    NO_SESSION("no-session"),

    /**
     * The session is gone and the engine cannot say why. Kept distinct from {@link #NO_SESSION} so
     * that "we do not know" is never reported as one of the specific answers.
     */
    UNKNOWN("unknown");

    private final String wireName;

    SessionEndReason(String wireName) {
        this.wireName = wireName;
    }

    /** @return the token clients match on. */
    public String getWireName() {
        return wireName;
    }
}
