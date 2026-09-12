package org.ovirt.engine.core.common.businessentities;

import java.util.Date;
import java.util.Objects;

import org.ovirt.engine.core.compat.Guid;

public class UserSession implements Queryable {

    private long id;
    private String userName;
    private Guid userId;
    private String sourceIp;
    private String authzName;
    private Date sessionStartTime;
    private Date sessionLastActiveTime;

    public UserSession(EngineSession engineSession) {
        Objects.requireNonNull(engineSession, "engineSession cannot be null");

        id = engineSession.getId();
        userName = engineSession.getUserName();
        userId = engineSession.getUserId();
        sourceIp = engineSession.getSourceIp();
        authzName = engineSession.getAuthzName();
        sessionStartTime = engineSession.getStartTime();
        sessionLastActiveTime = engineSession.getLastActiveTime();
    }

    private UserSession() {
    }

    public long getId() {
        return id;
    }

    @Override
    public Object getQueryableId() {
        return getId();
    }

    public Guid getUserId() {
        return userId;
    }

    public String getUserName() {
        return userName;
    }

    /**
     * @return the user named the way a person reads and writes it - the login name and the
     *         authorization provider that knows it, as in {@code admin@internal-authz}.
     *
     *         <p>This is the spelling the engine already uses whenever it names a user in plain
     *         text, in the audit log entry for a terminated session among others, so a session in
     *         the list and the record of it ending name the same user the same way.</p>
     *
     *         <p>It is not {@link #getUserId()}. That is an identifier the engine assigned for its
     *         own use, which is exactly what it says on {@code EngineSession.getUserId()}, and it
     *         means nothing to the administrator reading the list or to anything outside this
     *         engine.</p>
     */
    public String getPrincipalName() {
        if (userName == null) {
            return authzName == null ? "" : authzName;
        }
        return authzName == null ? userName : userName + "@" + authzName;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public String getAuthzName() {
        return authzName;
    }

    public Date getSessionStartTime() {
        return sessionStartTime;
    }

    public Date getSessionLastActiveTime() {
        return sessionLastActiveTime;
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (other == null || getClass() != other.getClass()) {
            return false;
        }
        final UserSession that = (UserSession) other;
        return Objects.equals(this.id, that.id);
    }
}
