package org.ovirt.engine.core.common.businessentities.aaa;

import java.io.Serializable;
import java.util.Date;
import java.util.Objects;

/**
 * One password a user has used in the past, kept as a salted hash so that the password
 * reuse policies can be enforced.
 */
public class UserPasswordHistoryEntry implements Serializable {

    private static final long serialVersionUID = 6151806229304913911L;

    private long id;
    private String principal;
    private String passwordHash;
    private Date changeDate;

    public UserPasswordHistoryEntry() {
    }

    public UserPasswordHistoryEntry(String principal, String passwordHash, Date changeDate) {
        this.principal = principal;
        this.passwordHash = passwordHash;
        this.changeDate = changeDate;
    }

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getPrincipal() {
        return principal;
    }

    public void setPrincipal(String principal) {
        this.principal = principal;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    public Date getChangeDate() {
        return changeDate;
    }

    public void setChangeDate(Date changeDate) {
        this.changeDate = changeDate;
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, principal, changeDate);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof UserPasswordHistoryEntry)) {
            return false;
        }
        UserPasswordHistoryEntry other = (UserPasswordHistoryEntry) obj;
        return id == other.id
                && Objects.equals(principal, other.principal)
                && Objects.equals(passwordHash, other.passwordHash)
                && Objects.equals(changeDate, other.changeDate);
    }
}
