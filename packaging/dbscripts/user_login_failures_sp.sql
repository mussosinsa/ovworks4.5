

-- Failed password attempts per account. The engine records them from the SSO login path, which
-- writes the table directly; what is needed here is the other end of it - lifting a lock on
-- request, which is done from the user list.

-- Lifts the lock an administrator sees in the user list.
-- The lock is filed under 'name@profile', and the user list knows the login name rather than the
-- profile the account authenticates with, so every profile carrying that name is cleared. Both
-- v_login_name and the stored column are lowercase.

CREATE OR REPLACE FUNCTION ClearUserLoginFailuresByLoginName (
    v_login_name VARCHAR(255)
    )
RETURNS VOID AS $FUNCTION$
BEGIN
    DELETE FROM user_login_failures
    WHERE login_name = v_login_name;
END;$FUNCTION$
LANGUAGE plpgsql;

-- Releases every lock whose time has run out, and names the accounts it released so that the
-- release can be recorded in the audit log at the moment it happens rather than whenever the
-- account next tries to log in. The rows are deleted and returned in the one statement, so a
-- lock is released - and therefore reported - exactly once however many callers are running.

CREATE OR REPLACE FUNCTION ReleaseExpiredUserLoginFailures (
    v_now TIMESTAMP WITH TIME ZONE
    )
RETURNS TABLE (released_principal VARCHAR(510)) AS $FUNCTION$
BEGIN
    RETURN QUERY

    DELETE FROM user_login_failures
    WHERE locked_until IS NOT NULL
        AND locked_until <= v_now
    RETURNING principal;
END;$FUNCTION$
LANGUAGE plpgsql;
