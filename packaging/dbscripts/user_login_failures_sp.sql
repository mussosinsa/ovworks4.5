

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
