

-- Password history of a user, used to enforce the password reuse policies.
-- v_principal is the normalized 'name@realm' key, see PasswordHistoryCryptor.principalKey().

CREATE OR REPLACE FUNCTION InsertUserPasswordHistory (
    v_principal VARCHAR(510),
    v_password_hash TEXT,
    v_change_date TIMESTAMP WITH TIME ZONE
    )
RETURNS VOID AS $FUNCTION$
BEGIN
    INSERT INTO user_password_history (
        principal,
        password_hash,
        change_date
        )
    VALUES (
        v_principal,
        v_password_hash,
        v_change_date
        );
END;$FUNCTION$
LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION GetUserPasswordHistoryByPrincipal (
    v_principal VARCHAR(510),
    v_limit INT
    )
RETURNS SETOF user_password_history STABLE AS $FUNCTION$
BEGIN
    RETURN QUERY

    SELECT *
    FROM user_password_history
    WHERE principal = v_principal
    ORDER BY change_date DESC LIMIT v_limit;
END;$FUNCTION$
LANGUAGE plpgsql;

-- Drops the entries that can no longer make a difference: older than the reuse window and
-- not among the v_keep most recent ones, which are needed by the "previous password" check.
CREATE OR REPLACE FUNCTION CleanupUserPasswordHistory (
    v_principal VARCHAR(510),
    v_threshold TIMESTAMP WITH TIME ZONE,
    v_keep INT
    )
RETURNS VOID AS $FUNCTION$
BEGIN
    DELETE FROM user_password_history
    WHERE principal = v_principal
        AND change_date < v_threshold
        AND id NOT IN (
            SELECT id
            FROM user_password_history
            WHERE principal = v_principal
            ORDER BY change_date DESC LIMIT v_keep
            );
END;$FUNCTION$
LANGUAGE plpgsql;
