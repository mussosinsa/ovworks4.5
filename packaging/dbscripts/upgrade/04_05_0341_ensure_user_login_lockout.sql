--#source user_login_failures_sp.sql
-- Repair installations that never got the account lockout schema.
--
-- 04_05_0329 carries it, and an upgrade skips any script whose version is at or below the one
-- the database is already at, so a database that had passed 0329 by the time that script
-- existed never ran it - and the engine calls functions that are not there, once a minute,
-- for ever. Everything here is written to be a no-op where 0329 did run.
CREATE TABLE IF NOT EXISTS user_login_failures (
    principal VARCHAR(510) NOT NULL,
    login_name VARCHAR(255) NOT NULL,
    failure_count INTEGER DEFAULT 0 NOT NULL,
    last_failure_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    locked_until TIMESTAMP WITH TIME ZONE,
    CONSTRAINT pk_user_login_failures PRIMARY KEY (principal)
);

CREATE INDEX IF NOT EXISTS idx_user_login_failures_login_name
    ON user_login_failures USING btree (login_name);

select fn_db_add_config_value('ENGINE_SSO_USER_LOCK_MAX_FAILURES','5','general');
select fn_db_add_config_value('ENGINE_SSO_USER_LOCK_MINUTES','5','general');
