-- Lock an ordinary account after repeated password failures, the way the protected administrator
-- already is, and let the lock expire on its own after the configured number of minutes.
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

--#source user_login_failures_sp.sql
