-- Password history used by the "previous password" and "reused within N months" policies.
-- The principal is the normalized 'name@realm' key so that a password set through the
-- administrative reset and one set through the interactive change share a single history.
CREATE TABLE IF NOT EXISTS user_password_history (
    id BIGSERIAL,
    principal VARCHAR(510) NOT NULL,
    password_hash TEXT NOT NULL,
    change_date TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    CONSTRAINT pk_user_password_history PRIMARY KEY (id)
);

CREATE INDEX IF NOT EXISTS idx_user_password_history_principal
    ON user_password_history USING btree (principal, change_date DESC);

-- Mandatory policy
select fn_db_add_config_value('PasswordPolicyMinLength','12','general');
select fn_db_add_config_value('PasswordPolicyRequireUppercase','true','general');
select fn_db_add_config_value('PasswordPolicyRequireLowercase','true','general');
select fn_db_add_config_value('PasswordPolicyRequireDigit','true','general');
select fn_db_add_config_value('PasswordPolicyRequireSpecial','true','general');
select fn_db_add_config_value('PasswordPolicyForbidSameAsUserId','true','general');

-- Optional policy, each one may be switched off independently
select fn_db_add_config_value('PasswordPolicyForbidRepeatedCharacters','true','general');
select fn_db_add_config_value('PasswordPolicyRepeatLimit','3','general');
select fn_db_add_config_value('PasswordPolicyForbidSequentialCharacters','true','general');
select fn_db_add_config_value('PasswordPolicySequenceLength','4','general');
select fn_db_add_config_value('PasswordPolicyForbidPreviousPassword','true','general');
select fn_db_add_config_value('PasswordPolicyForbidReuseWithinPeriod','true','general');
select fn_db_add_config_value('PasswordPolicyReuseHistoryMonths','3','general');

-- Force the password change on the first login after the password was set by somebody else
select fn_db_add_config_value('PasswordPolicyForceChangeOnFirstLogin','true','general');
