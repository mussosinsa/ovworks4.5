-- Repair installations whose clean-install schema did not contain the password history table.
CREATE TABLE IF NOT EXISTS user_password_history (
    id BIGSERIAL,
    principal VARCHAR(510) NOT NULL,
    password_hash TEXT NOT NULL,
    change_date TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    CONSTRAINT pk_user_password_history PRIMARY KEY (id)
);

CREATE INDEX IF NOT EXISTS idx_user_password_history_principal
    ON user_password_history USING btree (principal, change_date DESC);

--#source user_password_history_sp.sql
