-- Stop requiring a regular user to change an administratively assigned password on the
-- first login. The bootstrap administrator is unaffected: its initial password is always
-- stored expired, whatever this option says.
select fn_db_update_config_value('PasswordPolicyForceChangeOnFirstLogin', 'false', 'general');
select fn_db_add_config_value('PasswordPolicyForceChangeOnFirstLogin', 'false', 'general');
