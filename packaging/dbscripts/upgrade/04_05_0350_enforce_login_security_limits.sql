select fn_db_update_config_value('UserSessionTimeOutInterval', '10', 'general');
select fn_db_update_config_value('ENGINE_SSO_ADMIN_LOCK_MAX_FAILURES', '5', 'general');
select fn_db_delete_config_value_all_versions('ENGINE_SSO_ADMIN_LOCK_HOURS');
select fn_db_add_config_value('ENGINE_SSO_ADMIN_LOCK_MINUTES', '5', 'general');
