select fn_db_add_config_value('ENGINE_AUDIT_LOG_MAX_SIZE_MB', '1024', 'general');
select fn_db_add_config_value('ENGINE_AUDIT_LOG_CAPACITY_CHECK_INTERVAL_SECONDS', '60', 'general');
select fn_db_add_config_value('ENGINE_AUDIT_LOG_DIR', '/var/log/ovirt-engine', 'general');
