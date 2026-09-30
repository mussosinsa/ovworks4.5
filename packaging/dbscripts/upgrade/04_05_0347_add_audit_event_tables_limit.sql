-- How much room the audit records may take in the engine database, and what is done when they
-- reach it.
--
-- The limit is on the live data of the event tables (audit_log, event_map,
-- event_notification_hist, event_subscriber); 0 switches it off. Reaching it raises the audit
-- storage events and, while the purge is enabled, archives and removes the oldest audit records
-- until the tables are back at the target share of the limit. Records younger than the minimum
-- retention are never removed. Removed records are written to the archive directory first.
select fn_db_add_config_value('ENGINE_AUDIT_EVENT_TABLES_MAX_SIZE_MB', '10240', 'general');
select fn_db_add_config_value('ENGINE_AUDIT_CAPACITY_PURGE_ENABLED', 'true', 'general');
select fn_db_add_config_value('ENGINE_AUDIT_CAPACITY_PURGE_MIN_RETENTION_DAYS', '30', 'general');
select fn_db_add_config_value('ENGINE_AUDIT_CAPACITY_PURGE_TARGET_PERCENT', '80', 'general');
select fn_db_add_config_value('ENGINE_AUDIT_PURGE_ARCHIVE_DIR', '/var/lib/ovirt-engine-backup/audit-log-purged', 'general');

-- Audit records are kept for 90 days rather than 30 before the daily cleanup removes them. An
-- installation that had changed the value keeps its own.
select fn_db_update_default_config_value('AuditLogAgingThreshold', '30', '90', 'general', false);
