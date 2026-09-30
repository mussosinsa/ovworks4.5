-- Where the audit records are stored, and at which usage the storage is reported.
--
-- The thresholds are four ascending percentages - notice, warning, high, critical - applied to the
-- file system of the engine database, its WAL, the log file system and the backup storage. A
-- storage that is full (100%) is always reported. The data directory is found by the storage
-- helper when left empty and the database is local; the backup directory is optional.
select fn_db_add_config_value('ENGINE_AUDIT_STORAGE_THRESHOLDS', '70,80,90,95', 'general');
select fn_db_add_config_value('ENGINE_AUDIT_DB_DATA_DIR', '', 'general');
select fn_db_add_config_value('ENGINE_AUDIT_BACKUP_DIR', '', 'general');
