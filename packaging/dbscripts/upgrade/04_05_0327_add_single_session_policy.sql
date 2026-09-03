-- Do not reuse 04_05_0325: that version is present in established 4.5
-- installations. Keep this within schema.sh's ten-version window from 0325.
select fn_db_add_config_value('ENGINE_SSO_SINGLE_SESSION_POLICY', 'REPLACE_EXISTING', 'general');
