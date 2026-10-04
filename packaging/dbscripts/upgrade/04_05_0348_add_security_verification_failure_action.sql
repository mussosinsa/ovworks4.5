-- What is done when the scheduled security verification (ovirt-engine-security-audit.timer) does
-- not pass.
--
-- STOP (default): the failure is recorded, the alert is raised, and after the delay - time for the
-- event notifier to send the alert while the engine is still up - the engine service is stopped.
-- NOTIFY: the failure is recorded and the alert raised; the engine keeps running.
select fn_db_add_config_value('ENGINE_SECURITY_VERIFICATION_FAILURE_ACTION', 'STOP', 'general');
select fn_db_add_config_value('ENGINE_SECURITY_VERIFICATION_HALT_DELAY_SECONDS', '300', 'general');
