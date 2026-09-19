-- What the engine records of what goes wrong inside a guest.
--
-- On by default. Asking goes through the host and then through the guest agent, which is not
-- cheap, so a pass asks a limited number of VMs and the rest are asked on the passes after it.
-- Set VmGuestCriticalEventsEnabled to false to stop asking at all.
select fn_db_add_config_value('VmGuestCriticalEventsEnabled','true','general');
select fn_db_add_config_value('VmGuestCriticalEventsIntervalMinutes','15','general');
select fn_db_add_config_value('VmGuestCriticalEventsVmsPerPass','25','general');
select fn_db_add_config_value('VmGuestCriticalEventsLookbackHours','2','general');
