-- What a local user is given when it is created (AddLocalUserCommand).
--
-- ENGINE_LOCAL_USER_DEFAULT_ROLES: roles given on the whole system, by name and comma separated;
-- user roles only. ExternalEventsCreator by default. Empty for none.
-- ENGINE_LOCAL_USER_DEFAULT_GROUP: a local group the user is added to, so that it has what the
-- group is given. Empty (none) by default.
select fn_db_add_config_value('ENGINE_LOCAL_USER_DEFAULT_ROLES', 'ExternalEventsCreator', 'general');
select fn_db_add_config_value('ENGINE_LOCAL_USER_DEFAULT_GROUP', '', 'general');
