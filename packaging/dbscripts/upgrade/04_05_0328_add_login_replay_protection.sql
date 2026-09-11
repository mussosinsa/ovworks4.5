-- Replay protection for the encrypted REST API credentials.
--
-- ENGINE_SSO_LOGIN_REQUIRE_FRESH_CREDENTIALS starts off allowing credentials that carry no
-- protection, so that upgrading the engine does not lock out clients that have not been updated.
-- Clients that do wrap their credentials are protected either way; turning this on refuses the
-- unwrapped form outright, once every client is sending the new one.
select fn_db_add_config_value('ENGINE_SSO_LOGIN_REQUIRE_FRESH_CREDENTIALS', 'false', 'general');
select fn_db_add_config_value('ENGINE_SSO_LOGIN_FRESHNESS_SECONDS', '120', 'general');
