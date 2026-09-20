-- Whether the block-file-sharing filter is the only one a vNIC profile may have.
--
-- On, which is how the engine is installed and what the security baseline expects: the filter is
-- written onto every profile that is not a passthrough one, whatever the request asked for. Set it
-- to false where the profiles of a data centre are to carry the filters they are given, and
-- block-file-sharing becomes what a new profile merely starts out with.
select fn_db_add_config_value('EnforceBlockFileSharingFilter','true','general');
