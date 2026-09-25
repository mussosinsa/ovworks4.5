-- Whether the block-file-sharing filter is the only one a vNIC profile may have.
--
-- Off, which is how the engine is installed: a profile carries the filter it is given, and
-- block-file-sharing is what a new one starts out with rather than what every one ends up
-- with. Set it to true where the sharing between the VMs of a data centre is to be closed off
-- by the engine, whatever a profile was asked for.
select fn_db_add_config_value('EnforceBlockFileSharingFilter','false','general');
