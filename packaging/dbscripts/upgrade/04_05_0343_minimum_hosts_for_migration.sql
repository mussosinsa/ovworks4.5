-- How many hosts a cluster needs before a VM in it may be migrated.
--
-- Three, so a cluster of two is not offered a migration. Two hosts can move a VM between them and
-- nothing else refuses it, so this is a decision about how the estate is run rather than about
-- what is possible: a pair has nowhere to put the VM when the other one is the reason it is being
-- moved. Set it to 2 to put a pair back.
select fn_db_add_config_value('MinimumHostsForMigration','3','general');
