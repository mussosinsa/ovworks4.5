-- Where the guest event collector stopped reading each log of each VM, so that an engine
-- restart does not make it report again everything the lookback window still holds.
CREATE TABLE IF NOT EXISTS vm_guest_event_mark (
    vm_id UUID NOT NULL,
    log_name VARCHAR(64) NOT NULL,
    last_record_id BIGINT DEFAULT 0 NOT NULL,
    update_date TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL,
    CONSTRAINT pk_vm_guest_event_mark PRIMARY KEY (vm_id, log_name),
    CONSTRAINT vm_static_vm_guest_event_mark FOREIGN KEY (vm_id)
        REFERENCES vm_static(vm_guid) ON DELETE CASCADE
);

-- The security log of a guest, which the collector was not reading at all.
select fn_db_add_config_value('VmGuestSecurityEventsEnabled','true','general');
