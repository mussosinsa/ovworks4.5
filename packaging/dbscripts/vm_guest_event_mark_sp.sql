-- How far the guest event collector has read each event log of a VM.
-- Windows numbers the records of each log on its own, so the key is (vm_id, log_name).

CREATE OR REPLACE FUNCTION GetVmGuestEventMarksByVmId (v_vm_id UUID)
RETURNS SETOF vm_guest_event_mark STABLE AS $FUNCTION$
BEGIN
    RETURN QUERY

    SELECT *
    FROM vm_guest_event_mark
    WHERE vm_id = v_vm_id;
END;$FUNCTION$
LANGUAGE plpgsql;

-- The mark is set, not raised. A guest whose log was cleared numbers its records from one again,
-- and the mark has to follow it down; refusing to lower it would skip everything that guest
-- records afterwards for as long as it took to climb back.
CREATE OR REPLACE FUNCTION UpsertVmGuestEventMark (
    v_vm_id UUID,
    v_log_name VARCHAR(64),
    v_last_record_id BIGINT
    )
RETURNS VOID AS $FUNCTION$
BEGIN
    INSERT INTO vm_guest_event_mark (
        vm_id,
        log_name,
        last_record_id,
        update_date
        )
    VALUES (
        v_vm_id,
        v_log_name,
        v_last_record_id,
        now()
        )
    ON CONFLICT (vm_id, log_name)
    DO UPDATE
    SET last_record_id = v_last_record_id,
        update_date = now();
END;$FUNCTION$
LANGUAGE plpgsql;
