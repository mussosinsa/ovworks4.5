-- Ensure non-passthrough vNIC profiles always use the mandatory
-- block-file-sharing filter, including environments where old
-- profiles still point to legacy filters (e.g. vdsm-no-mac-spoofing).
UPDATE vnic_profiles vp
SET network_filter_id = nf.filter_id
FROM network_filter nf
WHERE nf.filter_name = 'block-file-sharing'
  AND COALESCE(vp.passthrough, false) = false
  AND vp.network_filter_id IS DISTINCT FROM nf.filter_id;

-- Passthrough profiles must not use network filters.
UPDATE vnic_profiles
SET network_filter_id = NULL
WHERE COALESCE(passthrough, false) = true
  AND network_filter_id IS NOT NULL;
