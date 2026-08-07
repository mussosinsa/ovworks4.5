-- Enforce block-file-sharing nwfilter as the default and mandatory filter
-- for non-passthrough vNIC profiles.
UPDATE vnic_profiles vp
SET network_filter_id = nf.filter_id
FROM network_filter nf
WHERE nf.filter_name = 'block-file-sharing'
  AND COALESCE(vp.passthrough, false) = false;

-- Passthrough profiles cannot use network filters.
UPDATE vnic_profiles
SET network_filter_id = NULL
WHERE COALESCE(passthrough, false) = true;
