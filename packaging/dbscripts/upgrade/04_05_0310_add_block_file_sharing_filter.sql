INSERT INTO network_filter (filter_id, filter_name, version)
SELECT 'c0f956c2-e2a2-43b9-a14c-24ceb2fd1af4', 'block-file-sharing', '4.5'
WHERE NOT EXISTS (
    SELECT 1
    FROM network_filter
    WHERE filter_name = 'block-file-sharing'
);
