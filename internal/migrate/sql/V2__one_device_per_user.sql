-- v1 is single-device: each user has exactly ONE live device. Earlier builds appended a new
-- row on every re-provision (cleared storage / a different device) and never retired the old
-- ones, so KEY_FETCH could hand a peer a dead device and the safety number would be computed
-- against a stale identity. Publish now retires other devices (replace-on-publish); this one-time
-- migration collapses the ALREADY-accumulated rows so the whole table holds the invariant now,
-- not only after each user's next publish. Keep the most-recently-published device per user
-- (updated_at, then device_id as a deterministic tie-break); drop the rest. The FK cascade drops
-- the retired devices' signed + one-time prekeys.
DELETE FROM e2e_identity e
WHERE EXISTS (
    SELECT 1 FROM e2e_identity n
    WHERE n.user_id = e.user_id
      AND (n.updated_at, n.device_id) > (e.updated_at, e.device_id)
);
