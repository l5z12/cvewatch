-- Set by the Emergency stop workflow. A stopped destination sends and edits nothing
-- until it is resumed; polling keeps queuing alerts for it meanwhile.
ALTER TABLE channel_state ADD COLUMN stopped_at INTEGER;
