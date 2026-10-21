-- The sent message, so a score published later can be added to it. Alerts sent
-- before this migration have none and keep their original text.
ALTER TABLE deliveries ADD COLUMN message_id TEXT;
