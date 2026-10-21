-- Requests failed before the redirect fix, and their backoff can delay live polls for hours.
UPDATE live_poll_state SET next_poll_at = 0, failure_count = 0;
