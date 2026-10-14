-- Derived receipt state. Receipt identities/checksums remain authoritative.
CREATE TABLE IF NOT EXISTS scan_upload_stream (
    execution_id INT NOT NULL REFERENCES scan_task_execution(id) ON DELETE CASCADE,
    upload_id VARCHAR(36) NOT NULL,
    batch_count BIGINT NOT NULL DEFAULT 0,
    confirmed_count BIGINT NOT NULL DEFAULT 0,
    pending_count BIGINT NOT NULL DEFAULT 0,
    first_batch INT,
    last_batch INT,
    final_count BIGINT NOT NULL DEFAULT 0,
    final_batch INT,
    confirmed_observations BIGINT NOT NULL DEFAULT 0,
    dirty BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (execution_id, upload_id)
);

-- Serialize installation/backfill with receipt writers, including older instances.
LOCK TABLE scan_result_batch IN SHARE ROW EXCLUSIVE MODE;
CREATE OR REPLACE FUNCTION maintain_scan_upload_stream() RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        -- Administrative receipt removal is rare. Rebuild once on the next upload,
        -- instead of rescanning remaining receipts on every cascading deletion.
        UPDATE scan_upload_stream SET dirty = TRUE
        WHERE execution_id = OLD.execution_id AND upload_id = OLD.upload_id;
        RETURN OLD;
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF (NEW.execution_id, NEW.upload_id, NEW.batch_index, NEW.is_final, NEW.observation_count)
            IS DISTINCT FROM
           (OLD.execution_id, OLD.upload_id, OLD.batch_index, OLD.is_final, OLD.observation_count) THEN
            RAISE EXCEPTION 'scan receipt identity and counts are immutable';
        END IF;
        IF NEW.storage_backend IS DISTINCT FROM OLD.storage_backend THEN
            UPDATE scan_upload_stream SET
                confirmed_count = confirmed_count + (NEW.storage_backend <> 'pending')::INT - (OLD.storage_backend <> 'pending')::INT,
                pending_count = pending_count + (NEW.storage_backend = 'pending')::INT - (OLD.storage_backend = 'pending')::INT,
                confirmed_observations = confirmed_observations +
                    ((NEW.storage_backend <> 'pending')::INT - (OLD.storage_backend <> 'pending')::INT)::BIGINT * NEW.observation_count
            WHERE execution_id = NEW.execution_id AND upload_id = NEW.upload_id;
        END IF;
        RETURN NEW;
    END IF;
    INSERT INTO scan_upload_stream AS s
        (execution_id, upload_id, batch_count, confirmed_count, pending_count,
         first_batch, last_batch, final_count, final_batch, confirmed_observations)
    VALUES (NEW.execution_id, NEW.upload_id, 1, (NEW.storage_backend <> 'pending')::INT,
            (NEW.storage_backend = 'pending')::INT, NEW.batch_index, NEW.batch_index,
            NEW.is_final::INT, CASE WHEN NEW.is_final THEN NEW.batch_index END,
            CASE WHEN NEW.storage_backend <> 'pending' THEN NEW.observation_count ELSE 0 END)
    ON CONFLICT (execution_id, upload_id) DO UPDATE SET
        batch_count = s.batch_count + 1,
        confirmed_count = s.confirmed_count + EXCLUDED.confirmed_count,
        pending_count = s.pending_count + EXCLUDED.pending_count,
        first_batch = LEAST(s.first_batch, EXCLUDED.first_batch),
        last_batch = GREATEST(s.last_batch, EXCLUDED.last_batch),
        final_count = s.final_count + EXCLUDED.final_count,
        final_batch = LEAST(s.final_batch, EXCLUDED.final_batch),
        confirmed_observations = s.confirmed_observations + EXCLUDED.confirmed_observations;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS scan_upload_stream_receipt ON scan_result_batch;
CREATE TRIGGER scan_upload_stream_receipt
AFTER INSERT OR DELETE OR UPDATE OF execution_id, upload_id, batch_index, is_final, observation_count, storage_backend
ON scan_result_batch FOR EACH ROW EXECUTE FUNCTION maintain_scan_upload_stream();

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM scan_storage_state WHERE state_key = 'upload_stream_schema_v1') THEN
        INSERT INTO scan_upload_stream
            (execution_id, upload_id, batch_count, confirmed_count, pending_count, first_batch,
             last_batch, final_count, final_batch, confirmed_observations)
        SELECT execution_id, upload_id, COUNT(*), COUNT(*) FILTER (WHERE storage_backend <> 'pending'),
               COUNT(*) FILTER (WHERE storage_backend = 'pending'), MIN(batch_index), MAX(batch_index),
               COUNT(*) FILTER (WHERE is_final), MIN(batch_index) FILTER (WHERE is_final),
               COALESCE(SUM(observation_count) FILTER (WHERE storage_backend <> 'pending'), 0)
        FROM scan_result_batch GROUP BY execution_id, upload_id
        ON CONFLICT (execution_id, upload_id) DO NOTHING;
        INSERT INTO scan_storage_state(state_key, state_value)
        VALUES ('upload_stream_schema_v1', '{"version":1}'::JSONB);
    END IF;
END $$;
