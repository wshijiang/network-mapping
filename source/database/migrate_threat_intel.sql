-- Public threat intelligence is independent of scanner observations/checksums.
CREATE TABLE IF NOT EXISTS intel_settings (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    revision BIGINT NOT NULL DEFAULT 1,
    document JSONB NOT NULL DEFAULT '{"ai_enabled":false,"ai_endpoint":"https://api.openai.com/v1/chat/completions","ai_model":"","ai_key_env":"NM_INTEL_AI_API_KEY"}',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO intel_settings(singleton) VALUES(TRUE) ON CONFLICT DO NOTHING;
ALTER TABLE intel_settings ADD COLUMN IF NOT EXISTS credential_ciphertext BYTEA;

CREATE TABLE IF NOT EXISTS intel_source (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    kind TEXT NOT NULL CHECK(kind IN ('json','lines','threatfox','threatfox_export','eset_github','rss','mitre_stix')),
    transport TEXT NOT NULL CHECK(transport IN ('local','https')),
    location TEXT NOT NULL,
    allowed_hosts TEXT[] NOT NULL DEFAULT '{}',
    auth_env TEXT NOT NULL DEFAULT '',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    require_review BOOLEAN NOT NULL DEFAULT FALSE,
    interval_seconds INTEGER NOT NULL DEFAULT 1800 CHECK(interval_seconds BETWEEN 60 AND 2592000),
    revision BIGINT NOT NULL DEFAULT 1,
    next_check_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE intel_source ADD COLUMN IF NOT EXISTS credential_ciphertext BYTEA;
ALTER TABLE intel_source ADD COLUMN IF NOT EXISTS publisher_id TEXT NOT NULL DEFAULT '';
ALTER TABLE intel_source DROP CONSTRAINT IF EXISTS intel_source_kind_check;
ALTER TABLE intel_source ADD CONSTRAINT intel_source_kind_check CHECK(kind IN ('json','lines','threatfox','threatfox_export','eset_github','rss','mitre_stix','article'));
ALTER TABLE intel_source DROP CONSTRAINT IF EXISTS intel_source_transport_check;
ALTER TABLE intel_source ADD CONSTRAINT intel_source_transport_check CHECK(transport IN ('local','https','upload','manual'));
ALTER TABLE intel_source ADD COLUMN IF NOT EXISTS expiry_months INTEGER NOT NULL DEFAULT 6 CHECK(expiry_months BETWEEN 0 AND 120);
INSERT INTO intel_source(id,name,kind,transport,location,allowed_hosts,auth_env,interval_seconds) VALUES
 ('01800000-0000-7000-8000-000000000001','MITRE Enterprise ATT&CK','mitre_stix','https','https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json',ARRAY['raw.githubusercontent.com'],'',86400),
 ('01800000-0000-7000-8000-000000000002','ESET malware-ioc','eset_github','https','https://api.github.com/repos/eset/malware-ioc/git/trees/master?recursive=1',ARRAY['api.github.com','raw.githubusercontent.com'],'',3600),
 ('01800000-0000-7000-8000-000000000003','ThreatFox','threatfox','https','https://threatfox-api.abuse.ch/api/v1/',ARRAY['threatfox-api.abuse.ch'],'NM_INTEL_THREATFOX_AUTH_KEY',1800),
 ('01800000-0000-7000-8000-000000000004','ESET WeLiveSecurity RSS','rss','https','https://www.welivesecurity.com/en/rss/feed/',ARRAY['www.welivesecurity.com','welivesecurity.com'],'',1800)
ON CONFLICT(id) DO NOTHING;

INSERT INTO intel_source(id,name,kind,transport,location,interval_seconds,enabled)
 VALUES('01800000-0000-7000-8000-000000000005','ThreatFox 离线历史导入','threatfox_export','upload','',3600,TRUE)
 ON CONFLICT(id) DO NOTHING;
CREATE TABLE IF NOT EXISTS intel_import_snapshot (
    source_id UUID PRIMARY KEY REFERENCES intel_source(id),
    source_revision BIGINT NOT NULL,
    snapshot_id UUID NOT NULL,
    stage TEXT NOT NULL CHECK(stage IN ('downloaded','ready','complete')),
    byte_offset BIGINT NOT NULL DEFAULT 0,
    record_count BIGINT NOT NULL DEFAULT 0,
    processed_count BIGINT NOT NULL DEFAULT 0,
    content_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE intel_import_snapshot ADD COLUMN IF NOT EXISTS validation_summary JSONB NOT NULL DEFAULT '{}';
ALTER TABLE intel_import_snapshot ADD COLUMN IF NOT EXISTS paused BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS intel_sync_run (
    id UUID PRIMARY KEY,
    source_id UUID NOT NULL REFERENCES intel_source(id),
    source_revision BIGINT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','running','succeeded','partial','failed','cancelled')),
    attempts INTEGER NOT NULL DEFAULT 0,
    claim_token UUID,
    lease_until TIMESTAMPTZ,
    available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    summary JSONB NOT NULL DEFAULT '{}',
    error_code TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS intel_sync_one_active ON intel_sync_run(source_id) WHERE status IN ('queued','running');
CREATE INDEX IF NOT EXISTS intel_sync_pending ON intel_sync_run(available_at,created_at) WHERE status IN ('queued','running');
CREATE TABLE IF NOT EXISTS intel_source_file (
    source_id UUID NOT NULL REFERENCES intel_source(id),
    path TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    PRIMARY KEY(source_id,path)
);
ALTER TABLE intel_source_file ADD COLUMN IF NOT EXISTS parser_version INTEGER NOT NULL DEFAULT 1;

CREATE TABLE IF NOT EXISTS intel_entity (
    attack_id TEXT PRIMARY KEY,
    stix_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('actor','software','technique')),
    name TEXT NOT NULL,
    aliases TEXT[] NOT NULL DEFAULT '{}',
    active BOOLEAN NOT NULL DEFAULT TRUE,
    source_id UUID NOT NULL REFERENCES intel_source(id),
    dataset_version TEXT NOT NULL,
    object JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS intel_entity_kind ON intel_entity(kind,active);
CREATE TABLE IF NOT EXISTS intel_relationship (
    stix_id TEXT PRIMARY KEY,
    source_ref TEXT NOT NULL,
    target_ref TEXT NOT NULL,
    relation TEXT NOT NULL,
    source_id UUID NOT NULL REFERENCES intel_source(id),
    active BOOLEAN NOT NULL DEFAULT TRUE,
    dataset_version TEXT NOT NULL,
    object JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS intel_name_mapping (
    id UUID PRIMARY KEY,
    source_id UUID NOT NULL REFERENCES intel_source(id),
    name_normalized TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'actor' CHECK(kind IN ('actor','software')),
    attack_id TEXT NOT NULL REFERENCES intel_entity(attack_id),
    reviewed_by INTEGER NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(source_id,name_normalized,kind)
);

CREATE TABLE IF NOT EXISTS intel_article (
    id UUID PRIMARY KEY,
    source_id UUID NOT NULL REFERENCES intel_source(id),
    source_revision BIGINT NOT NULL,
    url TEXT NOT NULL,
    title TEXT NOT NULL,
    feed_hash TEXT NOT NULL,
    body_hash TEXT,
    body TEXT,
    status TEXT NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','running','proposed','failed','cancelled')),
    attempts INTEGER NOT NULL DEFAULT 0,
    claim_token UUID,
    lease_until TIMESTAMPTZ,
    available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    error_code TEXT,
    extraction_metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT intel_article_source_version UNIQUE(source_id,url,feed_hash,source_revision),
    UNIQUE(source_id,id)
);
-- Upgrade existing installations without changing old snapshots/review evidence.
ALTER TABLE intel_article DROP CONSTRAINT IF EXISTS intel_article_source_id_url_feed_hash_key;
CREATE UNIQUE INDEX IF NOT EXISTS intel_article_source_version
 ON intel_article(source_id,url,feed_hash,source_revision);

-- Only accepted indicators enter this table. AI drafts live in intel_record.
CREATE TABLE IF NOT EXISTS intel_ioc (
    id UUID PRIMARY KEY,
    kind TEXT NOT NULL CHECK(kind IN ('ip','ip_port','domain','url','md5','sha1','sha256')),
    value TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(kind,value)
);
ALTER TABLE intel_ioc DROP CONSTRAINT IF EXISTS intel_ioc_kind_check;
ALTER TABLE intel_ioc ADD CONSTRAINT intel_ioc_kind_check CHECK(kind IN ('ip','ip_port','domain','url','md5','sha1','sha256','asn'));
CREATE TABLE IF NOT EXISTS intel_record (
    id UUID PRIMARY KEY,
    source_id UUID NOT NULL REFERENCES intel_source(id),
    source_revision BIGINT NOT NULL,
    external_key TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    origin TEXT NOT NULL CHECK(origin IN ('structured','ai')),
    status TEXT NOT NULL CHECK(status IN ('pending','approved','rejected','superseded','revoked')),
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    payload JSONB NOT NULL,
    article_id UUID,
    actor_id TEXT REFERENCES intel_entity(attack_id),
    ioc_id UUID REFERENCES intel_ioc(id),
    review_id UUID,
    valid_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(source_id,external_key,content_hash,origin),
    FOREIGN KEY(source_id,article_id) REFERENCES intel_article(source_id,id),
    CHECK(origin <> 'ai' OR article_id IS NOT NULL),
    CHECK(status <> 'approved' OR ioc_id IS NOT NULL),
    CHECK(origin <> 'ai' OR status <> 'approved' OR review_id IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS intel_record_published ON intel_record(kind,value) WHERE status='approved';
CREATE INDEX IF NOT EXISTS intel_record_match_key ON intel_record((kind||':'||value)) WHERE status='approved';
CREATE INDEX IF NOT EXISTS intel_record_attack_types ON intel_record USING GIN ((payload->'attack_types'));
CREATE INDEX IF NOT EXISTS intel_record_queue ON intel_record(status,created_at);
CREATE INDEX IF NOT EXISTS intel_sync_source_history ON intel_sync_run(source_id,created_at DESC);
CREATE INDEX IF NOT EXISTS intel_article_pending ON intel_article(available_at,created_at) WHERE status IN ('queued','running');
ALTER TABLE intel_record ADD COLUMN IF NOT EXISTS observed_at TIMESTAMPTZ;
CREATE OR REPLACE FUNCTION intel_observed_time(value TEXT) RETURNS TIMESTAMPTZ LANGUAGE plpgsql STABLE AS $$
BEGIN
 IF value IS NULL OR length(value)>100 THEN RETURN NULL; END IF;
 IF value ~ '^[0-9]{10}$' THEN RETURN to_timestamp(value::BIGINT); END IF;
 IF value !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}' THEN RETURN NULL; END IF;
 IF value ~ '(Z|UTC|[+-][0-9]{2}:?[0-9]{2})$' THEN RETURN value::TIMESTAMPTZ; END IF;
 RETURN value::TIMESTAMP AT TIME ZONE 'UTC';
EXCEPTION WHEN invalid_datetime_format OR datetime_field_overflow OR numeric_value_out_of_range THEN RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS intel_record_publication_guard ON intel_record;
UPDATE intel_record SET observed_at=LEAST(created_at,COALESCE(intel_observed_time(payload->>'last_seen'),intel_observed_time(payload->>'first_seen'),created_at)) WHERE observed_at IS NULL;
CREATE TABLE IF NOT EXISTS intel_review (
    id UUID PRIMARY KEY,
    record_id UUID NOT NULL REFERENCES intel_record(id),
    content_hash TEXT NOT NULL,
    decision TEXT NOT NULL CHECK(decision IN ('approved','rejected','revoked')),
    reviewed_by INTEGER NOT NULL REFERENCES users(id),
    reason TEXT NOT NULL CHECK(length(reason) BETWEEN 1 AND 1000),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(record_id,id)
);
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='intel_record_review_fk' AND conrelid='intel_record'::REGCLASS) THEN
  ALTER TABLE intel_record ADD CONSTRAINT intel_record_review_fk FOREIGN KEY(id,review_id) REFERENCES intel_review(record_id,id);
 END IF;
END $$;
CREATE OR REPLACE FUNCTION intel_record_guard() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='INSERT' AND (SELECT kind FROM intel_source WHERE id=NEW.source_id) IN ('rss','article') AND NEW.origin<>'ai' THEN
  RAISE EXCEPTION 'Article extraction is always AI evidence';
 END IF;
 IF TG_OP='UPDATE' AND (NEW.origin,NEW.source_id,NEW.source_revision,NEW.external_key,NEW.content_hash,NEW.kind,NEW.value,NEW.payload,NEW.article_id,NEW.actor_id,NEW.valid_until,NEW.observed_at)
     IS DISTINCT FROM (OLD.origin,OLD.source_id,OLD.source_revision,OLD.external_key,OLD.content_hash,OLD.kind,OLD.value,OLD.payload,OLD.article_id,OLD.actor_id,OLD.valid_until,OLD.observed_at) THEN
  RAISE EXCEPTION 'intelligence evidence is immutable';
 END IF;
 IF NEW.status='approved' AND (TG_OP='INSERT' OR OLD.status IS DISTINCT FROM 'approved') THEN
  IF NEW.origin='ai' OR (SELECT require_review FROM intel_source WHERE id=NEW.source_id) THEN
   IF NOT EXISTS (SELECT 1 FROM intel_review r JOIN users u ON u.id=r.reviewed_by AND u.role=1 AND u.disabled_at IS NULL AND u.deleted_at IS NULL WHERE r.id=NEW.review_id AND r.record_id=NEW.id AND r.content_hash=NEW.content_hash AND r.decision='approved') THEN
    RAISE EXCEPTION 'matching human approval is required';
   END IF;
  END IF;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS intel_record_publication_guard ON intel_record;
CREATE TRIGGER intel_record_publication_guard BEFORE INSERT OR UPDATE ON intel_record FOR EACH ROW EXECUTE FUNCTION intel_record_guard();

CREATE OR REPLACE VIEW intel_record_state AS
 SELECT q.*,(q.effective_valid_until IS NOT NULL AND q.effective_valid_until<=NOW()) AS expired
 FROM (SELECT r.*,s.name AS source_name,
   LEAST(r.valid_until,CASE WHEN s.expiry_months>0 THEN COALESCE(r.observed_at,r.created_at)+make_interval(months=>s.expiry_months) END) AS effective_valid_until
   FROM intel_record r JOIN intel_source s ON s.id=r.source_id) q;
-- Preserve the original public view's column order when upgrading.
CREATE OR REPLACE VIEW intel_published AS
 SELECT r.id,r.source_id,r.source_revision,r.external_key,r.content_hash,r.origin,r.status,r.kind,r.value,
 r.payload,r.article_id,r.actor_id,r.ioc_id,r.review_id,r.valid_until,r.created_at,r.updated_at,r.source_name,
 r.observed_at,r.effective_valid_until,r.expired FROM intel_record_state r
 WHERE r.status='approved' AND NOT r.expired;
