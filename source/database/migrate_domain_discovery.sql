-- Control plane only. Certificate/name evidence lives in Elasticsearch snapshots.
CREATE TABLE IF NOT EXISTS domain_discovery_job (
    id UUID PRIMARY KEY,
    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    seed TEXT NOT NULL,
    include_related BOOLEAN NOT NULL DEFAULT FALSE,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','running','succeeded','partial','failed','cancelled')),
    attempts INTEGER NOT NULL DEFAULT 0,
    available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    claim_token UUID,
    lease_until TIMESTAMPTZ,
    summary JSONB NOT NULL DEFAULT '{}',
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS domain_discovery_owner_idx ON domain_discovery_job(owner_id,created_at DESC);
CREATE INDEX IF NOT EXISTS domain_discovery_pending_idx ON domain_discovery_job(available_at,created_at) WHERE status IN ('pending','running');
CREATE TABLE IF NOT EXISTS domain_discovery_dns_target (
    job_id UUID NOT NULL REFERENCES domain_discovery_job(id) ON DELETE CASCADE,
    domain TEXT NOT NULL,
    task_id VARCHAR(36) NOT NULL REFERENCES scan_task(task_id) ON DELETE CASCADE,
    PRIMARY KEY(job_id,domain)
);
