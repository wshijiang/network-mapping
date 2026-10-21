-- LLM runtime selection is a singleton; models belong to exactly one provider.
CREATE TABLE IF NOT EXISTS llm_provider (
 id UUID PRIMARY KEY,
 document JSONB NOT NULL,
 transport_ciphertext BYTEA,
 credential_ciphertext BYTEA,
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS llm_model (
 provider_id UUID NOT NULL REFERENCES llm_provider(id) ON DELETE CASCADE,
 model_id TEXT NOT NULL CHECK(length(model_id) BETWEEN 1 AND 200),
 document JSONB NOT NULL,
 PRIMARY KEY(provider_id,model_id)
);
CREATE TABLE IF NOT EXISTS llm_settings (
 singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK(singleton),
 revision BIGINT NOT NULL,
 enabled BOOLEAN NOT NULL DEFAULT FALSE,
 provider_id UUID,
 model_id TEXT,
 global_config JSONB NOT NULL DEFAULT '{"proxy_mode":"system","headers_mode":"replace","session_mode":"disabled","stream":false}',
 transport_ciphertext BYTEA,
 CHECK ((provider_id IS NULL) = (model_id IS NULL)),
 CHECK (NOT enabled OR provider_id IS NOT NULL),
 FOREIGN KEY(provider_id,model_id) REFERENCES llm_model(provider_id,model_id) DEFERRABLE INITIALLY DEFERRED
);

-- The singleton is the migration marker. Re-running startup never overwrites edits.
INSERT INTO llm_provider(id,document,credential_ciphertext)
SELECT '01800000-0000-7000-8000-000000000100',
 jsonb_build_object('name','迁移的 LLM 供应商','endpoint',document->>'ai_endpoint',
 'models_url','','default_model',document->>'ai_model',
 'protocol',COALESCE(document->>'ai_protocol','chat'),
 'key_env',COALESCE(document->>'ai_key_env','NM_INTEL_AI_API_KEY'),
 'timeout_seconds',COALESCE((document->>'ai_timeout_seconds')::INTEGER,180),
 'max_output_tokens',COALESCE((document->>'ai_max_output_tokens')::INTEGER,65536),
 'reasoning_effort',COALESCE(document->>'ai_reasoning_effort','none'),
 'transport',jsonb_build_object('proxy_mode','inherit','headers_mode','merge','session_mode','inherit')),
 credential_ciphertext
FROM intel_settings WHERE singleton AND NOT EXISTS(SELECT 1 FROM llm_settings)
ON CONFLICT DO NOTHING;
INSERT INTO llm_model(provider_id,model_id,document)
SELECT '01800000-0000-7000-8000-000000000100',document->>'ai_model',
 jsonb_build_object('id',document->>'ai_model','name',document->>'ai_model',
 'protocol',COALESCE(document->>'ai_protocol','chat'),'available',TRUE)
FROM intel_settings WHERE singleton AND COALESCE(document->>'ai_model','')<>''
 AND NOT EXISTS(SELECT 1 FROM llm_settings) ON CONFLICT DO NOTHING;
INSERT INTO llm_settings(singleton,revision,enabled,provider_id,model_id)
SELECT TRUE,revision,COALESCE((document->>'ai_enabled')::BOOLEAN,FALSE) AND COALESCE(document->>'ai_model','')<>'',
 CASE WHEN COALESCE(document->>'ai_model','')<>'' THEN '01800000-0000-7000-8000-000000000100'::UUID END,
 NULLIF(document->>'ai_model','') FROM intel_settings WHERE singleton ON CONFLICT DO NOTHING;
UPDATE intel_settings SET document=document || jsonb_build_object('llm_managed',TRUE,
 'ai_enabled',(SELECT enabled FROM llm_settings WHERE singleton),
 'llm_provider_id',(SELECT provider_id FROM llm_settings WHERE singleton))
 WHERE singleton AND NOT COALESCE((document->>'llm_managed')::BOOLEAN,FALSE);
