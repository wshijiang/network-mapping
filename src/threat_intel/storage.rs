use super::*;
use deadpool_postgres::GenericClient;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone)]
pub(super) struct Source {
    pub id: Uuid,
    pub revision: i64,
    pub input: SourceInput,
    pub fence: Option<Fence>,
    pub credential_ciphertext: Option<Vec<u8>>,
    pub request_config_ciphertext: Option<Vec<u8>>,
}
#[derive(Clone, Copy)]
pub(super) enum Fence {
    Sync(Uuid, Uuid),
    Article(Uuid, Uuid),
}
pub(super) async fn validate_source<C: GenericClient + Sync>(c: &C, s: &Source) -> Result<bool> {
    if let Some(fence) = s.fence {
        let (table, id, token) = match fence {
            Fence::Sync(id, token) => ("intel_sync_run", id, token),
            Fence::Article(id, token) => ("intel_article", id, token),
        };
        // Table names are an internal enum, never request data. Lock order is
        // job -> source -> record across workers and publication transactions.
        let sql = format!(
            "SELECT id FROM {table} WHERE id=$1 AND claim_token=$2 AND source_id=$3 AND source_revision=$4 AND status='running' AND lease_until>clock_timestamp() FOR SHARE"
        );
        if c.query_opt(&sql, &[&id, &token, &s.id, &s.revision])
            .await?
            .is_none()
        {
            return Err(Error::conflict());
        }
    }
    let row = c
        .query_one(
            "SELECT revision,enabled,require_review FROM intel_source WHERE id=$1 FOR SHARE",
            &[&s.id],
        )
        .await?;
    if row.get::<_, i64>("revision") != s.revision || !row.get::<_, bool>("enabled") {
        return Err(Error::conflict());
    }
    Ok(row.get("require_review"))
}
pub(super) fn source(row: &tokio_postgres::Row) -> Source {
    Source {
        id: row.get("id"),
        revision: row.get("revision"),
        input: SourceInput {
            name: row.get("name"),
            kind: row.get("kind"),
            transport: row.get("transport"),
            location: row.get("location"),
            allowed_hosts: row.get("allowed_hosts"),
            request_config: serde_json::from_value(row.get("request_config")).unwrap_or_default(),
            auth_env: row.get("auth_env"),
            credential: String::new(),
            clear_credential: false,
            enabled: row.get("enabled"),
            require_review: row.get("require_review"),
            interval_seconds: Some(row.get("interval_seconds")),
            expiry_months: row.get("expiry_months"),
            expected_revision: Some(row.get("revision")),
        },
        fence: None,
        credential_ciphertext: row.get("credential_ciphertext"),
        request_config_ciphertext: row.get("request_config_ciphertext"),
    }
}
pub(super) async fn get_source(pool: &Pool, id: Uuid) -> Result<Source> {
    pool.get()
        .await?
        .query_opt(
            "SELECT * FROM intel_source WHERE id=$1 AND deleted_at IS NULL",
            &[&id],
        )
        .await?
        .as_ref()
        .map(source)
        .ok_or_else(Error::missing)
}
pub(super) async fn sources(pool: &Pool, encryption_key: &str) -> Result<Value> {
    let rows=pool.get().await?.query("SELECT s.*, (SELECT JSONB_BUILD_OBJECT('status',j.status,'summary',j.summary,'error_code',j.error_code,'created_at',j.created_at) FROM intel_sync_run j WHERE j.source_id=s.id ORDER BY created_at DESC LIMIT 1) AS last_run,
    (SELECT JSONB_BUILD_OBJECT('stage',CASE WHEN i.source_revision<>s.revision THEN 'cancelled' WHEN i.paused THEN 'paused' ELSE i.stage END,'total',i.record_count,'processed',i.processed_count,'validation',i.validation_summary) FROM intel_import_snapshot i WHERE i.source_id=s.id) AS import_status
    FROM intel_source s WHERE s.deleted_at IS NULL ORDER BY name,id",&[]).await?;
    let items = rows
        .iter()
        .map(|row| {
            let s = source(row);
            let mut v = serde_json::to_value(&s.input).unwrap();
            let config = source_transport::RequestConfig::decrypt(
                s.request_config_ciphertext.as_deref(),
                encryption_key,
            )?;
            v["request_config"]["proxy_url"] = json!(config.proxy_url);
            v["id"] = json!(s.id);
            v["revision"] = json!(s.revision);
            v["next_check_at"] =
                json!(row.get::<_, chrono::DateTime<chrono::Utc>>("next_check_at"));
            let (kind, configured) =
                credentials::status(s.credential_ciphertext.is_some(), &s.input.auth_env);
            v["credential_configured"] = json!(configured);
            v["credential_source"] = json!(kind);
            v["database_credential_configured"] = json!(s.credential_ciphertext.is_some());
            v["import_status"] = row
                .get::<_, Option<Value>>("import_status")
                .unwrap_or(Value::Null);
            v["last_run"] = row
                .get::<_, Option<Value>>("last_run")
                .unwrap_or(Value::Null);
            Ok(v)
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(
        json!({"items":items,"defaults":{"mitre_stix":86400,"eset_github":3600,"rss":1800,"article":1800,"threatfox":1800,"threatfox_export":3600,"json":1800,"lines":1800}}),
    )
}
pub(super) async fn save_source(
    pool: &Pool,
    id: Option<Uuid>,
    mut input: SourceInput,
    user: &UserBaseI,
    context: &AuditContext,
    encryption_key: &str,
) -> Result<Value> {
    admin(user)?;
    let encrypted =
        credentials::encrypt_update(&input.credential, input.clear_credential, encryption_key)?;
    let clear = input.clear_credential || input.transport != "https";
    let mut c = pool.get().await?;
    let tx = c.transaction().await?;
    let id = id.unwrap_or_else(Uuid::now_v7);
    let old = tx
        .query_opt(
            "SELECT revision,deleted_at,request_config_ciphertext FROM intel_source WHERE id=$1 FOR UPDATE",
            &[&id],
        )
        .await?;
    let revision = if let Some(row) = old {
        let revision: i64 = row.get(0);
        if row
            .get::<_, Option<chrono::DateTime<chrono::Utc>>>("deleted_at")
            .is_some()
        {
            return Err(Error::missing());
        }
        if input.expected_revision != Some(revision) {
            return Err(Error::conflict());
        }
        let ciphertext: Option<Vec<u8>> = row.get("request_config_ciphertext");
        let old_config =
            source_transport::RequestConfig::decrypt(ciphertext.as_deref(), encryption_key)?;
        input.request_config.preserve(&old_config);
        input.validate()?;
        tx.execute("UPDATE intel_source SET name=$2,kind=$3,transport=$4,location=$5,allowed_hosts=$6,auth_env=$7,enabled=$8,require_review=$9,interval_seconds=$10,revision=revision+1,next_check_at=NOW(),updated_at=NOW() WHERE id=$1",&[&id,&input.name,&input.kind,&input.transport,&input.location,&input.allowed_hosts,&input.auth_env,&input.enabled,&input.require_review,&input.interval_seconds.unwrap()]).await?;
        tx.execute("DELETE FROM intel_source_file WHERE source_id=$1", &[&id])
            .await?;
        revision + 1
    } else {
        input.validate()?;
        if input.expected_revision.is_some() {
            return Err(Error::missing());
        }
        let count: i64 = tx
            .query_one(
                "SELECT COUNT(*) FROM intel_source WHERE deleted_at IS NULL",
                &[],
            )
            .await?
            .get(0);
        if count >= 100 {
            return Err(Error::bad("intel_source_limit"));
        }
        tx.execute("INSERT INTO intel_source(id,name,kind,transport,location,allowed_hosts,auth_env,enabled,require_review,interval_seconds) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",&[&id,&input.name,&input.kind,&input.transport,&input.location,&input.allowed_hosts,&input.auth_env,&input.enabled,&input.require_review,&input.interval_seconds.unwrap()]).await?;
        1
    };
    tx.execute("UPDATE intel_source SET credential_ciphertext=CASE WHEN $2 THEN NULL ELSE COALESCE($3,credential_ciphertext) END,expiry_months=$4 WHERE id=$1", &[&id,&clear,&encrypted,&input.expiry_months]).await?;
    tx.execute(
        "UPDATE intel_source SET request_config=$2,request_config_ciphertext=$3 WHERE id=$1",
        &[
            &id,
            &json!(input.request_config.redact()),
            &input.request_config.encrypt(encryption_key)?,
        ],
    )
    .await?;
    audit(&tx,user,context,"intel.source.save",&id.to_string(),json!({"revision":revision,"kind":input.kind,"enabled":input.enabled,"require_review":input.require_review,"interval_seconds":input.interval_seconds,"expiry_months":input.expiry_months,"credential_changed":clear||encrypted.is_some()})).await?;
    tx.commit().await?;
    Ok(json!({"id":id,"revision":revision}))
}
fn runtime_settings(mut document: Value) -> Result<Settings> {
    if let Some(fields) = document.as_object_mut() {
        fields.remove("llm_managed");
        fields.remove("llm_provider_id");
    }
    serde_json::from_value(document).map_err(|_| Error::unavailable())
}
pub(super) async fn settings(pool: &Pool) -> Result<(Settings, i64)> {
    let row = pool
        .get()
        .await?
        .query_one(
            "SELECT document,revision FROM intel_settings WHERE singleton",
            &[],
        )
        .await?;
    Ok((runtime_settings(row.get("document"))?, row.get("revision")))
}
pub(super) async fn settings_json(pool: &Pool) -> Result<Value> {
    let row=pool.get().await?.query_one("SELECT document,revision,credential_ciphertext IS NOT NULL AS stored FROM intel_settings WHERE singleton",&[]).await?;
    let s = runtime_settings(row.get("document"))?;
    let stored: bool = row.get("stored");
    let (kind, configured) = credentials::status(stored, &s.ai_key_env);
    Ok(
        json!({"settings":s,"revision":row.get::<_,i64>("revision"),"ai_review_required":true,"credential_configured":configured,"credential_source":kind,"database_credential_configured":stored}),
    )
}
pub(super) async fn ai_credential(
    pool: &Pool,
    s: &Settings,
    revision: i64,
    key: &str,
) -> Result<String> {
    let row = pool
        .get()
        .await?
        .query_opt(
            "SELECT credential_ciphertext FROM intel_settings WHERE singleton AND revision=$1",
            &[&revision],
        )
        .await?
        .ok_or_else(Error::conflict)?;
    let ciphertext: Option<Vec<u8>> = row.get(0);
    let transport = llm::runtime_transport(pool, revision, key).await?;
    let has_authorization = transport.headers.contains_key("authorization");
    if let Some(value) = credentials::resolve_with_authorization(
        ciphertext.as_deref(),
        &s.ai_key_env,
        key,
        has_authorization,
    )? {
        return Ok(value);
    }
    if has_authorization {
        return Ok(String::new());
    }
    Err(Error::bad("intel_credential_missing"))
}
pub(super) async fn save_settings(
    pool: &Pool,
    s: Settings,
    expected: i64,
    user: &UserBaseI,
    context: &AuditContext,
    encryption_key: &str,
) -> Result<Value> {
    admin(user)?;
    s.validate()?;
    let encrypted = credentials::encrypt_update(&s.credential, s.clear_credential, encryption_key)?;
    let mut c = pool.get().await?;
    let tx = c.transaction().await?;
    let managed: bool = tx.query_one("SELECT COALESCE((document->>'llm_managed')::BOOLEAN,FALSE) FROM intel_settings WHERE singleton FOR UPDATE", &[]).await?.get(0);
    if managed {
        return Err(Error::bad("llm_settings_moved"));
    }
    let row=tx.query_opt("UPDATE intel_settings SET document=$1,revision=revision+1,updated_at=NOW(),credential_ciphertext=CASE WHEN $3 THEN NULL ELSE COALESCE($4,credential_ciphertext) END WHERE singleton AND revision=$2 RETURNING revision",&[&json!(s),&expected,&s.clear_credential,&encrypted]).await?.ok_or_else(Error::conflict)?;
    let revision: i64 = row.get(0);
    audit(
        &tx,
        user,
        context,
        "intel.settings.save",
        "settings",
        json!({"revision":revision,"ai_enabled":s.ai_enabled,"ai_review_required":true,"credential_changed":s.clear_credential||encrypted.is_some()}),
    )
    .await?;
    tx.commit().await?;
    Ok(json!({"revision":revision}))
}
pub(super) async fn enqueue(
    pool: &Pool,
    id: Uuid,
    user: &UserBaseI,
    context: &AuditContext,
) -> Result<Value> {
    admin(user)?;
    let mut c = pool.get().await?;
    let tx = c.transaction().await?;
    let row = tx
        .query_opt(
            "SELECT revision,enabled,transport FROM intel_source WHERE id=$1 AND deleted_at IS NULL FOR UPDATE",
            &[&id],
        )
        .await?
        .ok_or_else(Error::missing)?;
    if !row.get::<_, bool>("enabled") {
        return Err(Error::bad("intel_source_disabled"));
    }
    let revision: i64 = row.get("revision");
    if row.get::<_, String>("transport") == "manual" {
        return Err(Error::bad("intel_article_submission_required"));
    }
    if row.get::<_,String>("transport")=="upload" && !tx.query_one("SELECT EXISTS(SELECT 1 FROM intel_import_snapshot WHERE source_id=$1 AND source_revision=$2 AND stage<>'complete')",&[&id,&revision]).await?.get::<_,bool>(0) {
        return Err(Error::bad("intel_import_file_required"));
    }
    tx.execute(
        "UPDATE intel_import_snapshot SET paused=FALSE WHERE source_id=$1 AND source_revision=$2",
        &[&id, &revision],
    )
    .await?;
    let job = Uuid::now_v7();
    let inserted=tx.query_opt("INSERT INTO intel_sync_run(id,source_id,source_revision) VALUES($1,$2,$3) ON CONFLICT(source_id) WHERE status IN ('queued','running') DO NOTHING RETURNING id",&[&job,&id,&revision]).await?;
    let job = if let Some(r) = inserted {
        r.get::<_, Uuid>(0)
    } else {
        tx.query_one(
            "SELECT id FROM intel_sync_run WHERE source_id=$1 AND status IN ('queued','running')",
            &[&id],
        )
        .await?
        .get(0)
    };
    audit(
        &tx,
        user,
        context,
        "intel.source.sync",
        &id.to_string(),
        json!({"job_id":job}),
    )
    .await?;
    tx.commit().await?;
    Ok(json!({"id":job}))
}

pub(super) async fn resolve_actor<C: GenericClient + Sync>(
    c: &C,
    source_id: Uuid,
    name: &str,
    suggested: Option<&str>,
    explicit_id: bool,
) -> Result<Option<String>> {
    let _ = source_id;
    let rows=c.query("SELECT e.attack_id FROM intel_entity e WHERE e.kind='actor' AND e.active AND (LOWER(e.name)=LOWER($1) OR ($2 AND $1='' AND e.attack_id=$3)) ORDER BY e.attack_id LIMIT 2",&[&name.trim(),&explicit_id,&suggested]).await?;
    Ok((rows.len() == 1).then(|| rows[0].get(0)))
}
pub(super) async fn ensure_ioc<C: GenericClient + Sync>(
    c: &C,
    kind: &str,
    value: &str,
) -> Result<Uuid> {
    let id = Uuid::now_v7();
    Ok(c.query_one("INSERT INTO intel_ioc(id,kind,value) VALUES($1,$2,$3) ON CONFLICT(kind,value) DO UPDATE SET value=EXCLUDED.value RETURNING id",&[&id,&kind,&value]).await?.get(0))
}
#[derive(Clone, Copy, PartialEq)]
pub(super) enum Origin {
    Structured,
    Ai {
        article_id: Uuid,
        settings_revision: i64,
    },
}
#[cfg(test)]
pub(super) async fn ingest(
    pool: &Pool,
    s: &Source,
    i: Indicator,
    origin: Origin,
    namespace: &str,
) -> Result<bool> {
    let mut c = pool.get().await?;
    let tx = c.transaction().await?;
    let inserted = ingest_in(&tx, s, i, origin, namespace).await?;
    tx.commit().await?;
    Ok(inserted)
}

// Quotes and execution statistics can vary without changing the reported facts.
// The report body is compared separately; evidence snapshots remain immutable.
pub(super) fn ai_facts(payload: &Value) -> Value {
    let mut facts = payload.clone();
    if let Some(fields) = facts.as_object_mut() {
        for key in ["extraction", "evidence", "evidence_spans"] {
            fields.remove(key);
        }
        for key in [
            "techniques",
            "attack_types",
            "victim_industries",
            "victim_countries",
        ] {
            if let Some(values) = fields.get_mut(key).and_then(Value::as_array_mut) {
                values.sort_by_key(Value::to_string);
                values.dedup();
            }
        }
    }
    facts
}

async fn link_article<C: GenericClient + Sync>(
    c: &C,
    s: &Source,
    article: Uuid,
    record: Uuid,
) -> Result<()> {
    let token = match s.fence {
        Some(Fence::Article(_, token)) => Some(token),
        _ => None,
    };
    c.execute("INSERT INTO intel_article_record(article_id,record_id,extraction_token) VALUES($1,$2,$3) ON CONFLICT(article_id,record_id) DO UPDATE SET extraction_token=EXCLUDED.extraction_token", &[&article,&record,&token]).await?;
    Ok(())
}

pub(super) async fn ingest_ai_report(
    pool: &Pool,
    source: &Source,
    mut entries: Vec<Indicator>,
    article: Uuid,
    settings_revision: i64,
    url: &str,
) -> Result<usize> {
    let mut c = pool.get().await?;
    let tx = c.transaction().await?;
    let snapshot = tx
        .query_one(
            "SELECT url,body FROM intel_article WHERE id=$1 AND source_id=$2 FOR UPDATE",
            &[&article, &source.id],
        )
        .await?;
    validate_source(&tx, source).await?;
    // All report insertions and review submissions acquire record locks in order.
    entries.sort_by_key(|item| format!("{}:{}", item.kind, item.value));
    let mut inserted = 0;
    for mut item in entries {
        item.reference = Some(url.into());
        inserted += usize::from(
            ingest_in(
                &tx,
                source,
                item,
                Origin::Ai {
                    article_id: article,
                    settings_revision,
                },
                &format!("{url}#"),
            )
            .await?,
        );
    }
    if let Some(Fence::Article(_, token)) = source.fence {
        // A completed extraction replaces obsolete pending proposals, while
        // previously reviewed evidence and its publication remain unchanged.
        tx.execute("UPDATE intel_record r SET status='superseded',updated_at=NOW() WHERE r.source_id=$1 AND r.origin='ai' AND r.status='pending' AND EXISTS(SELECT 1 FROM intel_article_record l JOIN intel_article a ON a.id=l.article_id WHERE l.record_id=r.id AND a.source_id=$1 AND a.url=$3 AND a.body IS NOT DISTINCT FROM $4) AND NOT EXISTS(SELECT 1 FROM intel_article_record l WHERE l.record_id=r.id AND l.article_id=$2 AND l.extraction_token=$5)", &[&source.id,&article,&snapshot.get::<_,String>("url"),&snapshot.get::<_,Option<String>>("body"),&token]).await?;
    }
    tx.commit().await?;
    Ok(inserted)
}

async fn ingest_in<C: GenericClient + Sync>(
    tx: &C,
    s: &Source,
    mut i: Indicator,
    origin: Origin,
    namespace: &str,
) -> Result<bool> {
    i.normalize()?;
    let require_review = validate_source(tx, s).await?;
    let (origin_str, article) = match origin {
        Origin::Structured => ("structured", None),
        Origin::Ai { article_id, .. } => ("ai", Some(article_id)),
    };
    // AI output cannot claim to be structured, and cannot supply approval metadata.
    let accepted = origin == Origin::Structured && !require_review;
    if let Origin::Ai {
        settings_revision, ..
    } = origin
    {
        // Keep the checked configuration locked until this insertion commits.
        // A preflight check in the worker cannot fence a concurrent settings edit.
        let settings=tx.query_one("SELECT (document->>'ai_enabled')::BOOLEAN AS enabled,revision FROM intel_settings WHERE singleton FOR SHARE",&[]).await?;
        if !settings.get::<_, bool>("enabled") {
            return Err(Error::bad("intel_ai_disabled"));
        }
        if settings.get::<_, i64>("revision") != settings_revision {
            return Err(Error::bad("intel_ai_settings_changed"));
        }
    }
    let explicit = origin == Origin::Structured && i.reference.is_some() && !i.evidence.is_empty();
    i.actor_id = if matches!(origin, Origin::Ai { .. }) {
        None
    } else {
        resolve_actor(tx, s.id, &i.actor_name, i.actor_id.as_deref(), explicit).await?
    };
    if i.reference.is_none() || i.evidence.is_empty() {
        i.actor_id = None;
    }
    let mut payload = json!(i);
    if let Some(id) = article {
        payload["extraction"] = tx
            .query_opt(
                "SELECT extraction_metadata FROM intel_article WHERE id=$1 AND source_id=$2 AND source_revision=$3",
                &[&id, &s.id, &s.revision],
            )
            .await?
            .ok_or_else(Error::conflict)?
            .get("extraction_metadata");
    }
    let identity = if article.is_some() {
        json!({"payload":payload,"article_id":article})
    } else {
        payload.clone()
    };
    let hash =
        digest(&serde_json::to_vec(&identity).map_err(|_| Error::bad("intel_invalid_indicator"))?);
    let key = format!(
        "{namespace}{}",
        if i.external_id.is_empty() {
            format!("{}:{}", i.kind, i.value)
        } else {
            i.external_id.clone()
        }
    );
    let id = Uuid::now_v7();
    // Serialize versions of the same source record, including approval races.
    tx.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended($1,317))",
        &[&format!("{}:{key}", s.id)],
    )
    .await?;
    if let Some(article) = article {
        let rows = tx.query("SELECT r.id,r.payload,r.status FROM intel_record r JOIN intel_article old ON old.id=r.article_id JOIN intel_article current ON current.id=$3 WHERE r.source_id=$1 AND r.external_key=$2 AND r.origin='ai' AND r.status<>'superseded' AND old.deleted_at IS NULL AND old.body IS NOT DISTINCT FROM current.body ORDER BY (r.status<>'pending') DESC,r.created_at DESC,r.id DESC", &[&s.id,&key,&article]).await?;
        let facts = ai_facts(&payload);
        let matches = rows
            .iter()
            .filter(|row| ai_facts(&row.get::<_, Value>("payload")) == facts)
            .collect::<Vec<_>>();
        if let Some(existing) = matches.first() {
            let existing: Uuid = existing.get("id");
            for duplicate in matches.iter().skip(1) {
                if duplicate.get::<_, String>("status") == "pending" {
                    tx.execute("UPDATE intel_record SET status='superseded',updated_at=NOW() WHERE id=$1 AND status='pending'", &[&duplicate.get::<_,Uuid>("id")]).await?;
                }
            }
            link_article(tx, s, article, existing).await?;
            return Ok(false);
        }
    }
    let ioc = if accepted {
        Some(ensure_ioc(tx, &i.kind, &i.value).await?)
    } else {
        None
    };
    let inserted=tx.execute("INSERT INTO intel_record(id,source_id,source_revision,external_key,content_hash,origin,status,kind,value,payload,article_id,actor_id,ioc_id,valid_until,observed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,LEAST(NOW(),COALESCE(intel_observed_time($10::JSONB->>'last_seen'),intel_observed_time($10::JSONB->>'first_seen'),NOW()))) ON CONFLICT(source_id,external_key,content_hash,origin) DO NOTHING",&[&id,&s.id,&s.revision,&key,&hash,&origin_str,&if accepted{"approved"}else{"pending"},&i.kind,&i.value,&payload,&article,&i.actor_id,&ioc,&i.valid_until]).await?;
    if let Some(article) = article {
        let actual = tx.query_one("SELECT id FROM intel_record WHERE source_id=$1 AND external_key=$2 AND content_hash=$3 AND origin='ai'", &[&s.id,&key,&hash]).await?.get(0);
        link_article(tx, s, article, actual).await?;
        if inserted > 0 {
            tx.execute("UPDATE intel_record SET status='superseded',updated_at=NOW() WHERE source_id=$1 AND external_key=$2 AND origin='ai' AND status='pending' AND id<>$3", &[&s.id,&key,&actual]).await?;
        }
    }
    if inserted > 0 && accepted {
        supersede(tx, s.id, &key, origin_str, id).await?;
    }
    if inserted == 0 && accepted
        && let Some(existing)=tx.query_opt("UPDATE intel_record SET status='approved',ioc_id=$5,updated_at=NOW() WHERE source_id=$1 AND external_key=$2 AND content_hash=$3 AND origin=$4 AND status IN ('pending','superseded') RETURNING id",&[&s.id,&key,&hash,&origin_str,&ioc]).await? {
            supersede(tx,s.id,&key,origin_str,existing.get(0)).await?;
    }
    Ok(inserted > 0)
}
async fn supersede<C: GenericClient + Sync>(
    c: &C,
    source: Uuid,
    key: &str,
    origin: &str,
    id: Uuid,
) -> Result<()> {
    c.execute("UPDATE intel_record SET status='superseded',updated_at=NOW() WHERE source_id=$1 AND external_key=$2 AND origin=$3 AND id<>$4 AND status='approved'",&[&source,&key,&origin,&id]).await?;
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReviewInput {
    pub content_hash: String,
    pub decision: String,
    pub reason: String,
    #[serde(default)]
    pub attribution: Option<attribution::ActorDecision>,
}
pub(super) async fn review(
    pool: &Pool,
    id: Uuid,
    input: ReviewInput,
    user: &UserBaseI,
    context: &AuditContext,
) -> Result<Value> {
    admin(user)?;
    let mut c = pool.get().await?;
    let tx = c.transaction().await?;
    let result = review_in(&tx, id, &input, user, context).await?;
    tx.commit().await?;
    Ok(result)
}

pub(super) async fn review_in(
    tx: &deadpool_postgres::Transaction<'_>,
    id: Uuid,
    input: &ReviewInput,
    user: &UserBaseI,
    context: &AuditContext,
) -> Result<Value> {
    admin(user)?;
    if !matches!(input.decision.as_str(), "approved" | "rejected" | "revoked")
        || input.reason.trim().is_empty()
        || input.reason.len() > 1000
    {
        return Err(Error::bad("intel_invalid_review"));
    }
    let identity = tx
        .query_opt(
            "SELECT source_id,external_key FROM intel_record_state WHERE id=$1",
            &[&id],
        )
        .await?
        .ok_or_else(Error::missing)?;
    let source: Uuid = identity.get(0);
    let key: String = identity.get(1);
    tx.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended($1,317))",
        &[&format!("{source}:{key}")],
    )
    .await?;
    let row = tx
        .query_one("SELECT * FROM intel_record WHERE id=$1 FOR UPDATE", &[&id])
        .await?;
    let hash: String = row.get("content_hash");
    let status: String = row.get("status");
    if input.content_hash != hash {
        return Err(Error::conflict());
    }
    if (input.decision == "revoked" && status != "approved")
        || (input.decision != "revoked" && status != "pending")
    {
        return Err(Error::conflict());
    }
    let source: Uuid = row.get("source_id");
    let key: String = row.get("external_key");
    let origin: String = row.get("origin");
    if input.decision != "approved" && input.attribution.is_some() {
        return Err(Error::bad("intel_invalid_attribution"));
    }
    let attribution = if input.decision == "approved" {
        attribution::decide(tx, &row, input.attribution.as_ref(), user).await?
    } else {
        json!({})
    };
    let review = Uuid::now_v7();
    tx.execute("INSERT INTO intel_review(id,record_id,content_hash,decision,reviewed_by,reason,attribution) VALUES($1,$2,$3,$4,$5,$6,$7)",&[&review,&id,&hash,&input.decision,&user.id,&input.reason.trim(),&attribution]).await?;
    let mut ioc: Option<Uuid> = row.get("ioc_id");
    if input.decision == "approved" {
        ioc = Some(
            ensure_ioc(
                tx,
                &row.get::<_, String>("kind"),
                &row.get::<_, String>("value"),
            )
            .await?,
        );
    }
    tx.execute(
        "UPDATE intel_record SET status=$2,review_id=$3,ioc_id=$4,updated_at=NOW() WHERE id=$1",
        &[&id, &input.decision, &review, &ioc],
    )
    .await?;
    if input.decision == "approved" {
        supersede(tx, source, &key, &origin, id).await?;
    }
    audit(
        tx,
        user,
        context,
        "intel.record.review",
        &id.to_string(),
        json!({"decision":input.decision,"content_hash":hash,"review_id":review,"attribution":attribution}),
    )
    .await?;
    Ok(json!({"id":id,"status":input.decision}))
}
pub(super) fn record_json(r: &tokio_postgres::Row) -> Value {
    let expired = r.try_get::<_, bool>("expired").unwrap_or(false);
    let status: String = r.get("status");
    let attribution = r
        .try_get::<_, Value>("reviewed_attribution")
        .unwrap_or_else(|_| json!({}));
    let original_actor: Option<String> = r.get("actor_id");
    let effective_actor = if attribution.get("actor_id").is_some() {
        attribution["actor_id"].as_str().map(str::to_owned)
    } else {
        original_actor.clone()
    };
    let until = r
        .try_get::<_, Option<chrono::DateTime<chrono::Utc>>>("effective_valid_until")
        .unwrap_or_else(|_| r.get("valid_until"));
    let article = r
        .try_get::<_, Option<Uuid>>("active_article_id")
        .unwrap_or_else(|_| r.get("article_id"));
    json!({"id":r.get::<_,Uuid>("id"),"source_id":r.get::<_,Uuid>("source_id"),"source_name":r.get::<_,String>("source_name"),"source_revision":r.get::<_,i64>("source_revision"),"origin":r.get::<_,String>("origin"),"status":if status=="approved"&&expired{"expired".to_owned()}else{status},"expired":expired,"type":r.get::<_,String>("kind"),"value":r.get::<_,String>("value"),"content_hash":r.get::<_,String>("content_hash"),"payload":r.get::<_,Value>("payload"),"actor_id":effective_actor,"original_actor_id":original_actor,"reviewed_attribution":attribution,"article_id":article,"review_id":r.get::<_,Option<Uuid>>("review_id"),"valid_until":until,"created_at":r.get::<_,chrono::DateTime<chrono::Utc>>("created_at")})
}
#[derive(Deserialize, Default)]
pub(super) struct ListQuery {
    pub status: Option<String>,
    pub q: Option<String>,
    pub offset: Option<i64>,
    pub source_id: Option<Uuid>,
    #[serde(rename = "type")]
    pub kind: Option<String>,
    pub attack_type: Option<String>,
}
pub(super) async fn records(pool: &Pool, user: &UserBaseI, q: &ListQuery) -> Result<Value> {
    let status = q.status.as_deref().unwrap_or("approved");
    if !matches!(
        status,
        "pending" | "approved" | "expired" | "rejected" | "revoked" | "superseded"
    ) {
        return Err(Error::bad("intel_invalid_status"));
    }
    if status != "approved" {
        admin(user)?;
    }
    let query = q.q.as_deref().unwrap_or("");
    let offset = q.offset.unwrap_or(0);
    if query.len() > 200 || !(0..=1_000_000).contains(&offset) {
        return Err(Error::bad("intel_invalid_query"));
    }
    let kind = q.kind.as_deref().unwrap_or("");
    let attack = q.attack_type.as_deref().unwrap_or("");
    if !matches!(
        kind,
        "" | "ip" | "ip_port" | "domain" | "url" | "md5" | "sha1" | "sha256" | "asn"
    ) || (!attack.is_empty() && !ATTACK_TYPES.contains(&attack))
    {
        return Err(Error::bad("intel_invalid_query"));
    }
    let c = pool.get().await?;
    let rows=c.query("SELECT r.*,(SELECT a.id FROM intel_article_record l JOIN intel_article a ON a.id=l.article_id WHERE l.record_id=r.id AND a.source_id=r.source_id AND a.deleted_at IS NULL ORDER BY (a.id=r.article_id) DESC,a.created_at DESC,a.id DESC LIMIT 1) AS active_article_id,COALESCE(rv.attribution,'{}'::JSONB) AS reviewed_attribution,COUNT(*) OVER() AS total FROM intel_record_state r LEFT JOIN intel_review rv ON rv.id=r.review_id AND rv.record_id=r.id WHERE ((r.status=$1 AND ($1<>'approved' OR NOT r.expired)) OR ($1='expired' AND r.status='approved' AND r.expired)) AND ($2::UUID IS NULL OR r.source_id=$2) AND ($3='' OR r.value ILIKE '%'||$3||'%' OR r.payload->>'actor_name' ILIKE '%'||$3||'%' OR r.payload->>'malware' ILIKE '%'||$3||'%') AND ($5='' OR r.kind=$5) AND ($6='' OR (r.payload->'attack_types') ? $6) ORDER BY r.created_at DESC,r.id DESC LIMIT 50 OFFSET $4",&[&status,&q.source_id,&query,&offset,&kind,&attack]).await?;
    Ok(
        json!({"items":rows.iter().map(record_json).collect::<Vec<_>>(),"total":rows.first().map(|r|r.get::<_,i64>("total")).unwrap_or(0),"offset":offset}),
    )
}
pub(super) async fn entity_list(pool: &Pool, q: &str, kind: &str) -> Result<Value> {
    if q.len() > 200 || !matches!(kind, "actor" | "software" | "technique") {
        return Err(Error::bad("intel_invalid_query"));
    }
    let rows=pool.get().await?.query("SELECT * FROM intel_entity WHERE kind=$1 AND ($2='' OR name ILIKE '%'||$2||'%' OR attack_id ILIKE '%'||$2||'%' OR array_to_string(aliases,',') ILIKE '%'||$2||'%') ORDER BY active DESC,attack_id LIMIT 100",&[&kind,&q]).await?;
    Ok(
        json!({"items":rows.iter().map(|r|json!({"attack_id":r.get::<_,String>("attack_id"),"name":r.get::<_,String>("name"),"kind":r.get::<_,String>("kind"),"aliases":r.get::<_,Vec<String>>("aliases"),"active":r.get::<_,bool>("active"),"dataset_version":r.get::<_,String>("dataset_version")})).collect::<Vec<_>>()}),
    )
}
pub(super) async fn import_stix(pool: &Pool, s: &Source, data: &[u8]) -> Result<usize> {
    let bundle: Value =
        serde_json::from_slice(data.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(data))
            .map_err(|_| Error::bad("intel_invalid_stix"))?;
    if bundle.get("type").and_then(Value::as_str) != Some("bundle") {
        return Err(Error::bad("intel_invalid_stix"));
    }
    let objects = bundle
        .get("objects")
        .and_then(Value::as_array)
        .filter(|v| v.len() <= MAX_ITEMS)
        .ok_or_else(|| Error::bad("intel_invalid_stix"))?;
    let version = digest(data);
    let mut c = pool.get().await?;
    let tx = c.transaction().await?;
    validate_source(&tx, s).await?;
    let mut count = 0;
    for o in objects {
        let stix = o.get("id").and_then(Value::as_str).unwrap_or("");
        let typ = o.get("type").and_then(Value::as_str).unwrap_or("");
        let active = !(o.get("revoked") == Some(&json!(true))
            || o.get("x_mitre_deprecated") == Some(&json!(true)));
        if typ == "relationship" {
            if let (Some(from), Some(to), Some(relation)) = (
                o.get("source_ref").and_then(Value::as_str),
                o.get("target_ref").and_then(Value::as_str),
                o.get("relationship_type").and_then(Value::as_str),
            ) {
                tx.execute("INSERT INTO intel_relationship(stix_id,source_ref,target_ref,relation,source_id,active,dataset_version,object) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(stix_id) DO UPDATE SET source_ref=EXCLUDED.source_ref,target_ref=EXCLUDED.target_ref,relation=EXCLUDED.relation,source_id=EXCLUDED.source_id,active=EXCLUDED.active,dataset_version=EXCLUDED.dataset_version,object=EXCLUDED.object",&[&stix,&from,&to,&relation,&s.id,&active,&version,o]).await?;
            }
            continue;
        }
        let kind = match typ {
            "intrusion-set" => "actor",
            "malware" | "tool" => "software",
            "attack-pattern" => "technique",
            _ => continue,
        };
        let attack = o
            .get("external_references")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .find(|v| {
                matches!(
                    v.get("source_name").and_then(Value::as_str),
                    Some("mitre-attack" | "mitre-mobile-attack" | "mitre-ics-attack")
                )
            })
            .and_then(|v| v.get("external_id"))
            .and_then(Value::as_str)
            .ok_or_else(|| Error::bad("intel_stix_attack_id_missing"))?;
        let prefix = match kind {
            "actor" => 'G',
            "software" => 'S',
            _ => 'T',
        };
        if !attack.starts_with(prefix) || attack.len() > 16 || stix.is_empty() {
            return Err(Error::bad("intel_invalid_stix_id"));
        }
        let name = o
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::bad("intel_invalid_stix"))?;
        let aliases = o
            .get("aliases")
            .or_else(|| o.get("x_mitre_aliases"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect::<Vec<_>>();
        tx.execute("INSERT INTO intel_entity(attack_id,stix_id,kind,name,aliases,active,source_id,dataset_version,object) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(attack_id) DO UPDATE SET stix_id=EXCLUDED.stix_id,kind=EXCLUDED.kind,name=EXCLUDED.name,aliases=EXCLUDED.aliases,active=EXCLUDED.active,source_id=EXCLUDED.source_id,dataset_version=EXCLUDED.dataset_version,object=EXCLUDED.object,updated_at=NOW()",&[&attack,&stix,&kind,&name,&aliases,&active,&s.id,&version,o]).await?;
        count += 1;
    }
    if count == 0 {
        return Err(Error::bad("intel_empty_stix_bundle"));
    }
    tx.execute(
        "UPDATE intel_entity SET active=FALSE WHERE source_id=$1 AND dataset_version<>$2",
        &[&s.id, &version],
    )
    .await?;
    tx.execute(
        "UPDATE intel_relationship SET active=FALSE WHERE source_id=$1 AND dataset_version<>$2",
        &[&s.id, &version],
    )
    .await?;
    tx.commit().await?;
    Ok(count)
}

#[derive(Clone, Serialize, Default)]
pub(crate) struct Annotation {
    pub available: bool,
    pub risk: Option<String>,
    pub matches: Vec<Value>,
    pub expired_matches: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn_context: Option<Box<Annotation>>,
}
pub(crate) async fn annotate(pool: &Pool, targets: &[Vec<(String, String)>]) -> Vec<Annotation> {
    match annotations(pool, targets).await {
        Ok(v) => v,
        Err(_) => vec![Annotation::default(); targets.len()],
    }
}
// One batched read after asset authorization. ASN evidence is context only and
// never changes the IP/endpoint risk or materializes derived IP indicators.
pub(crate) async fn annotate_assets(
    pool: &Pool,
    targets: &[Vec<(String, String)>],
    asns: &[Option<&str>],
) -> Vec<Annotation> {
    let mut combined = targets.to_vec();
    let keys = (0..targets.len())
        .map(|index| {
            asns.get(index)
                .copied()
                .flatten()
                .and_then(|v| normalize("asn", v).ok())
        })
        .collect::<Vec<_>>();
    combined.extend(keys.iter().map(|key| key.iter().cloned().collect()));
    let mut result = annotate(pool, &combined).await;
    let contexts = result.split_off(targets.len());
    for ((item, context), key) in result.iter_mut().zip(contexts).zip(keys) {
        if key.is_some() {
            item.asn_context = Some(Box::new(context));
        }
    }
    result
}
async fn annotations(pool: &Pool, targets: &[Vec<(String, String)>]) -> Result<Vec<Annotation>> {
    let keys = targets
        .iter()
        .flatten()
        .map(|(k, v)| format!("{k}:{v}"))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if keys.len() > 500 {
        return Err(Error::bad("intel_lookup_too_large"));
    }
    let rows = pool
        .get()
        .await?
        .query(
            r#"
WITH matches AS (
 SELECT r.*,ROW_NUMBER() OVER(PARTITION BY r.kind,r.value,r.expired ORDER BY r.created_at DESC,r.id) AS rank,
 BOOL_OR(r.payload->>'verdict'='malicious') OVER(PARTITION BY r.kind,r.value,r.expired) AS malicious
 FROM intel_record_state r WHERE r.status='approved' AND r.kind||':'||r.value=ANY($1)
)
SELECT r.*,COALESCE(rv.attribution,'{}'::JSONB) AS reviewed_attribution,e.attack_id AS canonical_actor_id,e.name AS canonical_actor_name,
 sw.attack_id AS canonical_software_id,sw.name AS canonical_software_name
FROM matches r
LEFT JOIN intel_review rv ON rv.id=r.review_id AND rv.record_id=r.id
LEFT JOIN intel_entity e ON e.kind='actor' AND e.active AND e.attack_id=CASE WHEN rv.attribution ? 'actor_id' THEN rv.attribution->>'actor_id' ELSE COALESCE(r.actor_id,
 (SELECT m.attack_id FROM intel_name_mapping m WHERE m.source_id=r.source_id AND m.kind='actor'
 AND m.name_normalized=LOWER(BTRIM(r.payload->>'actor_name')) LIMIT 1),
 (SELECT MIN(x.attack_id) FROM intel_entity x WHERE x.kind='actor' AND x.active
 AND LOWER(x.name)=LOWER(BTRIM(r.payload->>'actor_name')) HAVING COUNT(*)=1)) END
 AND r.payload->>'evidence'<>'' AND r.payload->>'reference' IS NOT NULL
LEFT JOIN intel_entity sw ON sw.kind='software' AND sw.active AND sw.attack_id=COALESCE(
 (SELECT m.attack_id FROM intel_name_mapping m WHERE m.source_id=r.source_id AND m.kind='software'
 AND m.name_normalized=LOWER(BTRIM(r.payload->>'malware')) LIMIT 1),
 (SELECT MIN(x.attack_id) FROM intel_entity x WHERE x.kind='software' AND x.active
 AND LOWER(x.name)=LOWER(BTRIM(r.payload->>'malware')) HAVING COUNT(*)=1))
WHERE r.rank<=10
"#,
            &[&keys],
        )
        .await?;
    let mut by_key = BTreeMap::<(String, bool), (bool, Vec<Value>)>::new();
    for r in rows {
        let kind: String = r.get("kind");
        let value: String = r.get("value");
        let key = format!("{kind}:{value}");
        let entry = by_key.entry((key, r.get("expired"))).or_default();
        entry.0 = r.get("malicious");
        let mut v = record_json(&r);
        v["ioc_id"] = json!(r.get::<_, Option<Uuid>>("ioc_id"));
        v["actor"]=r.get::<_,Option<String>>("canonical_actor_id").map(|id|json!({"id":id,"name":r.get::<_,Option<String>>("canonical_actor_name"),"basis":"direct_report"})).unwrap_or(Value::Null);
        v["software"] = r
            .get::<_, Option<String>>("canonical_software_id")
            .map(|id| json!({"id":id,"name":r.get::<_,Option<String>>("canonical_software_name")}))
            .unwrap_or(Value::Null);
        // Indirect software relationships are deliberately absent from actor.
        entry.1.push(v);
    }
    Ok(targets
        .iter()
        .map(|target| {
            let mut result = Annotation {
                available: true,
                ..Default::default()
            };
            for (kind, value) in target {
                if let Some((malicious, matches)) = by_key.get(&(format!("{kind}:{value}"), false))
                {
                    if *malicious {
                        result.risk = Some("malicious".into());
                    } else if result.risk.is_none() {
                        result.risk = Some("suspicious".into());
                    }
                    result.matches.extend(matches.iter().cloned());
                }
                if let Some((_, matches)) = by_key.get(&(format!("{kind}:{value}"), true)) {
                    result.expired_matches.extend(matches.iter().cloned());
                }
            }
            result
        })
        .collect())
}
pub(crate) fn endpoint_keys(ip: &str, port: Option<i32>) -> Vec<(String, String)> {
    let mut keys = vec![("ip".into(), ip.to_owned())];
    if let Some(p) = port
        && let Ok(k) = normalize("ip_port", &format!("{ip}:{p}"))
    {
        keys.push(k);
    }
    keys
}
