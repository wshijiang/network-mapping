use super::*;
use deadpool_postgres::Transaction;

pub(super) struct State {
    pub revision: i64,
    pub enabled: bool,
    pub provider_id: Option<Uuid>,
    pub model_id: Option<String>,
    pub global: Transport,
    pub ioc_prompt: String,
}
pub(super) async fn state<C: deadpool_postgres::GenericClient + Sync>(
    c: &C,
    key: &str,
) -> Result<State> {
    let r = c
        .query_one("SELECT l.*,COALESCE(i.document->>'ai_prompt','') AS ioc_prompt FROM llm_settings l CROSS JOIN intel_settings i WHERE l.singleton AND i.singleton", &[])
        .await?;
    Ok(State {
        revision: r.get("revision"),
        enabled: r.get("enabled"),
        provider_id: r.get("provider_id"),
        model_id: r.get("model_id"),
        global: decrypt(r.get("transport_ciphertext"), r.get("global_config"), key)?,
        ioc_prompt: r.get("ioc_prompt"),
    })
}
pub(super) async fn provider<C: deadpool_postgres::GenericClient + Sync>(
    c: &C,
    id: Uuid,
    key: &str,
) -> Result<Provider> {
    let row = c
        .query_opt("SELECT * FROM llm_provider WHERE id=$1", &[&id])
        .await?
        .ok_or_else(Error::missing)?;
    let mut p: Provider = decode(row.get("document"))?;
    p.id = Some(id);
    p.transport = decrypt(row.get("transport_ciphertext"), json!(p.transport), key)?;
    p.models = c
        .query(
            "SELECT document FROM llm_model WHERE provider_id=$1 ORDER BY model_id",
            &[&id],
        )
        .await?
        .into_iter()
        .map(|r| decode(r.get(0)))
        .collect::<Result<Vec<_>>>()?;
    let ciphertext: Option<Vec<u8>> = row.get("credential_ciphertext");
    p.database_credential_configured = ciphertext.is_some();
    p.credential_configured = credentials::status(ciphertext.is_some(), &p.key_env).1;
    Ok(p)
}
pub(super) async fn read(pool: &Pool, key: &str) -> Result<Value> {
    let mut c = pool.get().await?;
    let tx = c
        .build_transaction()
        .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
        .read_only(true)
        .start()
        .await?;
    let s = state(&tx, key).await?;
    let mut providers = vec![];
    let mut effective = Value::Null;
    for row in tx
        .query("SELECT id FROM llm_provider ORDER BY updated_at,id", &[])
        .await?
    {
        let p = provider(&tx, row.get(0), key).await?;
        if p.id == s.provider_id {
            let mut resolved = resolve(&s.global, &p.transport)?;
            resolved.provider_id = p.id;
            effective = resolved.preview();
        }
        providers.push(p.redact());
    }
    tx.commit().await?;
    Ok(
        json!({"revision":s.revision,"enabled":s.enabled,"provider_id":s.provider_id,"model_id":s.model_id,"global":s.global.redact(),"providers":providers,"presets":presets(),"effective":effective,"ioc_prompt":s.ioc_prompt,"default_ioc_prompt":DEFAULT_AI_PROMPT,"prompt_version":ai_prompt_version(&s.ioc_prompt),"prompt_max_bytes":MAX_AI_PROMPT_BYTES}),
    )
}
async fn lock(tx: &Transaction<'_>, expected: i64) -> Result<()> {
    // Matches IOC publication's lock order. Every writer locks the runtime fence first.
    let r = tx
        .query_one(
            "SELECT revision FROM intel_settings WHERE singleton FOR UPDATE",
            &[],
        )
        .await?;
    tx.query_one(
        "SELECT revision FROM llm_settings WHERE singleton FOR UPDATE",
        &[],
    )
    .await?;
    if r.get::<_, i64>(0) != expected {
        return Err(Error::conflict());
    }
    Ok(())
}
async fn publish(tx: &Transaction<'_>, s: &State, key: &str) -> Result<i64> {
    validate_ai_prompt(&s.ioc_prompt)?;
    let (mut document, ciphertext) = if let (Some(id), Some(model)) =
        (s.provider_id, s.model_id.as_deref())
    {
        let p = provider(tx, id, key).await?;
        if !p.models.iter().any(|m| {
            m.id == model && m.available && matches!(m.protocol.as_str(), "" | "chat" | "responses")
        }) {
            return Err(Error::bad("llm_model_unavailable"));
        }
        resolve(&s.global, &p.transport)?;
        let settings = p.settings(model, s.enabled)?;
        let row = tx
            .query_one(
                "SELECT credential_ciphertext FROM llm_provider WHERE id=$1",
                &[&id],
            )
            .await?;
        (json!(settings), row.get::<_, Option<Vec<u8>>>(0))
    } else {
        if s.enabled || s.provider_id.is_some() || s.model_id.is_some() {
            return Err(invalid());
        }
        let row = tx
            .query_one("SELECT document FROM intel_settings WHERE singleton", &[])
            .await?;
        let mut document: Value = row.get(0);
        document["ai_enabled"] = json!(false);
        (document, None)
    };
    document["llm_managed"] = json!(true);
    document["ai_prompt"] = json!(s.ioc_prompt);
    document["llm_provider_id"] = json!(s.provider_id);
    let revision:i64=tx.query_one("UPDATE intel_settings SET document=$1,credential_ciphertext=$2,revision=revision+1,updated_at=NOW() WHERE singleton RETURNING revision",&[&document,&ciphertext]).await?.get(0);
    let public = json!(s.global.redact());
    let encrypted = encrypt(&s.global, key)?;
    tx.execute("UPDATE llm_settings SET revision=$1,enabled=$2,provider_id=$3,model_id=$4,global_config=$5,transport_ciphertext=$6 WHERE singleton",&[&revision,&s.enabled,&s.provider_id,&s.model_id,&public,&encrypted]).await?;
    Ok(revision)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SettingsInput {
    pub expected_revision: i64,
    pub enabled: bool,
    pub provider_id: Option<Uuid>,
    pub model_id: Option<String>,
    pub global: Transport,
}
pub(super) async fn save_settings(
    pool: &Pool,
    mut input: SettingsInput,
    key: &str,
    user: &UserBaseI,
    context: &AuditContext,
) -> Result<Value> {
    admin(user)?;
    let mut c = pool.get().await?;
    let tx = c.transaction().await?;
    lock(&tx, input.expected_revision).await?;
    let old = state(&tx, key).await?;
    input.global.preserve(&old.global);
    input.global.validate(true)?;
    let s = State {
        revision: old.revision,
        enabled: input.enabled,
        provider_id: input.provider_id,
        model_id: input.model_id,
        global: input.global,
        ioc_prompt: old.ioc_prompt,
    };
    let revision = publish(&tx, &s, key).await?;
    audit(
        &tx,
        user,
        context,
        "llm.settings.save",
        "settings",
        json!({"revision":revision,"enabled":s.enabled,"provider_id":s.provider_id}),
    )
    .await?;
    tx.commit().await?;
    Ok(json!({"revision":revision}))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PromptInput {
    pub expected_revision: i64,
    pub prompt: String,
}

pub(super) async fn save_prompt(
    pool: &Pool,
    input: PromptInput,
    key: &str,
    user: &UserBaseI,
    context: &AuditContext,
) -> Result<Value> {
    admin(user)?;
    validate_ai_prompt(&input.prompt)?;
    let mut c = pool.get().await?;
    let tx = c.transaction().await?;
    lock(&tx, input.expected_revision).await?;
    let mut s = state(&tx, key).await?;
    s.ioc_prompt = input.prompt;
    let revision = publish(&tx, &s, key).await?;
    let default = s.ioc_prompt.is_empty();
    let effective = if default {
        DEFAULT_AI_PROMPT
    } else {
        &s.ioc_prompt
    };
    audit(&tx, user, context, if default { "llm.prompt.reset" } else { "llm.prompt.save" },
        "settings", json!({"revision":revision,"prompt_version":ai_prompt_version(&s.ioc_prompt),
            "prompt_hash":digest(effective.as_bytes()),"prompt_source":if default {"default"} else {"custom"}})).await?;
    tx.commit().await?;
    Ok(
        json!({"revision":revision,"ioc_prompt":s.ioc_prompt,"prompt_version":ai_prompt_version(&s.ioc_prompt)}),
    )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProviderInput {
    pub expected_revision: i64,
    pub provider: Provider,
}
pub(super) async fn save_provider(
    pool: &Pool,
    id: Option<Uuid>,
    mut input: ProviderInput,
    key: &str,
    user: &UserBaseI,
    context: &AuditContext,
) -> Result<Value> {
    admin(user)?;
    let mut c = pool.get().await?;
    let tx = c.transaction().await?;
    lock(&tx, input.expected_revision).await?;
    let s = state(&tx, key).await?;
    let p = &mut input.provider;
    if let Some(id) = id {
        let old = provider(&tx, id, key).await?;
        p.transport.preserve(&old.transport);
    }
    p.validate()?;
    resolve(&s.global, &p.transport)?;
    let encrypted = credentials::encrypt_update(&p.credential, p.clear_credential, key)?;
    let id = id.unwrap_or_else(Uuid::now_v7);
    p.id = Some(id);
    let doc = json!(p.redact());
    let transport = encrypt(&p.transport, key)?;
    tx.execute("INSERT INTO llm_provider(id,document,transport_ciphertext,credential_ciphertext) VALUES($1,$2,$3,$4) ON CONFLICT(id) DO UPDATE SET document=$2,transport_ciphertext=$3,credential_ciphertext=CASE WHEN $5 THEN NULL ELSE COALESCE($4,llm_provider.credential_ciphertext) END,updated_at=NOW()",&[&id,&doc,&transport,&encrypted,&p.clear_credential]).await?;
    tx.execute("DELETE FROM llm_model WHERE provider_id=$1", &[&id])
        .await?;
    for model in &p.models {
        tx.execute(
            "INSERT INTO llm_model(provider_id,model_id,document) VALUES($1,$2,$3)",
            &[&id, &model.id, &json!(model)],
        )
        .await?;
    }
    let revision = publish(&tx, &s, key).await?;
    audit(&tx,user,context,"llm.provider.save",&id.to_string(),json!({"revision":revision,"credential_changed":p.clear_credential||encrypted.is_some(),"model_count":p.models.len()})).await?;
    tx.commit().await?;
    Ok(json!({"revision":revision,"id":id}))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DeleteInput {
    pub expected_revision: i64,
    #[serde(default)]
    pub pause_extraction: bool,
}
pub(super) async fn delete(
    pool: &Pool,
    id: Uuid,
    input: DeleteInput,
    key: &str,
    user: &UserBaseI,
    context: &AuditContext,
) -> Result<Value> {
    admin(user)?;
    let mut c = pool.get().await?;
    let tx = c.transaction().await?;
    lock(&tx, input.expected_revision).await?;
    let mut s = state(&tx, key).await?;
    if s.provider_id == Some(id) {
        if !input.pause_extraction {
            return Err(Error::bad("llm_provider_in_use"));
        }
        s.enabled = false;
        s.provider_id = None;
        s.model_id = None;
    }
    if tx
        .execute("DELETE FROM llm_provider WHERE id=$1", &[&id])
        .await?
        == 0
    {
        return Err(Error::missing());
    }
    let revision = publish(&tx, &s, key).await?;
    audit(
        &tx,
        user,
        context,
        "llm.provider.delete",
        &id.to_string(),
        json!({"revision":revision,"enabled":s.enabled}),
    )
    .await?;
    tx.commit().await?;
    Ok(json!({"revision":revision}))
}
pub(in crate::threat_intel) async fn runtime_transport(
    pool: &Pool,
    revision: i64,
    key: &str,
) -> Result<Resolved> {
    let mut c = pool.get().await?;
    let tx = c
        .build_transaction()
        .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
        .read_only(true)
        .start()
        .await?;
    let row = tx
        .query_opt(
            "SELECT document FROM intel_settings WHERE singleton AND revision=$1",
            &[&revision],
        )
        .await?
        .ok_or_else(Error::conflict)?;
    let document: Value = row.get(0);
    let resolved = if let Some(id) = document.get("llm_provider_id").and_then(Value::as_str) {
        let id = Uuid::parse_str(id).map_err(|_| invalid())?;
        let s = state(&tx, key).await?;
        if s.revision != revision {
            return Err(Error::conflict());
        }
        let p = provider(&tx, id, key).await?;
        let mut resolved = resolve(&s.global, &p.transport)?;
        resolved.provider_id = Some(id);
        resolved
    } else {
        resolve(&Transport::global(), &Transport::default())?
    };
    tx.commit().await?;
    Ok(resolved)
}
pub(super) async fn debug_runtime(
    pool: &Pool,
    id: Uuid,
    model: &str,
    key: &str,
) -> Result<(Settings, Resolved, String)> {
    let mut c = pool.get().await?;
    let tx = c
        .build_transaction()
        .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
        .read_only(true)
        .start()
        .await?;
    let s = state(&tx, key).await?;
    let p = provider(&tx, id, key).await?;
    if !p.models.iter().any(|m| {
        m.id == model && m.available && matches!(m.protocol.as_str(), "" | "chat" | "responses")
    }) {
        return Err(Error::bad("llm_model_unavailable"));
    }
    let settings = p.settings(model, false)?;
    let mut transport = resolve(&s.global, &p.transport)?;
    transport.provider_id = Some(id);
    let row = tx
        .query_one(
            "SELECT credential_ciphertext FROM llm_provider WHERE id=$1",
            &[&id],
        )
        .await?;
    let cipher: Option<Vec<u8>> = row.get(0);
    let credential = credentials::resolve_with_authorization(
        cipher.as_deref(),
        &p.key_env,
        key,
        transport.headers.contains_key("authorization"),
    )?
    .unwrap_or_default();
    if credential.is_empty() && !transport.headers.contains_key("authorization") {
        return Err(Error::bad("intel_credential_missing"));
    }
    tx.commit().await?;
    Ok((settings, transport, credential))
}
pub(super) async fn models(pool: &Pool, id: Uuid, key: &str) -> Result<Vec<Model>> {
    let mut c = pool.get().await?;
    let tx = c
        .build_transaction()
        .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
        .read_only(true)
        .start()
        .await?;
    let s = state(&tx, key).await?;
    let p = provider(&tx, id, key).await?;
    if p.models_url.is_empty() {
        return Err(Error::bad("llm_models_url_required"));
    }
    let resolved = resolve(&s.global, &p.transport)?;
    let row = tx
        .query_one(
            "SELECT credential_ciphertext FROM llm_provider WHERE id=$1",
            &[&id],
        )
        .await?;
    let cipher: Option<Vec<u8>> = row.get(0);
    let credential = credentials::resolve_with_authorization(
        cipher.as_deref(),
        &p.key_env,
        key,
        resolved.headers.contains_key("authorization"),
    )?
    .unwrap_or_default();
    tx.commit().await?;
    let bytes = transport::get(&p.models_url, &resolved, &credential).await?;
    normalize_models(
        serde_json::from_slice(&bytes).map_err(|_| Error::bad("llm_invalid_model_list"))?,
        &p,
    )
}
