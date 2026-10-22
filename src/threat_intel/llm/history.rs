//! Opt-in encrypted transcripts. Capture never stores provider credentials.
use super::*;
use actix_web::{HttpRequest, web};
use tokio::sync::mpsc;

#[derive(Clone, Deserialize, Serialize)]
pub(super) struct Session {
    pub wire: String,
    pub header: String,
    pub value: Option<String>,
    pub endpoint: String,
    pub protocol: String,
}
impl Session {
    pub fn capture(settings: &Settings, transport: &Resolved, wire: &str) -> Result<Self> {
        let headers = transport.request_headers("", wire)?;
        Ok(Self {
            wire: wire.into(),
            header: transport.session_header.clone(),
            value: headers
                .get(&transport.session_header)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned),
            endpoint: settings.ai_endpoint.clone(),
            protocol: settings.ai_protocol.clone(),
        })
    }
    pub fn restore(&self, settings: &Settings, transport: &mut Resolved) -> Result<()> {
        if self.endpoint != settings.ai_endpoint || self.protocol != settings.ai_protocol {
            return Err(Error::bad("llm_history_configuration_changed"));
        }
        transport.headers.remove(&transport.session_header);
        transport.headers.remove(&self.header);
        transport.session_mode = "disabled".into();
        transport.session_header = self.header.clone();
        if let Some(value) = &self.value {
            transport.headers.insert(
                header_name(&self.header)?,
                reqwest::header::HeaderValue::from_str(value).map_err(|_| invalid())?,
            );
        }
        Ok(())
    }
}

pub(super) struct Capture {
    id: Uuid,
    run: Uuid,
    document: Value,
    pool: Pool,
    key: String,
}

pub(super) fn messages_with_metadata(mut messages: Value, previous: Option<&Value>) -> Value {
    if let Some(items) = messages.as_array_mut() {
        for message in items {
            message["complete"] = json!(true);
        }
    }
    if let (Some(messages), Some(previous)) =
        (messages.as_array_mut(), previous.and_then(Value::as_array))
    {
        for (message, old) in messages.iter_mut().zip(previous) {
            if message["role"] != old["role"] || message["content"] != old["content"] {
                break;
            }
            if message["role"] == "assistant" {
                for field in ["reasoning", "usage", "elapsed_ms", "parameters", "status"] {
                    if let Some(value) = old.get(field) {
                        message[field] = value.clone();
                    }
                }
            }
        }
    }
    messages
}
pub(super) struct NewConversation {
    pub kind: &'static str,
    pub owner: Option<i32>,
    pub session_id: Uuid,
    pub article_id: Option<Uuid>,
    pub provider_id: Option<Uuid>,
    pub model_id: String,
    pub document: Value,
}
pub(super) async fn begin(
    pool: &Pool,
    mut entry: NewConversation,
    key: &str,
) -> Result<Option<Capture>> {
    let c = pool.get().await?;
    let enabled: bool = c.query_one("SELECT CASE WHEN $1='ioc' THEN retain_ioc_conversations ELSE retain_debug_conversations END FROM llm_settings WHERE singleton", &[&entry.kind]).await?.get(0);
    if !enabled {
        return Ok(None);
    }
    if let Some(request) = entry.document["request"].as_object_mut() {
        request.remove("messages");
        request.remove("input");
    }
    if !entry.document["messages"].is_array() {
        return Err(invalid());
    }
    if entry.document.to_string().len() > 32 * 1024 * 1024 {
        return Err(Error::bad("llm_history_too_large"));
    }
    let id = Uuid::now_v7();
    let run = Uuid::now_v7();
    let cipher = encrypt(&entry.document, key)?;
    let id: Uuid = c.query_one("INSERT INTO llm_conversation(id,kind,owner_id,session_id,article_id,provider_id,model_id,run_id,document_ciphertext) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id", &[&id,&entry.kind,&entry.owner,&entry.session_id,&entry.article_id,&entry.provider_id,&entry.model_id,&run,&cipher]).await?.get(0);
    Ok(Some(Capture {
        id,
        run,
        document: entry.document,
        pool: pool.clone(),
        key: key.into(),
    }))
}

pub(super) fn spawn(
    capture: Option<Capture>,
) -> (
    Option<Uuid>,
    Option<mpsc::Sender<Value>>,
    tokio::task::JoinHandle<bool>,
) {
    let id = capture.as_ref().map(|c| c.id);
    let (tx, mut rx) = mpsc::channel::<Value>(16);
    let task = tokio::spawn(async move {
        let Some(mut c) = capture else {
            return true;
        };
        let mut text = String::new();
        let mut reasoning = String::new();
        let mut terminal = json!({"type":"error","code":"llm_cancelled"});
        while let Some(event) = rx.recv().await {
            match event["type"].as_str() {
                Some("delta") => {
                    if let Some(s) = event["text"].as_str() {
                        text.push_str(s);
                    }
                }
                Some("reasoning") => {
                    if let Some(s) = event["text"].as_str() {
                        reasoning.push_str(s);
                    }
                }
                Some("done" | "error") => {
                    terminal = event;
                    break;
                }
                _ => (),
            }
            if text.len() + reasoning.len() > MAX_AI_RESPONSE_BYTES {
                terminal = json!({"type":"error","code":"llm_response_too_large"});
                break;
            }
        }
        let complete = terminal["type"] == "done";
        if let Some(s) = terminal["text"].as_str() {
            text = s.into();
        }
        if let Some(s) = terminal["reasoning"].as_str().filter(|s| !s.is_empty()) {
            reasoning = s.into();
        }
        let status = if complete {
            "completed"
        } else if terminal["code"] == "llm_cancelled" {
            "cancelled"
        } else {
            "failed"
        };
        let parameters = c.document["parameters"].clone();
        c.document["messages"].as_array_mut().expect("capture messages").push(json!({"role":"assistant","content":text,"reasoning":reasoning,"complete":complete,"status":status,"usage":terminal["usage"],"elapsed_ms":terminal["elapsed_ms"],"parameters":parameters}));
        c.document["status"] = json!(status);
        c.document["error_code"] = terminal["code"].clone();
        let result = async {
            if c.document.to_string().len() > 32 * 1024 * 1024 { return Err(Error::bad("llm_history_too_large")); }
            let cipher = encrypt(&c.document, &c.key)?;
            let changed = c.pool.get().await?.execute("UPDATE llm_conversation SET document_ciphertext=$3,status=$4,updated_at=NOW() WHERE id=$1 AND run_id=$2", &[&c.id,&c.run,&cipher,&status]).await?;
            if changed == 0 { return Err(Error::missing()); }
            Ok::<_, Error>(())
        }.await;
        if result.is_err() {
            tracing::warn!("LLM transcript persistence failed");
        }
        result.is_ok()
    });
    (id, id.map(|_| tx), task)
}

pub(super) async fn internal(pool: &Pool, id: Uuid, user: &UserBaseI, key: &str) -> Result<Value> {
    admin(user)?;
    let row = pool.get().await?.query_opt("SELECT session_id,provider_id,model_id,document_ciphertext FROM llm_conversation WHERE id=$1 AND (owner_id IS NULL OR owner_id=$2)", &[&id,&user.id]).await?.ok_or_else(Error::missing)?;
    let mut data: Value = decrypt(Some(row.get(3)), Value::Null, key)?;
    data["session_id"] = json!(row.get::<_, Uuid>(0));
    data["provider_id"] = json!(row.get::<_, Option<Uuid>>(1));
    data["model_id"] = json!(row.get::<_, String>(2));
    Ok(data)
}
fn no_store(mut response: HttpResponse) -> HttpResponse {
    response.headers_mut().insert(
        actix_web::http::header::CACHE_CONTROL,
        actix_web::http::header::HeaderValue::from_static("no-store"),
    );
    response
}
async fn list(
    pool: web::Data<Pool>,
    user: UserBaseI,
    query: web::Query<ListQuery>,
) -> HttpResponse {
    no_store(response(async {
        admin(&user)?;
        let limit = 30_i64;
        let offset = query.offset.unwrap_or(0).clamp(0,100000);
        let c = pool.get().await?;
        let total: i64 = c.query_one("SELECT count(*) FROM llm_conversation WHERE owner_id IS NULL OR owner_id=$1", &[&user.id]).await?.get(0);
        let rows = c.query("SELECT id,kind,session_id,article_id,provider_id,model_id,status,created_at,updated_at FROM llm_conversation WHERE owner_id IS NULL OR owner_id=$1 ORDER BY updated_at DESC,id DESC LIMIT $2 OFFSET $3", &[&user.id,&limit,&offset]).await?;
        let items: Vec<Value> = rows.into_iter().map(|r| json!({"id":r.get::<_,Uuid>(0),"kind":r.get::<_,String>(1),"session_id":r.get::<_,Uuid>(2),"article_id":r.get::<_,Option<Uuid>>(3),"provider_id":r.get::<_,Option<Uuid>>(4),"model_id":r.get::<_,String>(5),"status":r.get::<_,String>(6),"created_at":r.get::<_,chrono::DateTime<chrono::Utc>>(7),"updated_at":r.get::<_,chrono::DateTime<chrono::Utc>>(8)})).collect();
        Ok(json!({"items":items,"total":total,"offset":offset,"limit":limit}))
    }.await))
}
#[derive(Deserialize)]
struct ListQuery {
    offset: Option<i64>,
}
async fn detail(
    pool: web::Data<Pool>,
    config: web::Data<crate::config::ServerConfig>,
    user: UserBaseI,
    id: web::Path<Uuid>,
) -> HttpResponse {
    no_store(response(
        async {
            let mut data = internal(&pool, *id, &user, &config.encrypt_key).await?;
            data["protocol"] = data["session"]["protocol"].clone();
            data.as_object_mut().unwrap().remove("session");
            Ok(data)
        }
        .await,
    ))
}
async fn delete(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    id: web::Path<Uuid>,
) -> HttpResponse {
    response(async {
        admin(&user)?;
        let c = pool.get().await?;
        let changed = c.execute("DELETE FROM llm_conversation WHERE id=$1 AND (owner_id IS NULL OR owner_id=$2)", &[&*id,&user.id]).await?;
        if changed == 0 { return Err(Error::missing()); }
        audit(&c,&user,&AuditContext::from_request(&req),"llm.conversation.delete",&id.to_string(),json!({})).await?;
        Ok(json!({"deleted":true}))
    }.await)
}
pub(super) fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/conversations", web::get().to(list))
        .route("/conversations/{id}", web::get().to(detail))
        .route("/conversations/{id}", web::delete().to(delete));
}

pub(super) fn terminal(value: &Value, protocol: &str) -> Value {
    match ai::response_content(value.to_string().as_bytes(), protocol) {
        Ok((text, usage)) => {
            json!({"type":"done","text":text,"usage":usage,"reasoning":debug::reasoning_text(value,protocol)})
        }
        Err(error) => {
            let text = if protocol == "responses" {
                value["output"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|item| item["type"] == "message")
                    .flat_map(|item| item["content"].as_array().into_iter().flatten())
                    .filter(|part| part["type"] == "output_text")
                    .filter_map(|part| part["text"].as_str())
                    .collect::<String>()
            } else {
                value
                    .pointer("/choices/0/message/content")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned()
            };
            let mut event = json!({"type":"error","code":error.code,"reasoning":debug::reasoning_text(value,protocol)});
            if !text.is_empty() {
                event["text"] = json!(text);
            }
            event
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(in crate::threat_intel) async fn ioc_request(
    pool: &Pool,
    article: Uuid,
    settings: &Settings,
    key: &str,
    encryption_key: &str,
    blocks: &Value,
    url: &str,
    transport: &Resolved,
    wire: &str,
) -> Result<(Vec<u8>, Value)> {
    let capture = if transport.provider_id.is_some() {
        let request = ai::retained_payload(settings, blocks, url);
        let messages = request
            .get("messages")
            .or_else(|| request.get("input"))
            .cloned()
            .unwrap_or(json!([]));
        begin(pool,NewConversation { kind:"ioc",owner:None,session_id:Uuid::now_v7(),article_id:Some(article),provider_id:transport.provider_id,model_id:settings.ai_model.clone(),
            document:json!({"messages":messages,"request":request,"parameters":debug::Parameters::default().effective(settings,transport),"session":Session::capture(settings,transport,wire)?}) },encryption_key).await?
    } else {
        None
    };
    let (_, events, task) = spawn(capture);
    let result = ai::request(settings, key, blocks, url, transport, wire, events.clone()).await;
    if let Some(events) = events {
        let event = match &result {
            Ok((bytes, _)) => terminal(
                &serde_json::from_slice(bytes).unwrap_or(Value::Null),
                &settings.ai_protocol,
            ),
            Err(error) => json!({"type":"error","code":error.code}),
        };
        let _ = events.send(event).await;
    }
    let _ = task.await;
    result
}

#[cfg(test)]
mod tests {
    use super::super::super::tests::{database, encryption_key, user};
    use super::*;

    fn settings() -> Settings {
        decode(json!({"ai_endpoint":"https://api.example/v1","ai_model":"fixture","ai_key_env":"","ai_enabled":false})).unwrap()
    }
    #[test]
    fn failed_responses_keep_partial_output_without_erasing_streamed_text() {
        let event = terminal(
            &json!({"status":"incomplete","incomplete_details":{"reason":"max_output_tokens"},"output":[{"type":"message","content":[{"type":"output_text","text":"partial response"}]}]}),
            "responses",
        );
        assert_eq!(event["type"], "error");
        assert_eq!(event["text"], "partial response");
        let empty = terminal(&json!({}), "chat");
        assert!(empty.get("text").is_none());
    }
    #[test]
    fn original_session_header_survives_replay_and_endpoint_changes_are_rejected() {
        let settings = settings();
        for mode in ["auto", "fixed", "disabled"] {
            let mut transport = Resolved {
                session_mode: mode.into(),
                session_header: "x-original-session".into(),
                session_value: "fixed-private-session".into(),
                ..Resolved::default()
            };
            let original =
                Session::capture(&settings, &transport, "ioc-original-wire-session").unwrap();
            transport.session_mode = "auto".into();
            transport.session_header = "x-different-session".into();
            transport.session_value = "different".into();
            original.restore(&settings, &mut transport).unwrap();
            let headers = transport
                .request_headers("", "new-debug-session-must-not-be-used")
                .unwrap();
            assert!(headers.get("x-different-session").is_none());
            assert_eq!(
                headers
                    .get("x-original-session")
                    .and_then(|v| v.to_str().ok()),
                original.value.as_deref()
            );
            assert_eq!(original.wire, "ioc-original-wire-session");
            let mut changed = settings.clone();
            changed.ai_endpoint = "https://other.example/v1".into();
            assert_eq!(
                original.restore(&changed, &mut transport).unwrap_err().code,
                "llm_history_configuration_changed"
            );
        }
    }
    #[test]
    fn metadata_is_preserved_only_for_the_exact_sent_prefix() {
        let old = json!([{"role":"user","content":"question"},{"role":"assistant","content":"answer","reasoning":"thought","complete":true}]);
        let messages = messages_with_metadata(
            json!([{"role":"user","content":"question"},{"role":"assistant","content":"answer"},{"role":"user","content":"next"}]),
            Some(&old),
        );
        assert_eq!(messages[1]["reasoning"], "thought");
        assert_eq!(messages[1]["complete"], true);
        let changed = messages_with_metadata(
            json!([{"role":"user","content":"edited"},{"role":"assistant","content":"answer"}]),
            Some(&old),
        );
        assert!(changed[1].get("reasoning").is_none());
    }
    #[tokio::test]
    #[ignore = "requires disposable INTEL_TEST_DATABASE_URL"]
    async fn opt_in_history_encrypts_partial_reasoning_enforces_ownership_and_cannot_resurrect_deleted_rows()
     {
        let (pool, c, schema) = database().await;
        let key = encryption_key();
        for _ in 0..2 {
            c.batch_execute(include_str!("../../../source/database/migrate_llm.sql"))
                .await
                .unwrap();
        }
        let session_id = Uuid::now_v7();
        let entry = || NewConversation {
            kind: "debug",
            owner: Some(1),
            session_id,
            article_id: None,
            provider_id: None,
            model_id: "fixture".into(),
            document: json!({"messages":[{"role":"user","content":"private-question"}],"request":{},"parameters":{},"session":Session::capture(&settings(),&Resolved::default(),"private-wire-session").unwrap()}),
        };
        assert!(begin(&pool, entry(), &key).await.unwrap().is_none());
        c.execute(
            "UPDATE llm_settings SET retain_debug_conversations=TRUE WHERE singleton",
            &[],
        )
        .await
        .unwrap();
        let (id, tx, task) = spawn(begin(&pool, entry(), &key).await.unwrap());
        let id = id.unwrap();
        let tx = tx.unwrap();
        tx.send(json!({"type":"reasoning","text":"private-thought"}))
            .await
            .unwrap();
        tx.send(json!({"type":"delta","text":"partial-answer"}))
            .await
            .unwrap();
        drop(tx);
        assert!(task.await.unwrap());
        let record = internal(&pool, id, &user(1), &key).await.unwrap();
        assert_eq!(record["messages"][1]["reasoning"], "private-thought");
        assert_eq!(record["messages"][1]["complete"], false);
        assert_eq!(record["status"], "cancelled");
        let response = detail(
            web::Data::new(pool.clone()),
            web::Data::new(super::super::super::tests::server_config()),
            user(1),
            web::Path::from(id),
        )
        .await;
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
        let public: Value = serde_json::from_slice(
            &actix_web::body::to_bytes(response.into_body())
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(!public.to_string().contains("private-wire-session"));
        assert!(public["data"].get("session").is_none());
        let bytes: Vec<u8> = c
            .query_one(
                "SELECT document_ciphertext FROM llm_conversation WHERE id=$1",
                &[&id],
            )
            .await
            .unwrap()
            .get(0);
        assert!(!String::from_utf8_lossy(&bytes).contains("private-thought"));
        let mut other = user(1);
        other.id = 2;
        assert_eq!(
            internal(&pool, id, &other, &key).await.unwrap_err().code,
            "intel_not_found"
        );
        assert_eq!(
            internal(&pool, id, &user(0), &key).await.unwrap_err().code,
            "intel_admin_required"
        );
        let (second, tx, task) = spawn(begin(&pool, entry(), &key).await.unwrap());
        assert_ne!(second.unwrap(), id); // Each attempt is a recoverable snapshot, even in the same session.
        let request = actix_web::test::TestRequest::default().to_http_request();
        let response = delete(
            request,
            web::Data::new(pool.clone()),
            user(1),
            web::Path::from(second.unwrap()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        tx.unwrap()
            .send(json!({"type":"done","text":"late answer"}))
            .await
            .unwrap();
        assert!(!task.await.unwrap());
        assert!(
            internal(&pool, second.unwrap(), &user(1), &key)
                .await
                .is_err()
        );
        let mut ioc = entry();
        ioc.kind = "ioc";
        ioc.owner = None;
        assert!(begin(&pool, ioc, &key).await.unwrap().is_none());
        c.execute(
            "UPDATE llm_settings SET retain_ioc_conversations=TRUE WHERE singleton",
            &[],
        )
        .await
        .unwrap();
        let article = Uuid::now_v7();
        let source: Uuid = c
            .query_one("SELECT id FROM intel_source LIMIT 1", &[])
            .await
            .unwrap()
            .get(0);
        c.execute("INSERT INTO intel_article(id,source_id,source_revision,url,title,feed_hash) VALUES($1,$2,1,'https://research.example/article','fixture article','fixture')",&[&article,&source]).await.unwrap();
        let mut local = settings();
        local.ai_endpoint = "https://127.0.0.1/v1".into();
        let transport = Resolved {
            provider_id: Some(Uuid::now_v7()),
            session_header: "x-session".into(),
            session_mode: "auto".into(),
            ..Resolved::default()
        };
        assert!(
            ioc_request(
                &pool,
                article,
                &local,
                "not-the-server-encryption-key",
                &key,
                &json!([]),
                "https://research.example/article",
                &transport,
                "original-ioc-session"
            )
            .await
            .is_err()
        );
        let ioc_id: Uuid = c
            .query_one("SELECT id FROM llm_conversation WHERE kind='ioc'", &[])
            .await
            .unwrap()
            .get(0);
        let ioc_record = internal(&pool, ioc_id, &other, &key).await.unwrap();
        assert_eq!(ioc_record["session"]["wire"], "original-ioc-session");
        assert_eq!(ioc_record["status"], "failed");
        c.batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }
}
