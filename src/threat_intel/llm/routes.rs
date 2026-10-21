use super::*;
use actix_web::{HttpRequest, web};
use std::{
    collections::HashSet,
    sync::{Mutex, OnceLock},
};

async fn read(
    pool: web::Data<Pool>,
    config: web::Data<crate::config::ServerConfig>,
    user: UserBaseI,
) -> HttpResponse {
    response(
        async {
            admin(&user)?;
            storage::read(&pool, &config.encrypt_key).await
        }
        .await,
    )
}
async fn settings(
    req: HttpRequest,
    pool: web::Data<Pool>,
    config: web::Data<crate::config::ServerConfig>,
    user: UserBaseI,
    input: web::Json<storage::SettingsInput>,
) -> HttpResponse {
    response(
        storage::save_settings(
            &pool,
            input.into_inner(),
            &config.encrypt_key,
            &user,
            &AuditContext::from_request(&req),
        )
        .await,
    )
}
async fn prompt(
    req: HttpRequest,
    pool: web::Data<Pool>,
    config: web::Data<crate::config::ServerConfig>,
    user: UserBaseI,
    input: web::Json<storage::PromptInput>,
) -> HttpResponse {
    response(
        storage::save_prompt(
            &pool,
            input.into_inner(),
            &config.encrypt_key,
            &user,
            &AuditContext::from_request(&req),
        )
        .await,
    )
}
async fn create(
    req: HttpRequest,
    pool: web::Data<Pool>,
    config: web::Data<crate::config::ServerConfig>,
    user: UserBaseI,
    input: web::Json<storage::ProviderInput>,
) -> HttpResponse {
    response(
        storage::save_provider(
            &pool,
            None,
            input.into_inner(),
            &config.encrypt_key,
            &user,
            &AuditContext::from_request(&req),
        )
        .await,
    )
}
async fn update(
    req: HttpRequest,
    pool: web::Data<Pool>,
    config: web::Data<crate::config::ServerConfig>,
    user: UserBaseI,
    id: web::Path<Uuid>,
    input: web::Json<storage::ProviderInput>,
) -> HttpResponse {
    response(
        storage::save_provider(
            &pool,
            Some(*id),
            input.into_inner(),
            &config.encrypt_key,
            &user,
            &AuditContext::from_request(&req),
        )
        .await,
    )
}
async fn delete(
    req: HttpRequest,
    pool: web::Data<Pool>,
    config: web::Data<crate::config::ServerConfig>,
    user: UserBaseI,
    id: web::Path<Uuid>,
    input: web::Json<storage::DeleteInput>,
) -> HttpResponse {
    response(
        storage::delete(
            &pool,
            *id,
            input.into_inner(),
            &config.encrypt_key,
            &user,
            &AuditContext::from_request(&req),
        )
        .await,
    )
}
async fn models(
    pool: web::Data<Pool>,
    config: web::Data<crate::config::ServerConfig>,
    user: UserBaseI,
    id: web::Path<Uuid>,
) -> HttpResponse {
    response(
        async {
            admin(&user)?;
            storage::models(&pool, *id, &config.encrypt_key).await
        }
        .await,
    )
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Message {
    pub role: String,
    pub content: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ChatInput {
    pub provider_id: Uuid,
    pub model_id: String,
    pub session_id: Uuid,
    pub messages: Vec<Message>,
}
impl ChatInput {
    pub fn validate(&self) -> Result<()> {
        if self.model_id.len() > 100
            || self.messages.is_empty()
            || self.messages.len() > 64
            || self.messages.iter().map(|m| m.content.len()).sum::<usize>() > 128 * 1024
            || self.messages.iter().enumerate().any(|(i, m)| {
                m.content.trim().is_empty()
                    || !matches!(m.role.as_str(), "user" | "assistant" | "system")
                    || (m.role == "system" && i != 0)
            })
            || self.messages.last().is_none_or(|m| m.role != "user")
        {
            return Err(Error::bad("llm_invalid_messages"));
        }
        Ok(())
    }
}
static ACTIVE: OnceLock<Mutex<HashSet<i32>>> = OnceLock::new();
struct Lease(i32);
impl Lease {
    fn acquire(user: i32) -> Result<Self> {
        let mut active = ACTIVE
            .get_or_init(Default::default)
            .lock()
            .map_err(|_| Error::unavailable())?;
        if active.len() >= 4 || !active.insert(user) {
            return Err(Error {
                status: StatusCode::TOO_MANY_REQUESTS,
                code: "llm_debug_busy",
                diagnostic: json!({}),
            });
        }
        Ok(Self(user))
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        if let Some(active) = ACTIVE.get()
            && let Ok(mut active) = active.lock()
        {
            active.remove(&self.0);
        }
    }
}

async fn chat(
    req: HttpRequest,
    pool: web::Data<Pool>,
    config: web::Data<crate::config::ServerConfig>,
    user: UserBaseI,
    input: web::Json<ChatInput>,
) -> HttpResponse {
    let input = input.into_inner();
    let setup = async {
        admin(&user)?;
        input.validate()?;
        let lease = Lease::acquire(user.id)?;
        let (settings, transport, key) = storage::debug_runtime(
            &pool,
            input.provider_id,
            &input.model_id,
            &config.encrypt_key,
        )
        .await?;
        let c = pool.get().await?;
        audit(
            &c,
            &user,
            &AuditContext::from_request(&req),
            "llm.debug.request",
            &input.provider_id.to_string(),
            json!({"model":input.model_id,"stream":transport.stream}),
        )
        .await?;
        Ok::<_, Error>((lease, settings, transport, key))
    }
    .await;
    let (lease, settings, transport, key) = match setup {
        Ok(v) => v,
        Err(error) => return response::<Value>(Err(error)),
    };
    let messages = json!(input.messages);
    let mut payload = if settings.ai_protocol == "responses" {
        json!({"model":settings.ai_model,"input":messages,"max_output_tokens":settings.ai_max_output_tokens,"store":false})
    } else {
        json!({"model":settings.ai_model,"messages":messages,"max_tokens":settings.ai_max_output_tokens})
    };
    if settings.ai_reasoning_effort != "default" {
        if settings.ai_protocol == "responses" {
            payload["reasoning"] = json!({"effort":settings.ai_reasoning_effort});
        } else {
            payload["reasoning_effort"] = json!(settings.ai_reasoning_effort);
        }
    }
    let session = digest(
        format!(
            "debug:{}:{}:{}:{}",
            user.id, input.session_id, input.provider_id, input.model_id
        )
        .as_bytes(),
    );
    let (wire, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);
    tokio::spawn(async move {
        let _lease = lease;
        let started = std::time::Instant::now();
        let (events, mut deltas) = tokio::sync::mpsc::channel(16);
        let result = execute(&settings, &key, &transport, payload, &session, Some(events));
        tokio::pin!(result);
        let _ = wire
            .send(sse(json!({"type":"started","stream":transport.stream})))
            .await;
        let mut deltas_open = true;
        let mut first_delta_ms = None;
        let result = loop {
            tokio::select! {
                biased;
                _=wire.closed()=>return,
                event=deltas.recv(),if deltas_open=>{
                    if let Some(event)=event {
                        if first_delta_ms.is_none(){first_delta_ms=Some(started.elapsed().as_millis() as u64);}
                        if wire.send(sse(event)).await.is_err(){return;}
                    }else{deltas_open=false;}
                }
                result=&mut result=>break result,
            }
        };
        // Drain queued deltas before emitting the terminal event.
        while let Ok(event) = deltas.try_recv() {
            if wire.send(sse(event)).await.is_err() {
                return;
            }
        }
        let event = match result {
            Ok(value) => {
                match ai::response_content(value.to_string().as_bytes(), &settings.ai_protocol) {
                    Ok((text, usage)) => {
                        json!({"type":"done","text":text,"usage":usage,"elapsed_ms":started.elapsed().as_millis() as u64,"first_delta_ms":first_delta_ms})
                    }
                    Err(error) => json!({"type":"error","code":error.code}),
                }
            }
            Err(error) => json!({"type":"error","code":error.code}),
        };
        let _ = wire.send(sse(event)).await;
    });
    let stream = futures::stream::unfold(rx, |mut rx| async move {
        rx.recv()
            .await
            .map(|bytes| (Ok::<_, actix_web::Error>(web::Bytes::from(bytes)), rx))
    });
    HttpResponse::Ok()
        .insert_header(("content-type", "text/event-stream"))
        .insert_header(("cache-control", "no-cache, no-store"))
        .insert_header(("x-accel-buffering", "no"))
        .streaming(stream)
}
fn sse(event: Value) -> Vec<u8> {
    format!("data: {event}\n\n").into_bytes()
}

pub(in crate::threat_intel) fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/llm")
            .app_data(web::JsonConfig::default().limit(1024 * 1024))
            .route("/settings", web::get().to(read))
            .route("/settings", web::put().to(settings))
            .route("/prompt", web::put().to(prompt))
            .route("/providers", web::get().to(read))
            .route("/providers", web::post().to(create))
            .route("/providers/{id}", web::put().to(update))
            .route("/providers/{id}", web::delete().to(delete))
            .route("/providers/{id}/models/refresh", web::post().to(models))
            .route("/debug/chat", web::post().to(chat)),
    );
}
