//! Feishu's outbound WebSocket event transport for personal-channel binding.
//!
//! The gateway issues protobuf frames rather than ordinary JSON WebSocket
//! messages. No gateway URL, event payload, or credential is ever logged.
use super::{ChannelSettings, FeishuTargetType, feishu_binding};
use crate::outbound_proxy::{ProxyConfig, ProxyMode};
use deadpool_postgres::Pool;
use futures_util::{SinkExt, StreamExt};
use prost::Message as ProstMessage;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use tokio::{sync::watch, task::JoinHandle};
use tokio_tungstenite::tungstenite::{Message, protocol::WebSocketConfig};
use uuid::Uuid;

#[derive(Clone, PartialEq, prost::Message)]
struct Header {
    #[prost(string, required, tag = "1")]
    key: String,
    #[prost(string, required, tag = "2")]
    value: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct Frame {
    #[prost(uint64, required, tag = "1")]
    seq_id: u64,
    #[prost(uint64, required, tag = "2")]
    log_id: u64,
    #[prost(int32, required, tag = "3")]
    service: i32,
    #[prost(int32, required, tag = "4")]
    method: i32,
    #[prost(message, repeated, tag = "5")]
    headers: Vec<Header>,
    #[prost(string, optional, tag = "6")]
    payload_encoding: Option<String>,
    #[prost(string, optional, tag = "7")]
    payload_type: Option<String>,
    #[prost(bytes = "vec", optional, tag = "8")]
    payload: Option<Vec<u8>>,
    #[prost(string, optional, tag = "9")]
    log_id_new: Option<String>,
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct AppConfig {
    pub(super) app_id: String,
    pub(super) secret: String,
    pub(super) proxy_mode: ProxyMode,
    pub(super) proxy_url: String,
}

impl AppConfig {
    fn proxy(&self) -> ProxyConfig {
        ProxyConfig {
            mode: self.proxy_mode,
            url: self.proxy_url.clone(),
        }
    }
}

struct Active {
    config: AppConfig,
    handle: JoinHandle<()>,
}

/// Reconcile configured app connections. Multiple channels can share an app
/// only when they agree on credentials and network settings.
pub(crate) async fn run(pool: Pool, key: String, mut shutdown: watch::Receiver<bool>) {
    let replies = tokio::spawn(run_replies(pool.clone(), key.clone()));
    let mut active: HashMap<String, Active> = HashMap::new();
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = tick.tick() => {
                let Ok(client) = pool.get().await else { continue };
                let rows = match client.query("SELECT c.settings,c.feishu_app_secret_ciphertext,c.proxy_mode,c.proxy_ciphertext FROM notification_channel c WHERE c.provider='feishu' AND c.deleted_at IS NULL AND c.settings->>'feishu_bot_type'='app' AND (c.settings->>'feishu_target_type'='user' OR EXISTS(SELECT 1 FROM feishu_binding_request b WHERE b.channel_id=c.id AND b.status='pending' AND b.expires_at>NOW())) ORDER BY c.id", &[]).await {
                    Ok(rows) => rows,
                    Err(_) => continue,
                };
                let mut desired: HashMap<String, Option<AppConfig>> = HashMap::new();
                for row in rows {
                    let Ok(settings) = serde_json::from_value::<ChannelSettings>(row.get("settings")) else { continue };
                    let Some(ciphertext) = row.get::<_,Option<Vec<u8>>>("feishu_app_secret_ciphertext") else { continue };
                    let Ok(secret) = super::decrypt(&ciphertext, &key) else { continue };
                    let Ok(mode) = row.get::<_,String>("proxy_mode").parse::<ProxyMode>() else { continue };
                    let proxy_bytes: Option<Vec<u8>> = row.get("proxy_ciphertext");
                    let Ok(proxy) = super::decrypted_proxy(mode, proxy_bytes.as_deref(), &key) else { continue };
                    let config = AppConfig { app_id: settings.feishu_app_id.clone(), secret, proxy_mode: mode, proxy_url: proxy.url };
                    match desired.entry(settings.feishu_app_id) {
                        std::collections::hash_map::Entry::Vacant(entry) => { entry.insert(Some(config)); }
                        std::collections::hash_map::Entry::Occupied(mut entry) => {
                            if entry.get().as_ref().is_some_and(|old| old != &config) { entry.insert(None); }
                        }
                    }
                }
                drop(client);
                active.retain(|app, task| {
                    let keep = desired.get(app).and_then(Option::as_ref).is_some_and(|new| *new == task.config) && !task.handle.is_finished();
                    if !keep { task.handle.abort(); }
                    keep
                });
                for (app, config) in desired {
                    let Some(config) = config else {
                        if let Ok(client) = pool.get().await {
                            let _ = client.execute("INSERT INTO feishu_binding_connection(app_id,state) VALUES($1,'conflict') ON CONFLICT(app_id) DO UPDATE SET state='conflict',updated_at=NOW() WHERE feishu_binding_connection.lease_until IS NULL OR feishu_binding_connection.lease_until<NOW()", &[&app]).await;
                        }
                        continue;
                    };
                    active.entry(app).or_insert_with(|| {
                        let handle = tokio::spawn(run_app(pool.clone(), key.clone(), config.clone()));
                        Active { config, handle }
                    });
                }
            }
        }
    }
    replies.abort();
    for (_, task) in active {
        task.handle.abort();
    }
}

/// Replies use their own durable outbox; a send failure never rolls back a
/// completed binding. An updated channel cannot send a stale confirmation.
pub(super) async fn run_replies(pool: Pool, key: String) {
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    let mut cleanup = 0_u32;
    loop {
        tick.tick().await;
        cleanup += 1;
        if cleanup >= 300 {
            cleanup = 0;
            if let Ok(client) = pool.get().await {
                let _ = client.batch_execute("UPDATE feishu_binding_request SET status='expired',completed_at=NOW() WHERE status='pending' AND expires_at<=NOW(); DELETE FROM feishu_binding_event WHERE created_at<NOW()-INTERVAL '2 days'; DELETE FROM feishu_binding_rate WHERE window_start<NOW()-INTERVAL '1 day'; DELETE FROM feishu_binding_request WHERE status<>'pending' AND created_at<NOW()-INTERVAL '30 days'; DELETE FROM feishu_binding_reply WHERE status IN ('sent','failed') AND created_at<NOW()-INTERVAL '30 days';").await;
            }
        }
        let Ok(mut client) = pool.get().await else {
            continue;
        };
        let Ok(tx) = client.transaction().await else {
            continue;
        };
        let row = tx.query_opt("SELECT r.*,c.settings,c.feishu_app_secret_ciphertext,c.proxy_mode,c.proxy_ciphertext,c.deleted_at FROM feishu_binding_reply r JOIN notification_channel c ON c.id=r.channel_id WHERE ((r.status='pending' AND r.available_at<=NOW()) OR (r.status='sending' AND r.lease_until<NOW())) ORDER BY r.available_at,r.id LIMIT 1 FOR UPDATE OF r SKIP LOCKED", &[]).await;
        let Ok(Some(row)) = row else { continue };
        let id: Uuid = row.get("id");
        let app_id: String = row.get("app_id");
        let target: String = row.get("target_open_id");
        let settings = serde_json::from_value::<ChannelSettings>(row.get("settings"));
        let permitted = settings.as_ref().is_ok_and(|s| {
            s.feishu_application()
                && s.feishu_target() == FeishuTargetType::User
                && s.feishu_app_id == app_id
                && s.feishu_open_id == target
        }) && row
            .get::<_, Option<chrono::DateTime<chrono::Utc>>>("deleted_at")
            .is_none();
        if !permitted {
            let _ = tx.execute("UPDATE feishu_binding_reply SET status='failed',claim_token=NULL,lease_until=NULL WHERE id=$1", &[&id]).await;
            let _ = tx.commit().await;
            continue;
        }
        let claim = Uuid::new_v4();
        let attempts = row.get::<_, i32>("attempts") + 1;
        if tx.execute("UPDATE feishu_binding_reply SET status='sending',attempts=$2,claim_token=$3,lease_until=NOW()+INTERVAL '60 seconds' WHERE id=$1", &[&id,&attempts,&claim]).await.is_err() || tx.commit().await.is_err() { continue; }
        // Release the claim connection before the network request and final
        // status update; the pool can be configured with just one connection.
        drop(client);
        let secret: Option<Vec<u8>> = row.get("feishu_app_secret_ciphertext");
        let proxy: Option<Vec<u8>> = row.get("proxy_ciphertext");
        let mode = row.get::<_, String>("proxy_mode").parse::<ProxyMode>();
        let outcome = match (secret.as_deref().and_then(|v| super::decrypt(v,&key).ok()), mode) {
            (Some(secret), Ok(mode)) => match super::decrypted_proxy(mode,proxy.as_deref(),&key).and_then(|p| p.http_client().map_err(|_| super::Error::internal())) {
                Ok(client) => super::feishu::send_application(&client,&app_id,&secret,(FeishuTargetType::User,&target),json!({"msg_type":"text","content":{"text":"绑定成功，后续通知将发送到此聊天。"}}),None,id).await,
                Err(_) => super::Outcome::failure("proxy_connection_failed",true),
            },
            _ => super::Outcome::failure("secret_unavailable",false),
        };
        if let Ok(client) = pool.get().await {
            let status = if outcome.sent {
                "sent"
            } else if outcome.retryable && attempts < 5 {
                "pending"
            } else {
                "failed"
            };
            let _ = client.execute("UPDATE feishu_binding_reply SET status=$3,available_at=NOW()+INTERVAL '1 minute',claim_token=NULL,lease_until=NULL WHERE id=$1 AND claim_token=$2 AND lease_until>clock_timestamp()", &[&id,&claim,&status]).await;
        }
    }
}

async fn run_app(pool: Pool, key: String, app: AppConfig) {
    let owner = Uuid::new_v4();
    loop {
        let acquired = async {
            let client = pool.get().await.ok()?;
            client.query_opt("INSERT INTO feishu_binding_connection(app_id,owner,generation,lease_until,state,updated_at) VALUES($1,$2,1,NOW()+INTERVAL '30 seconds','connecting',NOW()) ON CONFLICT(app_id) DO UPDATE SET owner=$2,generation=feishu_binding_connection.generation+1,lease_until=NOW()+INTERVAL '30 seconds',state='connecting',updated_at=NOW() WHERE feishu_binding_connection.lease_until IS NULL OR feishu_binding_connection.lease_until<clock_timestamp() RETURNING generation", &[&app.app_id,&owner]).await.ok()?.map(|row| row.get::<_,i64>(0))
        }.await;
        if let Some(generation) = acquired {
            let mut session = Box::pin(connect_and_run(&pool, &key, &app, owner, generation));
            let mut renew = tokio::time::interval(Duration::from_secs(10));
            loop {
                tokio::select! {
                    _ = &mut session => break,
                    _ = renew.tick() => {
                        let changed = match pool.get().await {
                            Ok(client) => client.execute("UPDATE feishu_binding_connection SET lease_until=NOW()+INTERVAL '30 seconds',updated_at=NOW() WHERE app_id=$1 AND owner=$2 AND generation=$3 AND lease_until>clock_timestamp()", &[&app.app_id,&owner,&generation]).await.unwrap_or(0),
                            Err(_) => 0,
                        };
                        if changed != 1 { break; }
                    }
                }
            }
            if let Ok(client) = pool.get().await {
                let _ = client.execute("UPDATE feishu_binding_connection SET owner=NULL,lease_until=NULL,state='disconnected',updated_at=NOW() WHERE app_id=$1 AND owner=$2 AND generation=$3", &[&app.app_id,&owner,&generation]).await;
            }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

fn header<'a>(frame: &'a Frame, key: &str) -> Option<&'a str> {
    frame
        .headers
        .iter()
        .find(|h| h.key == key)
        .map(|h| h.value.as_str())
}

struct Fragment {
    created: Instant,
    pieces: Vec<Option<Vec<u8>>>,
}

async fn connect_and_run(
    pool: &Pool,
    key: &str,
    app: &AppConfig,
    owner: Uuid,
    generation: i64,
) -> Result<(), ()> {
    let client = app.proxy().http_client().map_err(|_| ())?;
    let mut response = client
        .post("https://open.feishu.cn/callback/ws/endpoint")
        .json(&json!({"AppID":app.app_id,"AppSecret":app.secret}))
        .send()
        .await
        .map_err(|_| ())?;
    if !response.status().is_success() {
        return Err(());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
        if bytes.len() + chunk.len() > 16 * 1024 {
            return Err(());
        }
        bytes.extend_from_slice(&chunk);
    }
    let result: Value = serde_json::from_slice(&bytes).map_err(|_| ())?;
    if result["code"].as_i64() != Some(0) {
        return Err(());
    }
    let address = result["data"]["URL"].as_str().ok_or(())?;
    let url = reqwest::Url::parse(address).map_err(|_| ())?;
    let host = url.host_str().ok_or(())?;
    if url.scheme() != "wss"
        || url.port_or_known_default() != Some(443)
        || !url.username().is_empty()
        || url.password().is_some()
        || !(host == "feishu.cn" || host.ends_with(".feishu.cn"))
    {
        return Err(());
    }
    let service_id: i32 = url
        .query_pairs()
        .find(|(k, _)| k == "service_id")
        .and_then(|(_, v)| v.parse().ok())
        .ok_or(())?;
    let mut interval = result["data"]["ClientConfig"]["PingInterval"]
        .as_u64()
        .unwrap_or(120)
        .clamp(10, 300);
    let stream = crate::outbound_proxy::websocket_tunnel(&app.proxy(), host, 443)
        .await
        .map_err(|_| ())?;
    let config = WebSocketConfig::default()
        .max_message_size(Some(128 * 1024))
        .max_frame_size(Some(128 * 1024));
    let (mut socket, _) = tokio::time::timeout(
        Duration::from_secs(10),
        tokio_tungstenite::client_async_tls_with_config(address, stream, Some(config), None),
    )
    .await
    .map_err(|_| ())?
    .map_err(|_| ())?;
    let client = pool.get().await.map_err(|_| ())?;
    if client.execute("UPDATE feishu_binding_connection SET state='connected',updated_at=NOW() WHERE app_id=$1 AND owner=$2 AND generation=$3 AND lease_until>clock_timestamp()", &[&app.app_id,&owner,&generation]).await.map_err(|_| ())? != 1 { return Err(()); }
    drop(client);
    let mut ping = tokio::time::interval(Duration::from_secs(interval));
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_received = Instant::now();
    let mut fragments: HashMap<String, Fragment> = HashMap::new();
    loop {
        tokio::select! {
            _ = ping.tick() => {
                if last_received.elapsed() > Duration::from_secs(interval.saturating_mul(2) + 5) { return Err(()); }
                let frame = Frame { seq_id:0,log_id:0,service:service_id,method:0,headers:vec![Header { key:"type".into(),value:"ping".into() }],payload_encoding:None,payload_type:None,payload:None,log_id_new:None };
                tokio::time::timeout(Duration::from_secs(3), socket.send(Message::Binary(frame.encode_to_vec().into()))).await.map_err(|_| ())?.map_err(|_| ())?;
            }
            next = socket.next() => {
                let Some(Ok(message)) = next else { return Err(()) };
                last_received = Instant::now();
                match message {
                    Message::Binary(bytes) => {
                        let mut frame = Frame::decode(bytes.as_ref()).map_err(|_| ())?;
                        if frame.method == 0 && header(&frame,"type") == Some("pong") {
                            if let Some(seconds) = frame.payload.as_deref().and_then(|data| serde_json::from_slice::<Value>(data).ok()).and_then(|config| config["PingInterval"].as_u64()) {
                                interval = seconds.clamp(10, 300);
                                ping = tokio::time::interval_at(tokio::time::Instant::now() + Duration::from_secs(interval), Duration::from_secs(interval));
                                ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                            }
                            continue;
                        }
                        if frame.method != 1 || header(&frame,"type") != Some("event") { continue; }
                        let sum = header(&frame,"sum").and_then(|v| v.parse::<usize>().ok()).unwrap_or(1);
                        let seq = header(&frame,"seq").and_then(|v| v.parse::<usize>().ok()).unwrap_or(0);
                        let payload = frame.payload.take().unwrap_or_default();
                        let payload = if sum > 1 {
                            if sum > 32 || seq >= sum { return Err(()); }
                            let id = header(&frame,"message_id").ok_or(())?.to_owned();
                            fragments.retain(|_, f| f.created.elapsed() < Duration::from_secs(5));
                            if !fragments.contains_key(&id) && fragments.len() >= 16 { return Err(()); }
                            let entry = fragments.entry(id.clone()).or_insert_with(|| Fragment { created:Instant::now(),pieces:vec![None;sum] });
                            if entry.pieces.len() != sum { return Err(()); }
                            entry.pieces[seq] = Some(payload);
                            if entry.pieces.iter().flatten().map(Vec::len).sum::<usize>() > 128 * 1024 { return Err(()); }
                            if entry.pieces.iter().any(Option::is_none) { continue; }
                            let completed = fragments.remove(&id).ok_or(())?;
                            let data: Vec<u8> = completed.pieces.into_iter().flatten().flatten().collect();
                            if data.len() > 128 * 1024 { return Err(()); }
                            data
                        } else { payload };
                        let started = Instant::now();
                        let accepted = tokio::time::timeout(Duration::from_millis(2500), handle_event(pool,key,app,owner,generation,&payload)).await.is_ok_and(|result| result.is_ok());
                        frame.headers.push(Header { key:"biz_rt".into(), value:started.elapsed().as_millis().to_string() });
                        frame.payload = Some(serde_json::to_vec(&json!({"code": if accepted {200} else {500}, "headers": null, "data": null})).map_err(|_| ())?);
                        tokio::time::timeout(Duration::from_secs(3), socket.send(Message::Binary(frame.encode_to_vec().into()))).await.map_err(|_| ())?.map_err(|_| ())?;
                    }
                    Message::Ping(_) => { tokio::time::timeout(Duration::from_secs(3), socket.flush()).await.map_err(|_| ())?.map_err(|_| ())?; }
                    Message::Close(_) => return Err(()),
                    _ => {}
                }
            }
        }
    }
}

pub(super) async fn handle_event(
    pool: &Pool,
    key: &str,
    app: &AppConfig,
    owner: Uuid,
    generation: i64,
    payload: &[u8],
) -> Result<(), ()> {
    let event: Value = serde_json::from_slice(payload).map_err(|_| ())?;
    let header = &event["header"];
    if header["event_type"] != "im.message.receive_v1" || header["app_id"] != app.app_id {
        return Ok(());
    }
    let body = &event["event"];
    if body["message"]["chat_type"] != "p2p"
        || body["message"]["message_type"] != "text"
        || body["sender"]["sender_type"] != "user"
    {
        return Ok(());
    }
    let tenant = header["tenant_key"]
        .as_str()
        .filter(|v| !v.is_empty())
        .ok_or(())?;
    if body["sender"]["tenant_key"].as_str() != Some(tenant) {
        return Ok(());
    }
    let Some(code) = body["message"]["content"]
        .as_str()
        .and_then(feishu_binding::parse_command)
    else {
        return Ok(());
    };
    let event_id = header["event_id"].as_str().ok_or(())?;
    let open_id = body["sender"]["sender_id"]["open_id"].as_str().ok_or(())?;
    feishu_binding::consume(
        pool,
        key,
        &app.app_id,
        (owner, generation),
        event_id,
        open_id,
        &code,
    )
    .await
    .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_frame_uses_feishu_protobuf_wire_format() {
        // The protocol uses fields 1–4 for the identifiers and method,
        // field 5 for headers, with key=1 and value=2 in each header.
        let bytes = [
            0x08, 0, 0x10, 0, 0x18, 42, 0x20, 0, 0x2a, 12, 0x0a, 4, b't', b'y', b'p', b'e', 0x12,
            4, b'p', b'i', b'n', b'g',
        ];
        let frame = Frame::decode(bytes.as_slice()).unwrap();
        assert_eq!(frame.service, 42);
        assert_eq!(frame.method, 0);
        assert_eq!(header(&frame, "type"), Some("ping"));
        assert_eq!(frame.encode_to_vec(), bytes);
    }
}
