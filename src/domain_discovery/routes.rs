use super::*;
use crate::config::ServerConfig;
use crate::network_proxy::GlobalProxyState;
use crate::outbound_proxy::settings;
use crate::outbound_proxy::settings::DOMAIN_DISCOVERY_SCOPE;
use actix_web::{HttpRequest, HttpResponse, web};
fn respond<T: Serialize>(result: Result<T>) -> HttpResponse {
    match result {
        Ok(data) => HttpResponse::Ok().json(json!({"success":true,"data":data})),
        Err(e) => HttpResponse::build(e.status)
            .json(json!({"success":false,"code":e.code,"message":e.code})),
    }
}
#[allow(clippy::result_large_err)]
fn admin(user: &UserBaseI) -> std::result::Result<(), HttpResponse> {
    if user.role == 1 {
        Ok(())
    } else {
        Err(HttpResponse::Forbidden()
            .json(json!({"success":false,"message":"仅管理员可以管理域名发现代理设置"})))
    }
}
async fn create_job(
    req: HttpRequest,
    pool: web::Data<Pool>,
    es: web::Data<ElasticsearchService>,
    user: UserBaseI,
    input: web::Json<CreateInput>,
) -> HttpResponse {
    respond(
        create(
            &pool,
            &es,
            input.into_inner(),
            &user,
            &AuditContext::from_request(&req),
        )
        .await,
    )
}
async fn list(pool: web::Data<Pool>, user: UserBaseI) -> HttpResponse {
    respond(async {let rows=pool.get().await?.query("SELECT * FROM domain_discovery_job WHERE owner_id=$1 ORDER BY created_at DESC LIMIT 100", &[&user.id]).await?;Ok(rows.iter().map(job).collect::<Vec<_>>())}.await)
}
async fn detail(pool: web::Data<Pool>, user: UserBaseI, id: web::Path<Uuid>) -> HttpResponse {
    respond(owned(&pool, user.id, *id).await)
}
async fn result(
    pool: web::Data<Pool>,
    es: web::Data<ElasticsearchService>,
    runtime: web::Data<crate::runtime_config::RuntimeSettings>,
    user: UserBaseI,
    id: web::Path<Uuid>,
) -> HttpResponse {
    respond(async {let evidence=results(&pool,&es,user.id,*id).await?;let policy=runtime.dns_follow_up.get().await.value;
        let excluded:Vec<_>=evidence.candidates.iter().filter(|c|!policy.allows_domain(&c.name)).map(|c|c.name.clone()).collect();
        let tasks=pool.get().await?.query("SELECT domain,task_id FROM domain_discovery_dns_target WHERE job_id=$1", &[&*id]).await?;
        Ok(json!({"evidence":evidence,"excluded":excluded,"dns_tasks":tasks.iter().map(|r|json!({"domain":r.get::<_,String>(0),"task_id":r.get::<_,String>(1)})).collect::<Vec<_>>()}))}.await)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    domains: Vec<String>,
}
async fn dns(
    req: HttpRequest,
    pool: web::Data<Pool>,
    es: web::Data<ElasticsearchService>,
    runtime: web::Data<crate::runtime_config::RuntimeSettings>,
    user: UserBaseI,
    id: web::Path<Uuid>,
    input: web::Json<Selection>,
) -> HttpResponse {
    respond(
        queue_dns(
            &pool,
            &es,
            &runtime.dns_follow_up.get().await.value,
            &user,
            *id,
            input.into_inner().domains,
            &AuditContext::from_request(&req),
        )
        .await,
    )
}
async fn cancel(pool: web::Data<Pool>, user: UserBaseI, id: web::Path<Uuid>) -> HttpResponse {
    respond(async {owned(&pool,user.id,*id).await?;pool.get().await?.execute("UPDATE domain_discovery_job SET status='cancelled',claim_token=NULL,lease_until=NULL,updated_at=NOW() WHERE id=$1 AND owner_id=$2 AND status IN ('pending','running')", &[&*id,&user.id]).await?;Ok(json!({"id":*id}))}.await)
}
async fn get_settings(pool: web::Data<Pool>, user: UserBaseI) -> HttpResponse {
    if let Err(response) = admin(&user) {
        return response;
    }
    respond(
        settings::load(&pool, DOMAIN_DISCOVERY_SCOPE)
            .await
            .map(|settings| settings.public())
            .map_err(Error::from),
    )
}
async fn save_settings(
    req: HttpRequest,
    pool: web::Data<Pool>,
    config: web::Data<ServerConfig>,
    user: UserBaseI,
    input: web::Json<settings::SettingsInput>,
) -> HttpResponse {
    if let Err(response) = admin(&user) {
        return response;
    }
    respond(
        settings::save(
            &pool,
            DOMAIN_DISCOVERY_SCOPE,
            &config.encrypt_key,
            input.into_inner(),
            &user,
            &AuditContext::from_request(&req),
            "domain.discovery_proxy_update",
        )
        .await
        .map(|settings| settings.public())
        .map_err(Error::from),
    )
}
async fn clear_settings(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    input: web::Json<settings::ClearInput>,
) -> HttpResponse {
    if let Err(response) = admin(&user) {
        return response;
    }
    respond(
        settings::clear(
            &pool,
            DOMAIN_DISCOVERY_SCOPE,
            input.into_inner(),
            &user,
            &AuditContext::from_request(&req),
            "domain.discovery_proxy_clear",
        )
        .await
        .map(|settings| settings.public())
        .map_err(Error::from),
    )
}
async fn test_settings(
    pool: web::Data<Pool>,
    config: web::Data<ServerConfig>,
    network_proxy: web::Data<GlobalProxyState>,
    user: UserBaseI,
    input: web::Json<settings::ProxyTestInput>,
) -> HttpResponse {
    if let Err(response) = admin(&user) {
        return response;
    }
    let result = async {
        let local = settings::resolve_test_input(
            &pool,
            DOMAIN_DISCOVERY_SCOPE,
            &config.encrypt_key,
            &input,
        )
        .await
        .map_err(Error::from)?;
        let effective = network_proxy.resolve(&local).await.map_err(|error| Error {
            status: StatusCode::BAD_REQUEST,
            code: error.code,
        })?;
        let client = client::http_client(&effective).map_err(|error| Error {
            status: StatusCode::BAD_REQUEST,
            code: error.code,
        })?;
        let started = std::time::Instant::now();
        let probe = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            client::probe(&client, effective.mode),
        )
        .await;
        let latency_ms = started.elapsed().as_millis() as u64;
        Ok(json!({
            "ok": matches!(probe, Ok(Ok(()))),
            "code": match probe {
                Ok(Ok(())) => Value::Null,
                Ok(Err(error)) => Value::String(error.code.to_owned()),
                Err(_) => Value::String("source_timeout".into()),
            },
            "latency_ms": latency_ms,
        }))
    }
    .await;
    respond(result)
}
async fn relations(
    pool: web::Data<Pool>,
    es: web::Data<ElasticsearchService>,
    user: UserBaseI,
    domain: web::Path<String>,
) -> HttpResponse {
    respond(read_relations(&pool, &es, user.id, &domain).await)
}
async fn read_relations(
    pool: &Pool,
    es: &ElasticsearchService,
    owner: i32,
    domain: &str,
) -> Result<Value> {
    let domain =
        crate::dns::canonical_scan_domain(domain).map_err(|_| Error::bad("invalid_domain"))?;
    let hits = es
        .discovery_relations(owner, &domain)
        .await
        .map_err(|_| Error::unavailable())?;
    let mut sources = vec![];
    for hit in hits["hits"]["hits"].as_array().into_iter().flatten() {
        let Some(id) = hit["_id"].as_str().and_then(|s| Uuid::parse_str(s).ok()) else {
            continue;
        };
        let visible = match owned(pool, owner, id).await {
            Ok(job) => job,
            Err(e) if e.status == StatusCode::NOT_FOUND => continue,
            Err(e) => return Err(e),
        };
        if !matches!(visible["status"].as_str(), Some("succeeded" | "partial")) {
            continue;
        }
        let evidence: Evidence = serde_json::from_value(hit["_source"]["evidence"].clone())
            .map_err(|_| Error::unavailable())?;
        sources.push((id, evidence));
    }
    Ok(project_relations(
        &domain,
        sources,
        hits["hits"]["total"]["value"].as_u64().unwrap_or(0) > 20,
    ))
}
pub(super) fn project_relations(
    domain: &str,
    sources: Vec<(Uuid, Evidence)>,
    mut truncated: bool,
) -> Value {
    let mut certificates = BTreeMap::<String, Certificate>::new();
    let mut names = BTreeMap::<String, BTreeSet<i64>>::new();
    let mut stored_names = 0;
    let mut jobs = vec![];
    for (id, evidence) in sources {
        jobs.push(id);
        truncated |= evidence.truncated
            || evidence.incomplete_certificates > 0
            || !evidence.source_errors.is_empty();
        // Hierarchical children remain visible even when the seed itself is not a SAN.
        for candidate in evidence
            .candidates
            .iter()
            .filter(|c| within_seed(c.name.strip_prefix("*.").unwrap_or(&c.name), domain))
        {
            if names.len() < MAX_NAMES || names.contains_key(&candidate.name) {
                names
                    .entry(candidate.name.clone())
                    .or_default()
                    .extend(candidate.certificate_ids.iter().copied());
            } else {
                truncated = true;
            }
        }
        for cert in evidence.certificates {
            if !cert.full_san
                || !cert
                    .names
                    .iter()
                    .any(|n| within_seed(n.strip_prefix("*.").unwrap_or(n), domain))
            {
                continue;
            }
            let fingerprint = cert
                .fingerprint_sha256
                .clone()
                .unwrap_or_else(|| cert.crtsh_id.to_string());
            if certificates.contains_key(&fingerprint) {
                continue;
            }
            if certificates.len() >= MAX_CERTIFICATES
                || stored_names + cert.names.len() > MAX_EVIDENCE_NAMES
            {
                truncated = true;
                continue;
            }
            stored_names += cert.names.len();
            for name in &cert.names {
                if names.len() < MAX_NAMES || names.contains_key(name) {
                    names.entry(name.clone()).or_default().insert(cert.crtsh_id);
                } else {
                    truncated = true;
                }
            }
            certificates.insert(fingerprint, cert);
        }
    }
    let candidates:Vec<_>=names.into_iter().map(|(name,ids)|json!({
        "relation":if name.starts_with("*."){ "wildcard" }else if name==domain{"seed"}else if within_seed(&name,domain){"subdomain"}else{"certificate_related"},
        "name":name,"certificate_ids":ids.into_iter().take(MAX_CERTIFICATES).collect::<Vec<_>>()
    })).collect();
    json!({"domain":domain,"certificates":certificates.values().collect::<Vec<_>>(),"candidates":candidates,"job_ids":jobs,"truncated":truncated})
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/domain-discovery")
            .app_data(web::JsonConfig::default().limit(128 * 1024))
            .route("/settings", web::get().to(get_settings))
            .route("/settings", web::put().to(save_settings))
            .route("/settings/clear", web::post().to(clear_settings))
            .route("/settings/test", web::post().to(test_settings))
            .route("/jobs", web::post().to(create_job))
            .route("/jobs", web::get().to(list))
            .route("/jobs/{id}", web::get().to(detail))
            .route("/jobs/{id}/results", web::get().to(result))
            .route("/jobs/{id}/dns-tasks", web::post().to(dns))
            .route("/jobs/{id}/cancel", web::post().to(cancel)),
    );
    cfg.route("/api/domains/{domain}/relations", web::get().to(relations));
}
