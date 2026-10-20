use super::*;
use actix_web::{HttpRequest, web};
use futures_util::StreamExt;
use tokio::io::AsyncWriteExt;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportQuery {
    expected_revision: i64,
}
async fn upload_source(
    pool: &Pool,
    user: &UserBaseI,
    id: Uuid,
    revision: i64,
) -> Result<storage::Source> {
    admin(user)?;
    let s = storage::get_source(pool, id).await?;
    if s.revision != revision {
        return Err(Error::conflict());
    }
    if s.input.transport != "upload" {
        return Err(Error::bad("intel_invalid_upload_source"));
    }
    if !s.input.enabled {
        return Err(Error::bad("intel_source_disabled"));
    }
    if pool.get().await?.query_one("SELECT EXISTS(SELECT 1 FROM intel_sync_run WHERE source_id=$1 AND status IN ('queued','running'))",&[&s.id]).await?.get::<_,bool>(0) {
        return Err(Error {status:StatusCode::CONFLICT,code:"intel_import_busy",diagnostic:json!({})});
    }
    Ok(s)
}
async fn check_import(
    pool: web::Data<Pool>,
    user: UserBaseI,
    id: web::Path<Uuid>,
    q: web::Query<ImportQuery>,
) -> HttpResponse {
    response(
        async {
            upload_source(&pool, &user, id.into_inner(), q.expected_revision).await?;
            imports::check_writable().await?;
            Ok(json!({"ready": true}))
        }
        .await,
    )
}
async fn offline_import(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    id: web::Path<Uuid>,
    q: web::Query<ImportQuery>,
    mut payload: web::Payload,
) -> HttpResponse {
    response(
        async {
            // Repeat preflight checks; readiness is not a reservation or authorization token.
            let s = upload_source(&pool, &user, id.into_inner(), q.expected_revision).await?;
            let temp = imports::temporary().await?;
            let mut file = tokio::fs::File::from_std(
                temp.reopen()
                    .map_err(|_| Error::bad("intel_import_write_failed"))?,
            );
            let mut size = 0_u64;
            let mut hash = openssl::sha::Sha256::new();
            while let Some(chunk) =
                tokio::time::timeout(std::time::Duration::from_secs(60), payload.next())
                    .await
                    .map_err(|_| Error::bad("intel_import_read_failed"))?
            {
                let chunk = chunk.map_err(|_| Error::bad("intel_import_read_failed"))?;
                size += chunk.len() as u64;
                if size > import_parse::MAX_ARCHIVE {
                    return Err(Error {
                        status: StatusCode::PAYLOAD_TOO_LARGE,
                        code: "intel_import_too_large",
                        diagnostic: json!({}),
                    });
                }
                hash.update(&chunk);
                file.write_all(&chunk)
                    .await
                    .map_err(|_| Error::bad("intel_import_write_failed"))?;
            }
            if size == 0 {
                return Err(Error::bad("intel_no_supported_indicators"));
            }
            file.sync_all()
                .await
                .map_err(|_| Error::bad("intel_import_write_failed"))?;
            drop(file);
            let hash = hash.finish().iter().map(|b| format!("{b:02x}")).collect();
            let snapshot = imports::install(
                &pool,
                &s,
                temp,
                hash,
                Some((&user, &AuditContext::from_request(&req))),
            )
            .await?;
            Ok(json!({"snapshot_id":snapshot,"queued":true}))
        }
        .await,
    )
}

async fn list_sources(pool: web::Data<Pool>, user: UserBaseI) -> HttpResponse {
    response(
        async {
            admin(&user)?;
            storage::sources(&pool).await
        }
        .await,
    )
}
async fn add_source(
    req: HttpRequest,
    pool: web::Data<Pool>,
    config: web::Data<crate::config::ServerConfig>,
    user: UserBaseI,
    input: web::Json<SourceInput>,
) -> HttpResponse {
    response(
        storage::save_source(
            &pool,
            None,
            input.into_inner(),
            &user,
            &AuditContext::from_request(&req),
            &config.encrypt_key,
        )
        .await,
    )
}
async fn update_source(
    req: HttpRequest,
    pool: web::Data<Pool>,
    config: web::Data<crate::config::ServerConfig>,
    user: UserBaseI,
    id: web::Path<Uuid>,
    input: web::Json<SourceInput>,
) -> HttpResponse {
    response(
        storage::save_source(
            &pool,
            Some(id.into_inner()),
            input.into_inner(),
            &user,
            &AuditContext::from_request(&req),
            &config.encrypt_key,
        )
        .await,
    )
}
async fn sync_source(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    id: web::Path<Uuid>,
) -> HttpResponse {
    response(
        storage::enqueue(
            &pool,
            id.into_inner(),
            &user,
            &AuditContext::from_request(&req),
        )
        .await,
    )
}
async fn get_settings(pool: web::Data<Pool>, user: UserBaseI) -> HttpResponse {
    response(
        async {
            admin(&user)?;
            storage::settings_json(&pool).await
        }
        .await,
    )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SettingsInput {
    settings: Settings,
    expected_revision: i64,
}
async fn put_settings(
    req: HttpRequest,
    pool: web::Data<Pool>,
    config: web::Data<crate::config::ServerConfig>,
    user: UserBaseI,
    input: web::Json<SettingsInput>,
) -> HttpResponse {
    let input = input.into_inner();
    response(
        storage::save_settings(
            &pool,
            input.settings,
            input.expected_revision,
            &user,
            &AuditContext::from_request(&req),
            &config.encrypt_key,
        )
        .await,
    )
}
async fn records(
    pool: web::Data<Pool>,
    user: UserBaseI,
    q: web::Query<storage::ListQuery>,
) -> HttpResponse {
    response(storage::records(&pool, &user, &q).await)
}
async fn review_queue(
    pool: web::Data<Pool>,
    user: UserBaseI,
    q: web::Query<storage::ListQuery>,
) -> HttpResponse {
    response(review::queue(&pool, &user, &q).await)
}
async fn report_review(
    pool: web::Data<Pool>,
    user: UserBaseI,
    id: web::Path<Uuid>,
) -> HttpResponse {
    response(review::report(&pool, id.into_inner(), &user).await)
}
async fn submit_report_review(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    id: web::Path<Uuid>,
    input: web::Json<review::BatchInput>,
) -> HttpResponse {
    response(
        review::submit(
            &pool,
            id.into_inner(),
            input.into_inner(),
            &user,
            &AuditContext::from_request(&req),
        )
        .await,
    )
}
async fn review(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    id: web::Path<Uuid>,
    input: web::Json<storage::ReviewInput>,
) -> HttpResponse {
    response(
        storage::review(
            &pool,
            id.into_inner(),
            input.into_inner(),
            &user,
            &AuditContext::from_request(&req),
        )
        .await,
    )
}
async fn attribution_candidates(
    pool: web::Data<Pool>,
    user: UserBaseI,
    id: web::Path<Uuid>,
) -> HttpResponse {
    response(
        async {
            admin(&user)?;
            attribution::candidates(&pool, id.into_inner()).await
        }
        .await,
    )
}
#[derive(Deserialize)]
struct EntityQuery {
    #[serde(default)]
    q: String,
    #[serde(default = "actor")]
    kind: String,
}
fn actor() -> String {
    "actor".into()
}
async fn entities(
    pool: web::Data<Pool>,
    _user: UserBaseI,
    q: web::Query<EntityQuery>,
) -> HttpResponse {
    response(storage::entity_list(&pool, &q.q, &q.kind).await)
}
#[derive(Deserialize)]
struct LookupQuery {
    #[serde(rename = "type")]
    kind: String,
    value: String,
}
async fn lookup(
    pool: web::Data<Pool>,
    _user: UserBaseI,
    q: web::Query<LookupQuery>,
) -> HttpResponse {
    response(
        async {
            let key = normalize(&q.kind, &q.value)?;
            let mut result = storage::annotate(&pool, &[vec![key]]).await;
            Ok(json!(result.remove(0)))
        }
        .await,
    )
}
async fn jobs(pool: web::Data<Pool>, user: UserBaseI) -> HttpResponse {
    response(async {
    admin(&user)?;
    let rows=pool.get().await?.query("SELECT j.*,s.name AS source_name FROM intel_sync_run j JOIN intel_source s ON s.id=j.source_id ORDER BY created_at DESC LIMIT 100",&[]).await?;
    Ok(json!({"items":rows.iter().map(|r|json!({"id":r.get::<_,Uuid>("id"),"source_id":r.get::<_,Uuid>("source_id"),"source_name":r.get::<_,String>("source_name"),"status":r.get::<_,String>("status"),"attempts":r.get::<_,i32>("attempts"),"summary":r.get::<_,Value>("summary"),"error_code":r.get::<_,Option<String>>("error_code"),"created_at":r.get::<_,chrono::DateTime<chrono::Utc>>("created_at")})).collect::<Vec<_>>()}))
}.await)
}
async fn articles(pool: web::Data<Pool>, user: UserBaseI) -> HttpResponse {
    response(async {
    admin(&user)?;
    let rows=pool.get().await?.query("SELECT a.*,s.name AS source_name,counts.record_count,counts.pending_count FROM (SELECT * FROM intel_article ORDER BY created_at DESC LIMIT 100) a JOIN intel_source s ON s.id=a.source_id CROSS JOIN LATERAL (SELECT COUNT(DISTINCT (r.kind,r.value)) AS record_count,COUNT(DISTINCT r.id) FILTER (WHERE r.status='pending') AS pending_count FROM intel_article_record l JOIN intel_record r ON r.id=l.record_id WHERE l.article_id=a.id AND r.source_id=a.source_id AND r.origin='ai' AND r.status<>'superseded') counts ORDER BY a.created_at DESC",&[]).await?;
    Ok(json!({"items":rows.iter().map(|r|json!({"id":r.get::<_,Uuid>("id"),"source_name":r.get::<_,String>("source_name"),"url":r.get::<_,String>("url"),"title":r.get::<_,String>("title"),"status":r.get::<_,String>("status"),"record_count":r.get::<_,i64>("record_count"),"pending_count":r.get::<_,i64>("pending_count"),"body_hash":r.get::<_,Option<String>>("body_hash"),"error_code":r.get::<_,Option<String>>("error_code"),"extraction_metadata":r.get::<_,Value>("extraction_metadata"),"created_at":r.get::<_,chrono::DateTime<chrono::Utc>>("created_at")})).collect::<Vec<_>>()}))
}.await)
}
async fn article_detail(
    pool: web::Data<Pool>,
    user: UserBaseI,
    id: web::Path<Uuid>,
) -> HttpResponse {
    response(async {
    admin(&user)?;let row=pool.get().await?.query_opt("SELECT url,title,body,body_hash,extraction_metadata FROM intel_article WHERE id=$1",&[&id.into_inner()]).await?.ok_or_else(Error::missing)?;
    Ok(json!({"url":row.get::<_,String>(0),"title":row.get::<_,String>(1),"body":row.get::<_,Option<String>>(2),"body_hash":row.get::<_,Option<String>>(3),"extraction_metadata":row.get::<_,Value>(4)}))
}.await)
}
async fn submit_article(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    input: web::Json<articles::ArticleInput>,
) -> HttpResponse {
    response(
        articles::submit(
            &pool,
            input.into_inner(),
            &user,
            &AuditContext::from_request(&req),
        )
        .await,
    )
}
async fn retry_article(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    id: web::Path<Uuid>,
) -> HttpResponse {
    response(async {
    admin(&user)?;
    if !storage::settings(&pool).await?.0.ai_enabled{return Err(Error::bad("intel_ai_disabled"));}
    let mut c=pool.get().await?;let tx=c.transaction().await?;let requested=id.into_inner();
    let row=tx.query_opt("SELECT * FROM intel_article WHERE id=$1 FOR UPDATE",&[&requested]).await?.ok_or_else(Error::missing)?;
    let source_id:Uuid=row.get("source_id");let source=storage::source(&tx.query_one("SELECT * FROM intel_source WHERE id=$1 FOR SHARE",&[&source_id]).await?);
    if !source.input.enabled{return Err(Error::bad("intel_source_disabled"));}
    if !matches!(source.input.kind.as_str(),"rss"|"article"){return Err(Error::bad("intel_invalid_article_source"));}
    let stale=row.get::<_,i64>("source_revision")!=source.revision;
    let mut target=requested;let mut created=false;
    if stale {
        let url:String=row.get("url");validate_url(&url,&source.input.allowed_hosts)?;
        let body:Option<String>=row.get("body");let body_hash:Option<String>=row.get("body_hash");
        let metadata:Value=row.get("extraction_metadata");
        if !source.input.publisher_id.is_empty() && metadata.pointer("/intake/publisher_id").and_then(Value::as_str).is_some_and(|id|id!=source.input.publisher_id){return Err(Error::bad("intel_article_publisher_mismatch"));}
        target=Uuid::now_v7();
        let intake=json!({"intake":metadata.get("intake"),"retry_of":requested,"snapshot_source_revision":row.get::<_,i64>("source_revision")});
        created=tx.execute("INSERT INTO intel_article(id,source_id,source_revision,url,title,feed_hash,body,body_hash,extraction_metadata) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING",&[&target,&source_id,&source.revision,&url,&row.get::<_,String>("title"),&row.get::<_,String>("feed_hash"),&body,&body_hash,&intake]).await?>0;
        target=tx.query_one("SELECT id FROM intel_article WHERE source_id=$1 AND source_revision=$2 AND url=$3 AND feed_hash=$4 FOR UPDATE",&[&source_id,&source.revision,&url,&row.get::<_,String>("feed_hash")]).await?.get(0);
    }
    let row=tx.query_one("SELECT status FROM intel_article WHERE id=$1",&[&target]).await?;
    let status:String=row.get(0);
    let active=matches!(status.as_str(),"queued"|"running");
    if !active {
        tx.execute("UPDATE intel_article SET status='queued',attempts=0,error_code=NULL,available_at=NOW(),claim_token=NULL,lease_until=NULL,extraction_metadata=extraction_metadata-'last_error'-'result'-'ai_usage' WHERE id=$1",&[&target]).await?;
    }
    if created || !active {audit(&tx,&user,&AuditContext::from_request(&req),"intel.article.retry",&target.to_string(),json!({"requested_id":requested,"new_source_revision":stale})).await?;}
    tx.commit().await?;
    Ok(json!({"id":target,"status":if active {status.as_str()}else{"queued"},"already_active":active&&!created,"new_source_revision":stale}))
}.await)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MappingInput {
    source_id: Uuid,
    name: String,
    attack_id: String,
    #[serde(default = "actor")]
    kind: String,
}
async fn mappings(pool: web::Data<Pool>, user: UserBaseI) -> HttpResponse {
    response(async {
    admin(&user)?;let c=pool.get().await?;
    let rows=c.query("WITH names AS (SELECT source_id,'actor' AS kind,payload->>'actor_name' AS name FROM intel_record WHERE actor_id IS NULL UNION ALL SELECT source_id,'software' AS kind,payload->>'malware' AS name FROM intel_record) SELECT n.source_id,s.name AS source_name,n.name,n.kind,COUNT(*) AS count FROM names n JOIN intel_source s ON s.id=n.source_id WHERE n.name<>'' AND NOT EXISTS(SELECT 1 FROM intel_name_mapping m WHERE m.source_id=n.source_id AND m.kind=n.kind AND m.name_normalized=LOWER(BTRIM(n.name))) AND NOT EXISTS(SELECT 1 FROM intel_entity e WHERE e.kind=n.kind AND e.active AND LOWER(e.name)=LOWER(BTRIM(n.name))) GROUP BY n.source_id,s.name,n.name,n.kind ORDER BY COUNT(*) DESC LIMIT 100",&[]).await?;
    let mappings=c.query("SELECT m.*,e.name AS canonical_name FROM intel_name_mapping m JOIN intel_entity e ON e.attack_id=m.attack_id ORDER BY m.created_at DESC LIMIT 100",&[]).await?;
    Ok(json!({"unmapped":rows.iter().map(|r|json!({"source_id":r.get::<_,Uuid>(0),"source_name":r.get::<_,String>(1),"name":r.get::<_,String>(2),"kind":r.get::<_,String>(3),"count":r.get::<_,i64>(4)})).collect::<Vec<_>>(),"mappings":mappings.iter().map(|r|json!({"id":r.get::<_,Uuid>("id"),"source_id":r.get::<_,Uuid>("source_id"),"name":r.get::<_,String>("name_normalized"),"kind":r.get::<_,String>("kind"),"attack_id":r.get::<_,String>("attack_id"),"canonical_name":r.get::<_,String>("canonical_name")})).collect::<Vec<_>>()}))
}.await)
}
async fn save_mapping(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    input: web::Json<MappingInput>,
) -> HttpResponse {
    response(async {
    admin(&user)?;
    if input.name.trim().is_empty()||input.name.len()>200||!matches!(input.kind.as_str(),"actor"|"software"){return Err(Error::bad("intel_invalid_mapping"));}
    let mut c=pool.get().await?;let tx=c.transaction().await?;
    if !tx.query_one("SELECT EXISTS(SELECT 1 FROM intel_entity WHERE attack_id=$1 AND kind=$2 AND active)",&[&input.attack_id,&input.kind]).await?.get::<_,bool>(0){return Err(Error::bad("intel_unknown_actor"));}
    let id=Uuid::now_v7();
    let id:Uuid=tx.query_one("INSERT INTO intel_name_mapping(id,source_id,name_normalized,attack_id,reviewed_by,kind) VALUES($1,$2,LOWER($3),$4,$5,$6) ON CONFLICT(source_id,name_normalized,kind) DO UPDATE SET attack_id=EXCLUDED.attack_id,reviewed_by=EXCLUDED.reviewed_by,created_at=NOW() RETURNING id",&[&id,&input.source_id,&input.name.trim(),&input.attack_id,&user.id,&input.kind]).await?.get(0);
    audit(&tx,&user,&AuditContext::from_request(&req),"intel.mapping.save",&id.to_string(),json!({"source_id":input.source_id,"name":input.name,"attack_id":input.attack_id})).await?;
    tx.commit().await?;Ok(json!({"id":id}))
}.await)
}
#[derive(Deserialize)]
struct DeleteMapping {
    attack_id: String,
}
async fn delete_mapping(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    id: web::Path<Uuid>,
    q: web::Query<DeleteMapping>,
) -> HttpResponse {
    response(
        async {
            admin(&user)?;
            let mut c = pool.get().await?;
            let tx = c.transaction().await?;
            let id = id.into_inner();
            if tx
                .execute(
                    "DELETE FROM intel_name_mapping WHERE id=$1 AND attack_id=$2",
                    &[&id, &q.attack_id],
                )
                .await?
                == 0
            {
                return Err(Error::conflict());
            }
            audit(
                &tx,
                &user,
                &AuditContext::from_request(&req),
                "intel.mapping.delete",
                &id.to_string(),
                json!({"attack_id":q.attack_id}),
            )
            .await?;
            tx.commit().await?;
            Ok(json!({"id":id}))
        }
        .await,
    )
}
async fn entity_detail(
    pool: web::Data<Pool>,
    _user: UserBaseI,
    id: web::Path<String>,
) -> HttpResponse {
    response(async {
    if id.len()>100{return Err(Error::bad("intel_invalid_query"));}let c=pool.get().await?;
    let row=c.query_opt("SELECT stix_id,object,dataset_version FROM intel_entity WHERE attack_id=$1",&[&id.as_str()]).await?.ok_or_else(Error::missing)?;
    let stix:String=row.get(0);
    let rows=c.query("SELECT r.relation,r.source_ref,e.attack_id,e.name,e.kind,r.object FROM intel_relationship r JOIN intel_entity e ON e.stix_id=CASE WHEN r.source_ref=$1 THEN r.target_ref ELSE r.source_ref END WHERE r.active AND e.active AND (r.source_ref=$1 OR r.target_ref=$1) ORDER BY e.kind,e.attack_id LIMIT 200",&[&stix]).await?;
    Ok(json!({"entity":row.get::<_,Value>(1),"dataset_version":row.get::<_,String>(2),"relationships":rows.iter().map(|r|json!({"relation":r.get::<_,String>(0),"direction":if r.get::<_,String>(1)==stix{"outgoing"}else{"incoming"},"attack_id":r.get::<_,String>(2),"name":r.get::<_,String>(3),"kind":r.get::<_,String>(4),"evidence":r.get::<_,Value>(5)})).collect::<Vec<_>>()}))
}.await)
}
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/intel")
            .app_data(web::JsonConfig::default().limit(128 * 1024))
            .route("/sources", web::get().to(list_sources))
            .route("/sources", web::post().to(add_source))
            .route("/sources/{id}", web::put().to(update_source))
            .route("/sources/{id}/sync", web::post().to(sync_source))
            .route("/sources/{id}/import/check", web::post().to(check_import))
            .route("/sources/{id}/import", web::post().to(offline_import))
            .route("/settings", web::get().to(get_settings))
            .route("/settings", web::put().to(put_settings))
            .route("/records", web::get().to(records))
            .route("/review-queue", web::get().to(review_queue))
            .route("/records/{id}/review", web::post().to(review))
            .route(
                "/records/{id}/attribution",
                web::get().to(attribution_candidates),
            )
            .route("/entities", web::get().to(entities))
            .route("/entities/{id}", web::get().to(entity_detail))
            .route("/lookup", web::get().to(lookup))
            .route("/jobs", web::get().to(jobs))
            .route("/articles", web::get().to(articles))
            .route("/articles", web::post().to(submit_article))
            .route("/articles/{id}", web::get().to(article_detail))
            .service(
                web::resource("/articles/{id}/review")
                    .app_data(web::JsonConfig::default().limit(2 * 1024 * 1024))
                    .route(web::get().to(report_review))
                    .route(web::post().to(submit_report_review)),
            )
            .route("/articles/{id}/retry", web::post().to(retry_article))
            .route("/mappings", web::get().to(mappings))
            .route("/mappings", web::post().to(save_mapping))
            .route("/mappings/{id}", web::delete().to(delete_mapping)),
    );
}
