use std::net::IpAddr;
use std::str::FromStr;

use crate::admin::UserBaseI;
use crate::audit::{AuditContext, AuditEvent, write as write_audit, write_standalone};
use crate::elasticsearch::ElasticsearchService;
use crate::logs::write::{error_logs, error_logs_error};
use crate::search_projection;
use actix_web::{HttpRequest, HttpResponse, Responder, delete, get, patch, post, web};
use deadpool_postgres::{Pool, Transaction};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio_postgres::types::ToSql;

const MAX_TAGS_PER_IP: i64 = 20;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct AssetTag {
    pub id: i64,
    pub name: String,
    pub kind: String,
    pub description: Option<String>,
    #[serde(default)]
    pub category_id: Option<i64>,
    #[serde(default)]
    pub category_name: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AssetTagCategory {
    id: i64,
    name: String,
    description: Option<String>,
    sort_order: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    tag_count: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    assignment_count: Option<i64>,
}

#[derive(Serialize)]
struct AssetTagCatalogItem {
    #[serde(flatten)]
    tag: AssetTag,
    #[serde(skip_serializing_if = "Option::is_none")]
    assignment_count: Option<i64>,
}

#[derive(Deserialize)]
pub(crate) struct CreateTagRequest {
    name: String,
    kind: String,
    description: Option<String>,
    category_id: Option<i64>,
}

#[derive(Deserialize)]
pub(crate) struct UpdateTagRequest {
    name: String,
    kind: String,
    description: Option<String>,
    category_id: Option<i64>,
}

#[derive(Deserialize)]
pub(crate) struct CreateTagCategoryRequest {
    name: String,
    description: Option<String>,
    sort_order: Option<i32>,
}

#[derive(Deserialize)]
pub(crate) struct UpdateTagCategoryRequest {
    name: String,
    description: Option<String>,
    sort_order: Option<i32>,
}

#[derive(Deserialize)]
pub(crate) struct ListTagsQuery {
    category_id: Option<i64>,
    kind: Option<String>,
    query: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct AssignTagRequest {
    ip: String,
    tag_id: i64,
}

#[derive(Deserialize)]
pub(crate) struct RemoveTagQuery {
    ip: String,
}

fn tag_list_filter<'a>(
    category_id: &'a Option<i64>,
    kind: &'a Option<String>,
    search: &'a Option<String>,
) -> (String, Vec<&'a (dyn ToSql + Sync)>) {
    let mut conditions = vec!["tag.is_active".to_owned(), "category.is_active".to_owned()];
    let mut params: Vec<&(dyn ToSql + Sync)> = Vec::new();

    if let Some(category_id) = category_id.as_ref() {
        params.push(category_id);
        conditions.push(format!("category.id = ${}", params.len()));
    }
    if let Some(kind) = kind.as_ref() {
        params.push(kind);
        conditions.push(format!("tag.kind = ${}", params.len()));
    }
    if let Some(search) = search.as_ref() {
        params.push(search);
        let index = params.len();
        conditions.push(format!(
            "(tag.name ILIKE ${index} OR COALESCE(tag.description, '') ILIKE ${index})"
        ));
    }

    (conditions.join(" AND "), params)
}

struct ValidatedTag {
    name: String,
    kind: String,
    description: Option<String>,
    category_id: Option<i64>,
}

struct ValidatedTagCategory {
    name: String,
    description: Option<String>,
    sort_order: i32,
}

fn normalize_ip(value: &str) -> Result<String, &'static str> {
    IpAddr::from_str(value.trim())
        .map(|address| address.to_string())
        .map_err(|_| "IP 地址格式无效")
}

fn validate_tag(
    name: &str,
    kind: &str,
    description: Option<&str>,
    category_id: Option<i64>,
) -> Result<ValidatedTag, &'static str> {
    let name = name.trim();
    if !(1..=32).contains(&name.chars().count()) {
        return Err("标签名称长度必须在 1 到 32 个字符之间");
    }
    if !matches!(kind, "info" | "malicious" | "benign") {
        return Err("标签类型无效");
    }
    let description = description.map(str::trim).filter(|value| !value.is_empty());
    if description.is_some_and(|value| value.chars().count() > 256) {
        return Err("标签描述不能超过 256 个字符");
    }
    Ok(ValidatedTag {
        name: name.to_owned(),
        kind: kind.to_owned(),
        description: description.map(str::to_owned),
        category_id,
    })
}

fn validate_tag_category(
    name: &str,
    description: Option<&str>,
    sort_order: Option<i32>,
) -> Result<ValidatedTagCategory, &'static str> {
    let name = name.trim();
    if !(1..=32).contains(&name.chars().count()) {
        return Err("分类名称长度必须在 1 到 32 个字符之间");
    }
    let description = description.map(str::trim).filter(|value| !value.is_empty());
    if description.is_some_and(|value| value.chars().count() > 256) {
        return Err("分类描述不能超过 256 个字符");
    }
    let sort_order = sort_order.unwrap_or(0);
    if !(-10_000..=10_000).contains(&sort_order) {
        return Err("分类排序值必须在 -10000 到 10000 之间");
    }
    Ok(ValidatedTagCategory {
        name: name.to_owned(),
        description: description.map(str::to_owned),
        sort_order,
    })
}

fn tag_from_row(row: &tokio_postgres::Row) -> AssetTag {
    AssetTag {
        id: row.get("id"),
        name: row.get("name"),
        kind: row.get("kind"),
        description: row.get("description"),
        category_id: row.try_get("category_id").ok(),
        category_name: row.try_get("category_name").ok(),
    }
}

fn category_from_row(row: &tokio_postgres::Row) -> AssetTagCategory {
    AssetTagCategory {
        id: row.get("id"),
        name: row.get("name"),
        description: row.get("description"),
        sort_order: row.get("sort_order"),
        tag_count: row.try_get("tag_count").ok(),
        assignment_count: row.try_get("assignment_count").ok(),
    }
}

pub(crate) fn tags_from_json(value: Value) -> Vec<AssetTag> {
    serde_json::from_value(value).unwrap_or_default()
}

fn database_error(
    req: &HttpRequest,
    event: &str,
    error_value: &(dyn std::error::Error + 'static),
) -> HttpResponse {
    error_logs_error(req, event, "tag_database_operation", error_value);
    HttpResponse::InternalServerError()
        .json(json!({"success": false, "message": "标签服务暂时不可用"}))
}

async fn deny_non_admin(
    req: &HttpRequest,
    pool: &Pool,
    user: &UserBaseI,
    action: &str,
) -> Option<HttpResponse> {
    if user.role == 1 {
        return None;
    }
    let mut event = AuditEvent::user("authorization", action, "denied", user);
    event.response_status = Some(403);
    event.reason_code = Some("insufficient_role".to_owned());
    write_standalone(pool, &AuditContext::from_request(req), &event).await;
    Some(HttpResponse::Forbidden().json(json!({
        "success": false,
        "message": "仅管理员可以管理资产标签"
    })))
}

async fn audit_change(
    transaction: &Transaction<'_>,
    req: &HttpRequest,
    user: &UserBaseI,
    action: &str,
    resource_type: &str,
    resource_id: &str,
    changes: Value,
) -> Result<(), tokio_postgres::Error> {
    let mut event = AuditEvent::user("data_access", action, "success", user)
        .resource(resource_type, resource_id);
    if matches!(resource_type, "asset_tag" | "asset_tag_category") {
        event.category = "configuration".to_owned();
    }
    event.response_status = Some(200);
    event.changes = Some(changes);
    write_audit(transaction, &AuditContext::from_request(req), &event).await
}

async fn active_tag(
    transaction: &Transaction<'_>,
    tag_id: i64,
) -> Result<Option<AssetTag>, tokio_postgres::Error> {
    transaction
        .query_opt(
            "SELECT tag.id, tag.name, tag.kind, tag.description, category.id AS category_id, \
                    category.name AS category_name \
             FROM asset_tag tag JOIN asset_tag_category category ON category.id = tag.category_id \
             WHERE tag.id = $1 AND tag.is_active AND category.is_active FOR UPDATE OF tag;",
            &[&tag_id],
        )
        .await
        .map(|row| row.as_ref().map(tag_from_row))
}

async fn has_classification_conflict(
    transaction: &Transaction<'_>,
    ip: &str,
    kind: &str,
    excluding_tag_id: Option<i64>,
) -> Result<bool, tokio_postgres::Error> {
    let opposite = match kind {
        "malicious" => "benign",
        "benign" => "malicious",
        _ => return Ok(false),
    };
    transaction
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM asset_ip_tag assignment \
             JOIN asset_tag tag ON tag.id = assignment.tag_id \
             WHERE assignment.ip_address = $1::TEXT::INET AND tag.is_active \
               AND tag.kind = $2 AND ($3::BIGINT IS NULL OR tag.id <> $3)) AS conflict;",
            &[&ip, &opposite, &excluding_tag_id],
        )
        .await
        .map(|row| row.get("conflict"))
}

async fn resolve_category_id(
    transaction: &Transaction<'_>,
    category_id: Option<i64>,
) -> Result<Option<i64>, tokio_postgres::Error> {
    if let Some(category_id) = category_id {
        return transaction
            .query_opt(
                "SELECT id FROM asset_tag_category WHERE id = $1 AND is_active;",
                &[&category_id],
            )
            .await
            .map(|row| row.map(|value| value.get("id")));
    }
    transaction
        .query_opt(
            "SELECT id FROM asset_tag_category WHERE is_active \
             ORDER BY CASE WHEN LOWER(name) = LOWER('未分类') THEN 0 ELSE 1 END, sort_order, id LIMIT 1;",
            &[],
        )
        .await
        .map(|row| row.map(|value| value.get("id")))
}

#[get("/api/tag-categories")]
pub(crate) async fn list_tag_categories(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
) -> impl Responder {
    let connection = match pool.get().await {
        Ok(value) => value,
        Err(error_value) => {
            return database_error(&req, "ListTagCategoriesPoolError", &error_value);
        }
    };
    let rows = match connection
        .query(
            "SELECT category.id, category.name, category.description, category.sort_order, \
                    COUNT(DISTINCT tag.id)::BIGINT AS tag_count, \
                    COUNT(assignment.tag_id)::BIGINT AS assignment_count \
             FROM asset_tag_category category \
             LEFT JOIN asset_tag tag ON tag.category_id = category.id AND tag.is_active \
             LEFT JOIN asset_ip_tag assignment ON assignment.tag_id = tag.id \
             WHERE category.is_active \
             GROUP BY category.id, category.name, category.description, category.sort_order \
             ORDER BY category.sort_order, LOWER(category.name), category.id;",
            &[],
        )
        .await
    {
        Ok(value) => value,
        Err(error_value) => {
            return database_error(&req, "ListTagCategoriesQueryError", &error_value);
        }
    };
    let items = rows
        .iter()
        .map(|row| {
            let mut category = category_from_row(row);
            if user.role != 1 {
                category.tag_count = None;
                category.assignment_count = None;
            }
            category
        })
        .collect::<Vec<_>>();
    HttpResponse::Ok().json(json!({
        "success": true,
        "data": {"items": items, "can_manage": user.role == 1}
    }))
}

#[post("/api/tag-categories")]
pub(crate) async fn create_tag_category(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    payload: web::Json<CreateTagCategoryRequest>,
) -> impl Responder {
    if let Some(response) =
        deny_non_admin(&req, pool.get_ref(), &user, "asset.tag_category.create").await
    {
        return response;
    }
    let category = match validate_tag_category(
        &payload.name,
        payload.description.as_deref(),
        payload.sort_order,
    ) {
        Ok(value) => value,
        Err(message) => {
            return HttpResponse::BadRequest().json(json!({"success": false, "message": message}));
        }
    };
    let mut connection = match pool.get().await {
        Ok(value) => value,
        Err(error_value) => {
            return database_error(&req, "CreateTagCategoryPoolError", &error_value);
        }
    };
    let transaction = match connection.transaction().await {
        Ok(value) => value,
        Err(error_value) => {
            return database_error(&req, "CreateTagCategoryTransactionError", &error_value);
        }
    };
    let row = match transaction
        .query_opt(
            "INSERT INTO asset_tag_category (name, description, sort_order, created_by) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (LOWER(name)) WHERE is_active DO NOTHING \
             RETURNING id, name, description, sort_order, 0::BIGINT AS tag_count, \
                       0::BIGINT AS assignment_count;",
            &[
                &category.name,
                &category.description,
                &category.sort_order,
                &user.id,
            ],
        )
        .await
    {
        Ok(Some(value)) => value,
        Ok(None) => {
            return HttpResponse::Conflict()
                .json(json!({"success": false, "message": "分类名称已存在"}));
        }
        Err(error_value) => {
            return database_error(&req, "CreateTagCategoryQueryError", &error_value);
        }
    };
    let created = category_from_row(&row);
    if let Err(error_value) = audit_change(
        &transaction,
        &req,
        &user,
        "asset.tag_category.create",
        "asset_tag_category",
        &created.id.to_string(),
        json!({"name": created.name, "description": created.description, "sort_order": created.sort_order}),
    )
    .await
    {
        return database_error(&req, "CreateTagCategoryAuditError", &error_value);
    }
    if let Err(error_value) = transaction.commit().await {
        return database_error(&req, "CreateTagCategoryCommitError", &error_value);
    }
    HttpResponse::Created().json(json!({"success": true, "data": {"category": created}}))
}

#[patch("/api/tag-categories/{category_id}")]
pub(crate) async fn update_tag_category(
    req: HttpRequest,
    pool: web::Data<Pool>,
    elasticsearch: web::Data<ElasticsearchService>,
    user: UserBaseI,
    category_id: web::Path<i64>,
    payload: web::Json<UpdateTagCategoryRequest>,
) -> impl Responder {
    if let Some(response) =
        deny_non_admin(&req, pool.get_ref(), &user, "asset.tag_category.update").await
    {
        return response;
    }
    let category_id = category_id.into_inner();
    let category = match validate_tag_category(
        &payload.name,
        payload.description.as_deref(),
        payload.sort_order,
    ) {
        Ok(value) => value,
        Err(message) => {
            return HttpResponse::BadRequest().json(json!({"success": false, "message": message}));
        }
    };
    let mut connection = match pool.get().await {
        Ok(value) => value,
        Err(error_value) => {
            return database_error(&req, "UpdateTagCategoryPoolError", &error_value);
        }
    };
    let transaction = match connection.transaction().await {
        Ok(value) => value,
        Err(error_value) => {
            return database_error(&req, "UpdateTagCategoryTransactionError", &error_value);
        }
    };
    let previous = match transaction
        .query_opt(
            "SELECT id, name, description, sort_order, 0::BIGINT AS tag_count, \
                    0::BIGINT AS assignment_count \
             FROM asset_tag_category WHERE id = $1 AND is_active FOR UPDATE;",
            &[&category_id],
        )
        .await
    {
        Ok(Some(row)) => category_from_row(&row),
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(json!({"success": false, "message": "标签分类不存在"}));
        }
        Err(error_value) => {
            return database_error(&req, "UpdateTagCategoryLookupError", &error_value);
        }
    };
    let duplicate: bool = match transaction
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM asset_tag_category \
             WHERE is_active AND id <> $1 AND LOWER(name) = LOWER($2)) AS duplicate;",
            &[&category_id, &category.name],
        )
        .await
    {
        Ok(row) => row.get("duplicate"),
        Err(error_value) => {
            return database_error(&req, "UpdateTagCategoryDuplicateError", &error_value);
        }
    };
    if duplicate {
        return HttpResponse::Conflict()
            .json(json!({"success": false, "message": "分类名称已存在"}));
    }
    let affected_rows = match transaction
        .query(
            "SELECT DISTINCT host(assignment.ip_address) AS ip \
             FROM asset_tag tag JOIN asset_ip_tag assignment ON assignment.tag_id = tag.id \
             WHERE tag.category_id = $1 AND tag.is_active;",
            &[&category_id],
        )
        .await
    {
        Ok(rows) => rows,
        Err(error_value) => {
            return database_error(&req, "UpdateTagCategoryAssignmentsError", &error_value);
        }
    };
    let affected_ips = affected_rows
        .into_iter()
        .map(|row| row.get::<_, String>("ip"))
        .collect::<Vec<_>>();
    let row = match transaction
        .query_one(
            "UPDATE asset_tag_category SET name = $1, description = $2, sort_order = $3, \
                    updated_at = NOW() WHERE id = $4 \
             RETURNING id, name, description, sort_order, \
                       (SELECT COUNT(*)::BIGINT FROM asset_tag WHERE category_id = $4 AND is_active) AS tag_count, \
                       (SELECT COUNT(*)::BIGINT FROM asset_ip_tag assignment JOIN asset_tag tag ON tag.id = assignment.tag_id \
                        WHERE tag.category_id = $4 AND tag.is_active) AS assignment_count;",
            &[
                &category.name,
                &category.description,
                &category.sort_order,
                &category_id,
            ],
        )
        .await
    {
        Ok(value) => value,
        Err(error_value) => {
            return database_error(&req, "UpdateTagCategoryQueryError", &error_value);
        }
    };
    let tag_ids = match transaction
        .query(
            "SELECT id FROM asset_tag WHERE category_id = $1 AND is_active;",
            &[&category_id],
        )
        .await
    {
        Ok(rows) => rows,
        Err(error_value) => {
            return database_error(&req, "UpdateTagCategoryTagsError", &error_value);
        }
    };
    for tag_id_row in tag_ids {
        let tag_id: i64 = tag_id_row.get("id");
        if let Err(error_value) =
            search_projection::enqueue_tag_assignments(&transaction, tag_id).await
        {
            return database_error(&req, "UpdateTagCategorySearchOutboxError", &error_value);
        }
    }
    let updated = category_from_row(&row);
    if let Err(error_value) = audit_change(
        &transaction,
        &req,
        &user,
        "asset.tag_category.update",
        "asset_tag_category",
        &category_id.to_string(),
        json!({"before": previous, "after": updated}),
    )
    .await
    {
        return database_error(&req, "UpdateTagCategoryAuditError", &error_value);
    }
    if let Err(error_value) = transaction.commit().await {
        return database_error(&req, "UpdateTagCategoryCommitError", &error_value);
    }
    if let Err(error) =
        refresh_elasticsearch_tag_ips(pool.get_ref(), elasticsearch.get_ref(), &affected_ips).await
    {
        error_logs(
            &req,
            "UpdateTagCategoryElasticsearchProjectionError",
            &error,
        );
        return HttpResponse::ServiceUnavailable()
            .json(json!({"success": false, "message": "分类已更新，但搜索投影更新失败"}));
    }
    HttpResponse::Ok().json(json!({"success": true, "data": {"category": updated}}))
}

#[delete("/api/tag-categories/{category_id}")]
pub(crate) async fn delete_tag_category(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    category_id: web::Path<i64>,
) -> impl Responder {
    if let Some(response) =
        deny_non_admin(&req, pool.get_ref(), &user, "asset.tag_category.delete").await
    {
        return response;
    }
    let category_id = category_id.into_inner();
    let mut connection = match pool.get().await {
        Ok(value) => value,
        Err(error_value) => {
            return database_error(&req, "DeleteTagCategoryPoolError", &error_value);
        }
    };
    let transaction = match connection.transaction().await {
        Ok(value) => value,
        Err(error_value) => {
            return database_error(&req, "DeleteTagCategoryTransactionError", &error_value);
        }
    };
    let category = match transaction
        .query_opt(
            "SELECT id, name, description, sort_order, \
                    (SELECT COUNT(*)::BIGINT FROM asset_tag WHERE category_id = $1 AND is_active) AS tag_count, \
                    0::BIGINT AS assignment_count \
             FROM asset_tag_category WHERE id = $1 AND is_active FOR UPDATE;",
            &[&category_id],
        )
        .await
    {
        Ok(Some(row)) => category_from_row(&row),
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(json!({"success": false, "message": "标签分类不存在"}));
        }
        Err(error_value) => {
            return database_error(&req, "DeleteTagCategoryLookupError", &error_value);
        }
    };
    if category.tag_count.unwrap_or(0) > 0 {
        return HttpResponse::Conflict().json(json!({
            "success": false,
            "message": "分类下仍有启用标签，请先移动或停用这些标签"
        }));
    }
    if let Err(error_value) = transaction
        .execute(
            "UPDATE asset_tag_category SET is_active = FALSE, updated_at = NOW() WHERE id = $1;",
            &[&category_id],
        )
        .await
    {
        return database_error(&req, "DeleteTagCategoryQueryError", &error_value);
    }
    if let Err(error_value) = audit_change(
        &transaction,
        &req,
        &user,
        "asset.tag_category.delete",
        "asset_tag_category",
        &category_id.to_string(),
        json!({"category": category}),
    )
    .await
    {
        return database_error(&req, "DeleteTagCategoryAuditError", &error_value);
    }
    if let Err(error_value) = transaction.commit().await {
        return database_error(&req, "DeleteTagCategoryCommitError", &error_value);
    }
    HttpResponse::Ok().json(json!({"success": true}))
}

#[get("/api/tags")]
pub(crate) async fn list_tags(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    query: web::Query<ListTagsQuery>,
) -> impl Responder {
    let kind = query
        .kind
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    if kind
        .as_deref()
        .is_some_and(|value| !matches!(value, "info" | "malicious" | "benign"))
    {
        return HttpResponse::BadRequest()
            .json(json!({"success": false, "message": "标签类型无效"}));
    }
    let search = query
        .query
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| format!("%{value}%"));
    let connection = match pool.get().await {
        Ok(value) => value,
        Err(error_value) => return database_error(&req, "ListTagsPoolError", &error_value),
    };
    let (filter_sql, params) = tag_list_filter(&query.category_id, &kind, &search);
    let sql = format!(
        "SELECT tag.id, tag.name, tag.kind, tag.description, category.id AS category_id, \
                category.name AS category_name, COUNT(assignment.tag_id)::BIGINT AS assignment_count \
         FROM asset_tag tag JOIN asset_tag_category category ON category.id = tag.category_id \
         LEFT JOIN asset_ip_tag assignment ON assignment.tag_id = tag.id \
         WHERE {filter_sql} \
         GROUP BY tag.id, tag.name, tag.kind, tag.description, category.id, category.name, category.sort_order \
         ORDER BY category.sort_order, LOWER(category.name), \
                  CASE tag.kind WHEN 'malicious' THEN 1 WHEN 'benign' THEN 2 ELSE 3 END, LOWER(tag.name), tag.id;"
    );
    let rows = match connection.query(&sql, &params).await {
        Ok(value) => value,
        Err(error_value) => return database_error(&req, "ListTagsQueryError", &error_value),
    };
    let items = rows
        .iter()
        .map(|row| AssetTagCatalogItem {
            tag: tag_from_row(row),
            assignment_count: (user.role == 1).then(|| row.get("assignment_count")),
        })
        .collect::<Vec<_>>();
    HttpResponse::Ok().json(json!({
        "success": true,
        "data": {"items": items, "can_manage": user.role == 1}
    }))
}

#[post("/api/tags")]
pub(crate) async fn create_tag(
    req: HttpRequest,
    pool: web::Data<Pool>,
    user: UserBaseI,
    payload: web::Json<CreateTagRequest>,
) -> impl Responder {
    if let Some(response) = deny_non_admin(&req, pool.get_ref(), &user, "asset.tag.create").await {
        return response;
    }
    let tag = match validate_tag(
        &payload.name,
        &payload.kind,
        payload.description.as_deref(),
        payload.category_id,
    ) {
        Ok(value) => value,
        Err(message) => {
            return HttpResponse::BadRequest().json(json!({"success": false, "message": message}));
        }
    };
    let mut connection = match pool.get().await {
        Ok(value) => value,
        Err(error_value) => return database_error(&req, "CreateTagPoolError", &error_value),
    };
    let transaction = match connection.transaction().await {
        Ok(value) => value,
        Err(error_value) => return database_error(&req, "CreateTagTransactionError", &error_value),
    };
    let category_id = match resolve_category_id(&transaction, tag.category_id).await {
        Ok(Some(value)) => value,
        Ok(None) => {
            return HttpResponse::BadRequest()
                .json(json!({"success": false, "message": "标签分类不存在"}));
        }
        Err(error_value) => {
            return database_error(&req, "CreateTagCategoryLookupError", &error_value);
        }
    };
    let created_id: i64 = match transaction
        .query_opt(
            "INSERT INTO asset_tag (name, kind, description, category_id, created_by) VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (LOWER(name)) WHERE is_active DO NOTHING \
             RETURNING id;",
            &[&tag.name, &tag.kind, &tag.description, &category_id, &user.id],
        )
        .await
    {
        Ok(Some(value)) => value.get("id"),
        Ok(None) => {
            return HttpResponse::Conflict()
                .json(json!({"success": false, "message": "标签名称已存在"}));
        }
        Err(error_value) => return database_error(&req, "CreateTagQueryError", &error_value),
    };
    let created = match active_tag(&transaction, created_id).await {
        Ok(Some(value)) => value,
        Ok(None) => {
            return HttpResponse::InternalServerError()
                .json(json!({"success": false, "message": "标签创建后读取失败"}));
        }
        Err(error_value) => return database_error(&req, "CreateTagReadbackError", &error_value),
    };
    if let Err(error_value) = audit_change(
        &transaction,
        &req,
        &user,
        "asset.tag.create",
        "asset_tag",
        &created.id.to_string(),
        json!({"name": created.name, "kind": created.kind, "description": created.description,
               "category_id": created.category_id, "category_name": created.category_name}),
    )
    .await
    {
        return database_error(&req, "CreateTagAuditError", &error_value);
    }
    if let Err(error_value) = transaction.commit().await {
        return database_error(&req, "CreateTagCommitError", &error_value);
    }
    HttpResponse::Created().json(json!({"success": true, "data": {"tag": created}}))
}

#[patch("/api/tags/{tag_id}")]
pub(crate) async fn update_tag(
    req: HttpRequest,
    pool: web::Data<Pool>,
    elasticsearch: web::Data<ElasticsearchService>,
    user: UserBaseI,
    tag_id: web::Path<i64>,
    payload: web::Json<UpdateTagRequest>,
) -> impl Responder {
    if let Some(response) = deny_non_admin(&req, pool.get_ref(), &user, "asset.tag.update").await {
        return response;
    }
    let tag_id = tag_id.into_inner();
    let tag = match validate_tag(
        &payload.name,
        &payload.kind,
        payload.description.as_deref(),
        payload.category_id,
    ) {
        Ok(value) => value,
        Err(message) => {
            return HttpResponse::BadRequest().json(json!({"success": false, "message": message}));
        }
    };
    let mut connection = match pool.get().await {
        Ok(value) => value,
        Err(error_value) => return database_error(&req, "UpdateTagPoolError", &error_value),
    };
    let transaction = match connection.transaction().await {
        Ok(value) => value,
        Err(error_value) => return database_error(&req, "UpdateTagTransactionError", &error_value),
    };
    let previous = match active_tag(&transaction, tag_id).await {
        Ok(Some(value)) => value,
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(json!({"success": false, "message": "标签不存在"}));
        }
        Err(error_value) => return database_error(&req, "UpdateTagLookupError", &error_value),
    };
    let category_id =
        match resolve_category_id(&transaction, tag.category_id.or(previous.category_id)).await {
            Ok(Some(value)) => value,
            Ok(None) => {
                return HttpResponse::BadRequest()
                    .json(json!({"success": false, "message": "标签分类不存在"}));
            }
            Err(error_value) => {
                return database_error(&req, "UpdateTagCategoryLookupError", &error_value);
            }
        };
    let assigned_ips = match transaction
        .query(
            "SELECT host(ip_address) AS ip FROM asset_ip_tag WHERE tag_id = $1;",
            &[&tag_id],
        )
        .await
    {
        Ok(rows) => rows
            .into_iter()
            .map(|row| row.get::<_, String>("ip"))
            .collect::<Vec<_>>(),
        Err(error_value) => {
            return database_error(&req, "UpdateTagAssignmentsLookupError", &error_value);
        }
    };
    let duplicate: bool = match transaction
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM asset_tag WHERE is_active AND id <> $1 AND LOWER(name) = LOWER($2)) AS duplicate;",
            &[&tag_id, &tag.name],
        )
        .await
    {
        Ok(row) => row.get("duplicate"),
        Err(error_value) => return database_error(&req, "UpdateTagDuplicateError", &error_value),
    };
    if duplicate {
        return HttpResponse::Conflict()
            .json(json!({"success": false, "message": "标签名称已存在"}));
    }
    if matches!(tag.kind.as_str(), "malicious" | "benign") {
        let conflict = match transaction
            .query_one(
                "SELECT EXISTS (SELECT 1 FROM asset_ip_tag current_assignment \
                 JOIN asset_ip_tag opposite_assignment ON opposite_assignment.ip_address = current_assignment.ip_address \
                 JOIN asset_tag opposite ON opposite.id = opposite_assignment.tag_id AND opposite.is_active \
                 WHERE current_assignment.tag_id = $1 AND opposite.id <> $1 AND opposite.kind = $2) AS conflict;",
                &[&tag_id, &if tag.kind == "malicious" { "benign" } else { "malicious" }],
            )
            .await
        {
            Ok(row) => row.get("conflict"),
            Err(error_value) => return database_error(&req, "UpdateTagConflictError", &error_value),
        };
        if conflict {
            return HttpResponse::Conflict().json(
                json!({"success": false, "message": "部分 IP 已绑定相反分类，请先移除冲突标签"}),
            );
        }
    }
    if let Err(error_value) = transaction
        .execute(
            "UPDATE asset_tag SET name = $1, kind = $2, description = $3, category_id = $4, \
                    updated_at = NOW() WHERE id = $5;",
            &[
                &tag.name,
                &tag.kind,
                &tag.description,
                &category_id,
                &tag_id,
            ],
        )
        .await
    {
        return database_error(&req, "UpdateTagQueryError", &error_value);
    }
    let updated = match active_tag(&transaction, tag_id).await {
        Ok(Some(value)) => value,
        Ok(None) => {
            return HttpResponse::InternalServerError()
                .json(json!({"success": false, "message": "标签更新后读取失败"}));
        }
        Err(error_value) => return database_error(&req, "UpdateTagQueryError", &error_value),
    };
    if let Err(error_value) = search_projection::enqueue_tag_assignments(&transaction, tag_id).await
    {
        return database_error(&req, "UpdateTagSearchOutboxError", &error_value);
    }
    if let Err(error_value) = audit_change(
        &transaction,
        &req,
        &user,
        "asset.tag.update",
        "asset_tag",
        &tag_id.to_string(),
        json!({"before": previous, "after": updated}),
    )
    .await
    {
        return database_error(&req, "UpdateTagAuditError", &error_value);
    }
    if let Err(error_value) = transaction.commit().await {
        return database_error(&req, "UpdateTagCommitError", &error_value);
    }
    if let Err(error) =
        refresh_elasticsearch_tag_ips(pool.get_ref(), elasticsearch.get_ref(), &assigned_ips).await
    {
        error_logs(&req, "UpdateTagElasticsearchProjectionError", &error);
        return HttpResponse::ServiceUnavailable()
            .json(json!({"success": false, "message": "标签已更新，但搜索投影更新失败"}));
    }
    HttpResponse::Ok().json(json!({"success": true, "data": {"tag": updated}}))
}

#[delete("/api/tags/{tag_id}")]
pub(crate) async fn delete_tag(
    req: HttpRequest,
    pool: web::Data<Pool>,
    elasticsearch: web::Data<ElasticsearchService>,
    user: UserBaseI,
    tag_id: web::Path<i64>,
) -> impl Responder {
    if let Some(response) = deny_non_admin(&req, pool.get_ref(), &user, "asset.tag.delete").await {
        return response;
    }
    let tag_id = tag_id.into_inner();
    let mut connection = match pool.get().await {
        Ok(value) => value,
        Err(error_value) => return database_error(&req, "DeleteTagPoolError", &error_value),
    };
    let transaction = match connection.transaction().await {
        Ok(value) => value,
        Err(error_value) => return database_error(&req, "DeleteTagTransactionError", &error_value),
    };
    let tag = match active_tag(&transaction, tag_id).await {
        Ok(Some(value)) => value,
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(json!({"success": false, "message": "标签不存在"}));
        }
        Err(error_value) => return database_error(&req, "DeleteTagLookupError", &error_value),
    };
    let assigned_ips = match transaction
        .query(
            "SELECT host(ip_address) AS ip FROM asset_ip_tag WHERE tag_id = $1;",
            &[&tag_id],
        )
        .await
    {
        Ok(rows) => rows
            .into_iter()
            .map(|row| row.get::<_, String>("ip"))
            .collect::<Vec<_>>(),
        Err(error_value) => {
            return database_error(&req, "DeleteTagAssignmentsLookupError", &error_value);
        }
    };
    if let Err(error_value) = search_projection::enqueue_tag_assignments(&transaction, tag_id).await
    {
        return database_error(&req, "DeleteTagSearchOutboxError", &error_value);
    }
    let removed_assignments = match transaction
        .execute("DELETE FROM asset_ip_tag WHERE tag_id = $1;", &[&tag_id])
        .await
    {
        Ok(value) => value,
        Err(error_value) => return database_error(&req, "DeleteTagAssignmentsError", &error_value),
    };
    if let Err(error_value) = transaction
        .execute(
            "UPDATE asset_tag SET is_active = FALSE, updated_at = NOW() WHERE id = $1;",
            &[&tag_id],
        )
        .await
    {
        return database_error(&req, "DeleteTagQueryError", &error_value);
    }
    if let Err(error_value) = audit_change(
        &transaction,
        &req,
        &user,
        "asset.tag.delete",
        "asset_tag",
        &tag_id.to_string(),
        json!({"tag": tag, "removed_assignments": removed_assignments}),
    )
    .await
    {
        return database_error(&req, "DeleteTagAuditError", &error_value);
    }
    if let Err(error_value) = transaction.commit().await {
        return database_error(&req, "DeleteTagCommitError", &error_value);
    }
    if let Err(error) =
        refresh_elasticsearch_tag_ips(pool.get_ref(), elasticsearch.get_ref(), &assigned_ips).await
    {
        error_logs(&req, "DeleteTagElasticsearchProjectionError", &error);
        return HttpResponse::ServiceUnavailable()
            .json(json!({"success": false, "message": "标签已删除，但搜索投影更新失败"}));
    }
    HttpResponse::Ok().json(json!({"success": true}))
}

#[get("/api/assets/tags")]
pub(crate) async fn get_asset_tags(
    req: HttpRequest,
    pool: web::Data<Pool>,
    elasticsearch: web::Data<ElasticsearchService>,
    user: UserBaseI,
    query: web::Query<RemoveTagQuery>,
) -> impl Responder {
    if let Some(response) =
        deny_non_admin(&req, pool.get_ref(), &user, "asset.tag.assign.prepare").await
    {
        return response;
    }
    let ip = match normalize_ip(&query.ip) {
        Ok(value) => value,
        Err(message) => {
            return HttpResponse::BadRequest().json(json!({"success": false, "message": message}));
        }
    };
    let connection = match pool.get().await {
        Ok(value) => value,
        Err(error_value) => return database_error(&req, "GetAssetTagsPoolError", &error_value),
    };
    let exists = {
        match elasticsearch.scan_asset_exists(&ip).await {
            Ok(value) => value,
            Err(error) => {
                error_logs(&req, "GetAssetTagsElasticsearchError", &error);
                return HttpResponse::ServiceUnavailable()
                    .json(json!({"success": false, "message": "扫描结果索引暂时不可用"}));
            }
        }
    };
    if !exists {
        return HttpResponse::NotFound().json(json!({"success": false, "message": "资产不存在"}));
    }
    let rows = match connection
        .query(
            "SELECT tag.id, tag.name, tag.kind, tag.description, category.id AS category_id, \
                    category.name AS category_name \
             FROM asset_ip_tag assignment JOIN asset_tag tag ON tag.id = assignment.tag_id \
             JOIN asset_tag_category category ON category.id = tag.category_id \
             WHERE assignment.ip_address = $1::TEXT::INET AND tag.is_active AND category.is_active \
             ORDER BY category.sort_order, LOWER(category.name), \
                      CASE tag.kind WHEN 'malicious' THEN 1 WHEN 'benign' THEN 2 ELSE 3 END, \
                      LOWER(tag.name), tag.id;",
            &[&ip],
        )
        .await
    {
        Ok(value) => value,
        Err(error_value) => return database_error(&req, "GetAssetTagsQueryError", &error_value),
    };
    let tags = rows.iter().map(tag_from_row).collect::<Vec<_>>();
    HttpResponse::Ok().json(json!({
        "success": true,
        "data": {"ip": ip, "tags": tags, "can_manage": true}
    }))
}

#[post("/api/assets/tags")]
pub(crate) async fn assign_tag(
    req: HttpRequest,
    pool: web::Data<Pool>,
    elasticsearch: web::Data<ElasticsearchService>,
    user: UserBaseI,
    payload: web::Json<AssignTagRequest>,
) -> impl Responder {
    if let Some(response) = deny_non_admin(&req, pool.get_ref(), &user, "asset.tag.assign").await {
        return response;
    }
    let ip = match normalize_ip(&payload.ip) {
        Ok(value) => value,
        Err(message) => {
            return HttpResponse::BadRequest().json(json!({"success": false, "message": message}));
        }
    };
    let mut connection = match pool.get().await {
        Ok(value) => value,
        Err(error_value) => return database_error(&req, "AssignTagPoolError", &error_value),
    };
    let transaction = match connection.transaction().await {
        Ok(value) => value,
        Err(error_value) => return database_error(&req, "AssignTagTransactionError", &error_value),
    };
    let exists = {
        match elasticsearch.scan_asset_exists(&ip).await {
            Ok(value) => value,
            Err(error) => {
                error_logs(&req, "AssignTagAssetElasticsearchError", &error);
                return HttpResponse::ServiceUnavailable()
                    .json(json!({"success": false, "message": "扫描结果索引暂时不可用"}));
            }
        }
    };
    if !exists {
        return HttpResponse::NotFound().json(json!({"success": false, "message": "资产不存在"}));
    }
    let tag = match active_tag(&transaction, payload.tag_id).await {
        Ok(Some(value)) => value,
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(json!({"success": false, "message": "标签不存在"}));
        }
        Err(error_value) => return database_error(&req, "AssignTagLookupError", &error_value),
    };
    if let Err(error_value) = transaction
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0));",
            &[&ip],
        )
        .await
    {
        return database_error(&req, "AssignTagLockError", &error_value);
    }
    let existing: bool = match transaction
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM asset_ip_tag WHERE ip_address = $1::TEXT::INET AND tag_id = $2) AS exists;",
            &[&ip, &tag.id],
        )
        .await
    {
        Ok(row) => row.get("exists"),
        Err(error_value) => return database_error(&req, "AssignTagExistingError", &error_value),
    };
    if existing {
        return HttpResponse::Ok()
            .json(json!({"success": true, "data": {"tag": tag, "created": false}}));
    }
    let count: i64 = match transaction
        .query_one(
            "SELECT COUNT(*)::BIGINT AS count FROM asset_ip_tag assignment \
             JOIN asset_tag current_tag ON current_tag.id = assignment.tag_id AND current_tag.is_active \
             WHERE assignment.ip_address = $1::TEXT::INET;",
            &[&ip],
        )
        .await
    {
        Ok(row) => row.get("count"),
        Err(error_value) => return database_error(&req, "AssignTagCountError", &error_value),
    };
    if count >= MAX_TAGS_PER_IP {
        return HttpResponse::Conflict()
            .json(json!({"success": false, "message": "单个 IP 最多绑定 20 个标签"}));
    }
    let conflict = match has_classification_conflict(&transaction, &ip, &tag.kind, None).await {
        Ok(value) => value,
        Err(error_value) => return database_error(&req, "AssignTagConflictError", &error_value),
    };
    if conflict {
        return HttpResponse::Conflict()
            .json(json!({"success": false, "message": "恶意与正常标签不能同时绑定"}));
    }
    if let Err(error_value) = transaction
        .execute(
            "INSERT INTO asset_ip_tag (ip_address, tag_id, assigned_by) VALUES ($1::TEXT::INET, $2, $3);",
            &[&ip, &tag.id, &user.id],
        )
        .await
    {
        return database_error(&req, "AssignTagQueryError", &error_value);
    }
    if let Err(error_value) = search_projection::enqueue_ip(&transaction, &ip).await {
        return database_error(&req, "AssignTagSearchOutboxError", &error_value);
    }
    if let Err(error_value) = audit_change(
        &transaction,
        &req,
        &user,
        "asset.tag.assign",
        "ip_asset",
        &ip,
        json!({"tag": tag}),
    )
    .await
    {
        return database_error(&req, "AssignTagAuditError", &error_value);
    }
    if let Err(error_value) = transaction.commit().await {
        return database_error(&req, "AssignTagCommitError", &error_value);
    }
    if let Err(error) =
        refresh_elasticsearch_tags(pool.get_ref(), elasticsearch.get_ref(), &ip).await
    {
        error_logs(&req, "AssignTagElasticsearchProjectionError", &error);
        return HttpResponse::ServiceUnavailable()
            .json(json!({"success": false, "message": "标签已保存，但搜索投影更新失败"}));
    }
    HttpResponse::Created().json(json!({"success": true, "data": {"tag": tag, "created": true}}))
}

#[delete("/api/assets/tags/{tag_id}")]
pub(crate) async fn remove_tag(
    req: HttpRequest,
    pool: web::Data<Pool>,
    elasticsearch: web::Data<ElasticsearchService>,
    user: UserBaseI,
    tag_id: web::Path<i64>,
    query: web::Query<RemoveTagQuery>,
) -> impl Responder {
    if let Some(response) = deny_non_admin(&req, pool.get_ref(), &user, "asset.tag.remove").await {
        return response;
    }
    let ip = match normalize_ip(&query.ip) {
        Ok(value) => value,
        Err(message) => {
            return HttpResponse::BadRequest().json(json!({"success": false, "message": message}));
        }
    };
    let tag_id = tag_id.into_inner();
    let mut connection = match pool.get().await {
        Ok(value) => value,
        Err(error_value) => return database_error(&req, "RemoveTagPoolError", &error_value),
    };
    let transaction = match connection.transaction().await {
        Ok(value) => value,
        Err(error_value) => return database_error(&req, "RemoveTagTransactionError", &error_value),
    };
    let tag = match active_tag(&transaction, tag_id).await {
        Ok(Some(value)) => value,
        Ok(None) => {
            return HttpResponse::NotFound()
                .json(json!({"success": false, "message": "标签不存在"}));
        }
        Err(error_value) => return database_error(&req, "RemoveTagLookupError", &error_value),
    };
    let removed = match transaction
        .execute(
            "DELETE FROM asset_ip_tag WHERE ip_address = $1::TEXT::INET AND tag_id = $2;",
            &[&ip, &tag_id],
        )
        .await
    {
        Ok(value) => value,
        Err(error_value) => return database_error(&req, "RemoveTagQueryError", &error_value),
    };
    if removed == 0 {
        return HttpResponse::NotFound()
            .json(json!({"success": false, "message": "IP 未绑定该标签"}));
    }
    if let Err(error_value) = search_projection::enqueue_ip(&transaction, &ip).await {
        return database_error(&req, "RemoveTagSearchOutboxError", &error_value);
    }
    if let Err(error_value) = audit_change(
        &transaction,
        &req,
        &user,
        "asset.tag.remove",
        "ip_asset",
        &ip,
        json!({"tag": tag}),
    )
    .await
    {
        return database_error(&req, "RemoveTagAuditError", &error_value);
    }
    if let Err(error_value) = transaction.commit().await {
        return database_error(&req, "RemoveTagCommitError", &error_value);
    }
    if let Err(error) =
        refresh_elasticsearch_tags(pool.get_ref(), elasticsearch.get_ref(), &ip).await
    {
        error_logs(&req, "RemoveTagElasticsearchProjectionError", &error);
        return HttpResponse::ServiceUnavailable()
            .json(json!({"success": false, "message": "标签已删除，但搜索投影更新失败"}));
    }
    HttpResponse::Ok().json(json!({"success": true}))
}

pub(crate) async fn refresh_elasticsearch_tags(
    pool: &Pool,
    elasticsearch: &ElasticsearchService,
    ip: &str,
) -> Result<(), String> {
    let connection = pool.get().await.map_err(|error| error.to_string())?;
    let rows = connection
        .query(
            "SELECT tag.id, tag.name, tag.kind, tag.description, category.id AS category_id, \
                    category.name AS category_name \
             FROM asset_ip_tag assignment JOIN asset_tag tag ON tag.id = assignment.tag_id \
             JOIN asset_tag_category category ON category.id = tag.category_id \
             WHERE assignment.ip_address = $1::TEXT::INET AND tag.is_active AND category.is_active \
             ORDER BY category.sort_order, LOWER(category.name), tag.id;",
            &[&ip],
        )
        .await
        .map_err(|error| error.to_string())?;
    let tags = rows.iter().map(tag_from_row).collect::<Vec<_>>();
    drop(connection);
    elasticsearch.refresh_scan_asset_tags(ip, &tags).await
}

async fn refresh_elasticsearch_tag_ips(
    pool: &Pool,
    elasticsearch: &ElasticsearchService,
    ips: &[String],
) -> Result<(), String> {
    for ip in ips {
        refresh_elasticsearch_tags(pool, elasticsearch, ip).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        normalize_ip, tag_list_filter, tags_from_json, validate_tag, validate_tag_category,
    };
    use serde_json::json;

    #[test]
    fn normalizes_ipv4_and_ipv6_addresses() {
        assert_eq!(normalize_ip(" 192.0.2.1 "), Ok("192.0.2.1".to_owned()));
        assert_eq!(
            normalize_ip("2001:0db8:0:0:0:0:0:1"),
            Ok("2001:db8::1".to_owned())
        );
    }

    #[test]
    fn validates_tag_fields() {
        assert!(validate_tag("办公出口", "info", Some("说明"), Some(1)).is_ok());
        assert!(validate_tag("", "info", None, None).is_err());
        assert!(validate_tag("标签", "unknown", None, None).is_err());
        assert!(validate_tag("标签", "info", Some(&"a".repeat(257)), None).is_err());
    }

    #[test]
    fn validates_tag_category_fields() {
        assert!(validate_tag_category("运行环境", Some("环境分类"), Some(10)).is_ok());
        assert!(validate_tag_category("", None, None).is_err());
        assert!(validate_tag_category("分类", None, Some(10_001)).is_err());
    }

    #[test]
    fn parses_aggregated_tags() {
        let tags = tags_from_json(json!([{
            "id": 1,
            "name": "可信",
            "kind": "benign",
            "description": null,
            "category_id": 1,
            "category_name": "处置状态"
        }]));
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].kind, "benign");
        assert_eq!(tags[0].category_name.as_deref(), Some("处置状态"));
    }

    #[test]
    fn tag_list_filter_omits_absent_options() {
        let (sql, params) = tag_list_filter(&None, &None, &None);
        assert_eq!(sql, "tag.is_active AND category.is_active");
        assert!(params.is_empty());
        assert!(!sql.contains("IS NULL OR"));
    }

    #[test]
    fn tag_list_filter_numbers_present_options_only() {
        let category_id = Some(3);
        let kind = Some("malicious".to_owned());
        let search = Some("%edge%".to_owned());
        let (sql, params) = tag_list_filter(&category_id, &kind, &search);

        assert_eq!(params.len(), 3);
        assert!(sql.contains("category.id = $1"));
        assert!(sql.contains("tag.kind = $2"));
        assert!(sql.contains("tag.name ILIKE $3"));
        assert!(sql.contains("tag.description, '') ILIKE $3"));
    }
}
