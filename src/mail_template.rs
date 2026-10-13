#[cfg(test)]
use nm_report_renderer::sanitize_email_html;
pub use nm_report_renderer::{
    HEALTH_ALERT_TEMPLATE_KEY, LOGIN_SUCCESS_TEMPLATE_KEY, MailTemplateSource,
    REPORT_MONTHLY_TEMPLATE_KEY, REPORT_WEEKLY_TEMPLATE_KEY, RenderedMailTemplate,
    SCANNER_OUTAGE_TEMPLATE_KEY, render_template,
};

use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;
use lettre::{Message, message::Mailbox, message::MultiPart};
use serde::Serialize;
use serde_json::{Value, json};
use tera::Context;

use crate::admin::{
    MailRetryPolicy, get_mail_sender_key_from_database, get_mail_settings_from_database,
    try_send_email,
};
use crate::config::EmailConfig;
use crate::monitor::HealthEvent;

const DEFAULT_LOGIN_SUBJECT: &str = "{{ system_name }} 登录成功提醒";
const DEFAULT_LOGIN_HTML: &str = include_str!("../templates/mail/login_success.html");
const DEFAULT_LOGIN_TEXT: &str = include_str!("../templates/mail/login_success.txt");
const DEFAULT_HEALTH_ALERT_SUBJECT: &str = "{{ system_name }} 健康告警：{{ alert_type }}";
const DEFAULT_HEALTH_ALERT_HTML: &str = include_str!("../templates/mail/health_alert.html");
const DEFAULT_HEALTH_ALERT_TEXT: &str = include_str!("../templates/mail/health_alert.txt");
const DEFAULT_SCANNER_OUTAGE_SUBJECT: &str =
    "{{ system_name }} 扫描器{{ event_label }}：{{ scanner_name }}";
const DEFAULT_SCANNER_OUTAGE_HTML: &str = include_str!("../templates/mail/scanner_outage.html");
const DEFAULT_SCANNER_OUTAGE_TEXT: &str = include_str!("../templates/mail/scanner_outage.txt");

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MailTemplateVariable {
    pub key: &'static str,
    pub label: &'static str,
    pub example: &'static str,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MailTemplateSummary {
    pub template_key: &'static str,
    pub display_name: &'static str,
    pub enabled: bool,
    pub active_version: Option<i32>,
    pub has_draft: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MailTemplateDetail {
    pub template_key: &'static str,
    pub display_name: &'static str,
    pub enabled: bool,
    pub active_version: Option<i32>,
    pub editing_version: i32,
    pub status: String,
    pub is_default: bool,
    pub source: MailTemplateSource,
    pub variables: Vec<MailTemplateVariable>,
    pub default_source: MailTemplateSource,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MailTemplateVersion {
    pub version: i32,
    pub status: String,
    pub created_by: Option<i32>,
    pub create_at: DateTime<Utc>,
    pub update_at: Option<DateTime<Utc>>,
    pub published_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy)]
struct MailTemplateDefinition {
    template_key: &'static str,
    display_name: &'static str,
    default_subject: &'static str,
    default_html: &'static str,
    default_text: &'static str,
}

const LOGIN_SUCCESS_DEFINITION: MailTemplateDefinition = MailTemplateDefinition {
    template_key: LOGIN_SUCCESS_TEMPLATE_KEY,
    display_name: "登录成功",
    default_subject: DEFAULT_LOGIN_SUBJECT,
    default_html: DEFAULT_LOGIN_HTML,
    default_text: DEFAULT_LOGIN_TEXT,
};

const HEALTH_ALERT_DEFINITION: MailTemplateDefinition = MailTemplateDefinition {
    template_key: HEALTH_ALERT_TEMPLATE_KEY,
    display_name: "健康告警",
    default_subject: DEFAULT_HEALTH_ALERT_SUBJECT,
    default_html: DEFAULT_HEALTH_ALERT_HTML,
    default_text: DEFAULT_HEALTH_ALERT_TEXT,
};

const SCANNER_OUTAGE_DEFINITION: MailTemplateDefinition = MailTemplateDefinition {
    template_key: SCANNER_OUTAGE_TEMPLATE_KEY,
    display_name: "扫描器掉线与恢复",
    default_subject: DEFAULT_SCANNER_OUTAGE_SUBJECT,
    default_html: DEFAULT_SCANNER_OUTAGE_HTML,
    default_text: DEFAULT_SCANNER_OUTAGE_TEXT,
};

const REPORT_WEEKLY_DEFINITION: MailTemplateDefinition = MailTemplateDefinition {
    template_key: REPORT_WEEKLY_TEMPLATE_KEY,
    display_name: "平台周报",
    default_subject: "{{ system_name }} {{ report_label }}：{{ period_label }}",
    default_html: include_str!("../templates/mail/report.html"),
    default_text: include_str!("../templates/mail/report.txt"),
};
const REPORT_MONTHLY_DEFINITION: MailTemplateDefinition = MailTemplateDefinition {
    template_key: REPORT_MONTHLY_TEMPLATE_KEY,
    display_name: "平台月报",
    ..REPORT_WEEKLY_DEFINITION
};

const ALL_TEMPLATE_DEFINITIONS: &[MailTemplateDefinition] = &[
    LOGIN_SUCCESS_DEFINITION,
    HEALTH_ALERT_DEFINITION,
    SCANNER_OUTAGE_DEFINITION,
    REPORT_WEEKLY_DEFINITION,
    REPORT_MONTHLY_DEFINITION,
];

fn template_definition(template_key: &str) -> Option<MailTemplateDefinition> {
    match template_key {
        LOGIN_SUCCESS_TEMPLATE_KEY => Some(LOGIN_SUCCESS_DEFINITION),
        HEALTH_ALERT_TEMPLATE_KEY => Some(HEALTH_ALERT_DEFINITION),
        SCANNER_OUTAGE_TEMPLATE_KEY => Some(SCANNER_OUTAGE_DEFINITION),
        REPORT_WEEKLY_TEMPLATE_KEY => Some(REPORT_WEEKLY_DEFINITION),
        REPORT_MONTHLY_TEMPLATE_KEY => Some(REPORT_MONTHLY_DEFINITION),
        _ => None,
    }
}

fn default_source(definition: MailTemplateDefinition) -> MailTemplateSource {
    MailTemplateSource {
        subject_template: definition.default_subject.to_owned(),
        html_template: definition.default_html.to_owned(),
        text_template: definition.default_text.to_owned(),
    }
}

fn template_variables(template_key: &str) -> Vec<MailTemplateVariable> {
    match template_key {
        LOGIN_SUCCESS_TEMPLATE_KEY => vec![
            MailTemplateVariable {
                key: "system_name",
                label: "系统名称",
                example: "Network Mapping",
            },
            MailTemplateVariable {
                key: "username",
                label: "登录用户名",
                example: "admin",
            },
            MailTemplateVariable {
                key: "login_time",
                label: "登录时间",
                example: "2026-08-13 20:30:00",
            },
            MailTemplateVariable {
                key: "source_ip",
                label: "来源地址",
                example: "192.0.2.10",
            },
        ],
        HEALTH_ALERT_TEMPLATE_KEY => vec![
            MailTemplateVariable {
                key: "system_name",
                label: "系统名称",
                example: "Network Mapping",
            },
            MailTemplateVariable {
                key: "alert_type",
                label: "告警类型",
                example: "slow_request / server_error / slow_sql / slow_elasticsearch_query",
            },
            MailTemplateVariable {
                key: "severity",
                label: "严重级别",
                example: "warning / critical",
            },
            MailTemplateVariable {
                key: "occurred_at",
                label: "发生时间",
                example: "2026-08-18 15:30:00",
            },
            MailTemplateVariable {
                key: "summary",
                label: "告警摘要",
                example: "请求耗时 5123ms 超过阈值：POST /api/task/create",
            },
            MailTemplateVariable {
                key: "details",
                label: "详情列表（label/value）",
                example: "[{\"label\":\"请求路径\",\"value\":\"/api/task/create\"}]",
            },
        ],
        SCANNER_OUTAGE_TEMPLATE_KEY => vec![
            MailTemplateVariable {
                key: "system_name",
                label: "系统名称",
                example: "Network Mapping",
            },
            MailTemplateVariable {
                key: "event_label",
                label: "事件类型",
                example: "掉线 / 恢复",
            },
            MailTemplateVariable {
                key: "scanner_name",
                label: "扫描器名称",
                example: "华东扫描器",
            },
            MailTemplateVariable {
                key: "scanner_id",
                label: "扫描器 ID",
                example: "01952f0c-0000-7000-8000-000000000001",
            },
            MailTemplateVariable {
                key: "location",
                label: "位置",
                example: "上海",
            },
            MailTemplateVariable {
                key: "last_seen_at",
                label: "最后心跳",
                example: "2026-09-30 10:00:00 UTC",
            },
            MailTemplateVariable {
                key: "event_at",
                label: "发现或恢复时间",
                example: "2026-09-30 10:02:00 UTC",
            },
            MailTemplateVariable {
                key: "detail_path",
                label: "扫描器详情路径",
                example: "/scanner/01952f0c-0000-7000-8000-000000000001",
            },
        ],
        REPORT_WEEKLY_TEMPLATE_KEY | REPORT_MONTHLY_TEMPLATE_KEY => vec![
            MailTemplateVariable {
                key: "system_name",
                label: "系统名称",
                example: "Network Mapping",
            },
            MailTemplateVariable {
                key: "report_label",
                label: "报告类型",
                example: "周报 / 月报",
            },
            MailTemplateVariable {
                key: "period_label",
                label: "报告周期（上海时间）",
                example: "2026-09-21 至 2026-09-28（不含）",
            },
            MailTemplateVariable {
                key: "tasks",
                label: "任务统计",
                example: "created / succeeded / failed / partial / cancelled / success_rate",
            },
            MailTemplateVariable {
                key: "scan_output",
                label: "扫描产出",
                example: "unique_ips / port_observations / service_observations",
            },
            MailTemplateVariable {
                key: "recommendations",
                label: "建议列表",
                example: "[处理失败任务]",
            },
            MailTemplateVariable {
                key: "detail_path",
                label: "报告详情路径",
                example: "/reports/报告ID",
            },
            MailTemplateVariable {
                key: "report_meta",
                label: "报告版本与归档信息",
                example: "revision / timezone / generated_at / cutoff_at",
            },
            MailTemplateVariable {
                key: "previous_available",
                label: "环比是否可用",
                example: "true / false",
            },
            MailTemplateVariable {
                key: "comparison",
                label: "环比数值",
                example: "created_growth_percent / unique_ips_growth_percent / daily_unique_ips_growth_percent / success_rate_change_points",
            },
            MailTemplateVariable {
                key: "comparison_rows",
                label: "格式化环比列表",
                example: "label / value",
            },
            MailTemplateVariable {
                key: "trend_rows",
                label: "每日完成任务",
                example: "day / succeeded / failed / partial / cancelled",
            },
            MailTemplateVariable {
                key: "trend_image_url",
                label: "服务器趋势图片地址",
                example: "启用远程图片后生成；预览使用示例图",
            },
            MailTemplateVariable {
                key: "scanners",
                label: "扫描器执行表现",
                example: "name / total / succeeded / failed / cancelled / avg_duration / p50 / p95",
            },
            MailTemplateVariable {
                key: "scanner_omitted",
                label: "未展示的扫描器数量",
                example: "0",
            },
            MailTemplateVariable {
                key: "quality_summary",
                label: "统计完整性",
                example: "ready / expected",
            },
            MailTemplateVariable {
                key: "notes",
                label: "统计口径说明",
                example: "[统计说明]",
            },
            MailTemplateVariable {
                key: "detail_url",
                label: "报告详情绝对地址",
                example: "https://平台地址/reports/报告ID",
            },
        ],
        _ => Vec::new(),
    }
}

pub fn sample_context(template_key: &str) -> Result<Context, Box<dyn std::error::Error>> {
    if template_definition(template_key).is_none() {
        return Err("未知邮件模板".into());
    }
    if matches!(
        template_key,
        REPORT_WEEKLY_TEMPLATE_KEY | REPORT_MONTHLY_TEMPLATE_KEY
    ) {
        let mut sample = crate::reports::mail_context::sample();
        sample["report_label"] = json!(if template_key == REPORT_WEEKLY_TEMPLATE_KEY {
            "周报"
        } else {
            "月报"
        });
        sample["trend_image_url"] = json!("/mail/report-images/sample/trend.png");
        return Ok(Context::from_serialize(sample)?);
    }
    if template_key == HEALTH_ALERT_TEMPLATE_KEY {
        return Ok(Context::from_serialize(json!({
            "system_name": "Network Mapping",
            "alert_type": "slow_request",
            "severity": "warning",
            "occurred_at": "2026-08-18 15:30:00",
            "summary": "请求耗时 5123ms 超过阈值：POST /api/task/create",
            "details": [
                {"label": "请求方法", "value": "POST"},
                {"label": "请求路径", "value": "/api/task/create"}
            ]
        }))?);
    }
    if template_key == SCANNER_OUTAGE_TEMPLATE_KEY {
        return Ok(Context::from_serialize(json!({
            "system_name": "Network Mapping",
            "event_label": "掉线",
            "scanner_name": "华东扫描器",
            "scanner_id": "01952f0c-0000-7000-8000-000000000001",
            "location": "上海",
            "last_seen_at": "2026-09-30 10:00:00 UTC",
            "event_at": "2026-09-30 10:02:00 UTC",
            "detail_path": "/scanner/01952f0c-0000-7000-8000-000000000001"
        }))?);
    }
    Ok(Context::from_serialize(json!({
        "system_name": "Network Mapping",
        "username": "admin",
        "login_time": "2026-08-13 20:30:00",
        "source_ip": "192.0.2.10"
    }))?)
}

pub fn login_context(username: &str, source_ip: &str) -> Result<Context, tera::Error> {
    Context::from_serialize(json!({
        "system_name": "Network Mapping",
        "username": username,
        "login_time": crate::system_time::format_now(),
        "source_ip": source_ip
    }))
}

pub fn validate_template(
    template_key: &str,
    source: &MailTemplateSource,
) -> Result<RenderedMailTemplate, Box<dyn std::error::Error>> {
    let context = sample_context(template_key)?;
    render_template(template_key, source, &context)
}

pub async fn list_templates(
    pool: &Pool,
) -> Result<Vec<MailTemplateSummary>, Box<dyn std::error::Error>> {
    let conn = pool.get().await?;
    let mut summaries = Vec::with_capacity(ALL_TEMPLATE_DEFINITIONS.len());
    for definition in ALL_TEMPLATE_DEFINITIONS {
        let row = conn
            .query_opt(
                "SELECT active_version, enabled, EXISTS(SELECT 1 FROM mail_template_version v \
                 WHERE v.template_key = t.template_key AND v.status = 'draft') AS has_draft \
                 FROM mail_template t WHERE template_key = $1;",
                &[&definition.template_key],
            )
            .await?;
        let (active_version, enabled, has_draft) = row
            .map(|row| {
                (
                    row.get::<_, Option<i32>>("active_version"),
                    row.get::<_, bool>("enabled"),
                    row.get::<_, bool>("has_draft"),
                )
            })
            .unwrap_or((None, true, false));

        summaries.push(MailTemplateSummary {
            template_key: definition.template_key,
            display_name: definition.display_name,
            enabled,
            active_version,
            has_draft,
        });
    }
    Ok(summaries)
}

pub async fn get_template_detail(
    pool: &Pool,
    template_key: &str,
) -> Result<MailTemplateDetail, Box<dyn std::error::Error>> {
    let definition = template_definition(template_key).ok_or("未知邮件模板")?;
    let conn = pool.get().await?;
    let template_row = conn
        .query_opt(
            "SELECT active_version, enabled FROM mail_template WHERE template_key = $1;",
            &[&template_key],
        )
        .await?;
    let (active_version, enabled) = template_row
        .map(|row| {
            (
                row.get::<_, Option<i32>>("active_version"),
                row.get::<_, bool>("enabled"),
            )
        })
        .unwrap_or((None, true));

    let selected_row = conn
        .query_opt(
            "SELECT version, status, subject_template, html_template, text_template \
             FROM mail_template_version WHERE template_key = $1 AND status = 'draft' LIMIT 1;",
            &[&template_key],
        )
        .await?;
    let selected_row = match (selected_row, active_version) {
        (Some(row), _) => Some(row),
        (None, Some(version)) => {
            conn.query_opt(
                "SELECT version, status, subject_template, html_template, text_template \
                 FROM mail_template_version WHERE template_key = $1 AND version = $2 LIMIT 1;",
                &[&template_key, &version],
            )
            .await?
        }
        (None, None) => None,
    };

    let (editing_version, status, source, is_default) = selected_row
        .map(|row| {
            (
                row.get::<_, i32>("version"),
                row.get::<_, String>("status"),
                MailTemplateSource {
                    subject_template: row.get("subject_template"),
                    html_template: row.get("html_template"),
                    text_template: row.get("text_template"),
                },
                false,
            )
        })
        .unwrap_or((0, "default".to_owned(), default_source(definition), true));

    Ok(MailTemplateDetail {
        template_key: definition.template_key,
        display_name: definition.display_name,
        enabled,
        active_version,
        editing_version,
        status,
        is_default,
        source,
        variables: template_variables(template_key),
        default_source: default_source(definition),
    })
}

pub async fn save_template_draft(
    pool: &Pool,
    template_key: &str,
    source: &MailTemplateSource,
    user_id: i32,
) -> Result<MailTemplateDetail, Box<dyn std::error::Error>> {
    let definition = template_definition(template_key).ok_or("未知邮件模板")?;
    validate_template(template_key, source)?;

    let mut conn = pool.get().await?;
    let transaction = conn.transaction().await?;
    transaction
        .execute(
            "INSERT INTO mail_template (template_key, display_name) VALUES ($1, $2) \
             ON CONFLICT (template_key) DO UPDATE SET display_name = EXCLUDED.display_name, update_at = NOW();",
            &[&template_key, &definition.display_name],
        )
        .await?;
    let draft = transaction
        .query_opt(
            "SELECT version FROM mail_template_version \
             WHERE template_key = $1 AND status = 'draft' FOR UPDATE;",
            &[&template_key],
        )
        .await?;
    match draft {
        Some(row) => {
            let version = row.get::<_, i32>("version");
            transaction
                .execute(
                    "UPDATE mail_template_version SET subject_template = $1, html_template = $2, \
                     text_template = $3, created_by = $4, update_at = NOW() \
                     WHERE template_key = $5 AND version = $6;",
                    &[
                        &source.subject_template,
                        &source.html_template,
                        &source.text_template,
                        &user_id,
                        &template_key,
                        &version,
                    ],
                )
                .await?;
        }
        None => {
            let version = transaction
                .query_one(
                    "SELECT COALESCE(MAX(version), 0) + 1 AS version \
                     FROM mail_template_version WHERE template_key = $1;",
                    &[&template_key],
                )
                .await?
                .get::<_, i32>("version");
            transaction
                .execute(
                    "INSERT INTO mail_template_version \
                     (template_key, version, status, subject_template, html_template, text_template, created_by) \
                     VALUES ($1, $2, 'draft', $3, $4, $5, $6);",
                    &[
                        &template_key,
                        &version,
                        &source.subject_template,
                        &source.html_template,
                        &source.text_template,
                        &user_id,
                    ],
                )
                .await?;
        }
    }
    transaction.commit().await?;
    get_template_detail(pool, template_key).await
}

pub async fn publish_template(
    pool: &Pool,
    template_key: &str,
) -> Result<MailTemplateDetail, Box<dyn std::error::Error>> {
    template_definition(template_key).ok_or("未知邮件模板")?;
    let mut conn = pool.get().await?;
    let transaction = conn.transaction().await?;
    let draft = transaction
        .query_opt(
            "SELECT version, subject_template, html_template, text_template \
             FROM mail_template_version WHERE template_key = $1 AND status = 'draft' FOR UPDATE;",
            &[&template_key],
        )
        .await?
        .ok_or("没有可发布的草稿")?;
    let version = draft.get::<_, i32>("version");
    let source = MailTemplateSource {
        subject_template: draft.get("subject_template"),
        html_template: draft.get("html_template"),
        text_template: draft.get("text_template"),
    };
    validate_template(template_key, &source)?;

    transaction
        .execute(
            "UPDATE mail_template_version SET status = 'archived' \
             WHERE template_key = $1 AND status = 'published';",
            &[&template_key],
        )
        .await?;
    transaction
        .execute(
            "UPDATE mail_template_version SET status = 'published', published_at = NOW(), update_at = NOW() \
             WHERE template_key = $1 AND version = $2;",
            &[&template_key, &version],
        )
        .await?;
    transaction
        .execute(
            "UPDATE mail_template SET active_version = $1, enabled = TRUE, update_at = NOW() \
             WHERE template_key = $2;",
            &[&version, &template_key],
        )
        .await?;
    transaction.commit().await?;
    get_template_detail(pool, template_key).await
}

pub async fn list_template_versions(
    pool: &Pool,
    template_key: &str,
) -> Result<Vec<MailTemplateVersion>, Box<dyn std::error::Error>> {
    template_definition(template_key).ok_or("未知邮件模板")?;
    let conn = pool.get().await?;
    let rows = conn
        .query(
            "SELECT version, status, created_by, create_at, update_at, published_at \
             FROM mail_template_version WHERE template_key = $1 ORDER BY version DESC;",
            &[&template_key],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|row| MailTemplateVersion {
            version: row.get("version"),
            status: row.get("status"),
            created_by: row.get("created_by"),
            create_at: row.get("create_at"),
            update_at: row.get("update_at"),
            published_at: row.get("published_at"),
        })
        .collect())
}

pub async fn restore_template_version(
    pool: &Pool,
    template_key: &str,
    version: i32,
    user_id: i32,
) -> Result<MailTemplateDetail, Box<dyn std::error::Error>> {
    template_definition(template_key).ok_or("未知邮件模板")?;
    let conn = pool.get().await?;
    let row = conn
        .query_opt(
            "SELECT subject_template, html_template, text_template FROM mail_template_version \
             WHERE template_key = $1 AND version = $2 AND status <> 'draft';",
            &[&template_key, &version],
        )
        .await?
        .ok_or("指定的模板版本不存在")?;
    let source = MailTemplateSource {
        subject_template: row.get("subject_template"),
        html_template: row.get("html_template"),
        text_template: row.get("text_template"),
    };
    drop(conn);
    save_template_draft(pool, template_key, &source, user_id).await
}

async fn get_published_source(
    pool: &Pool,
    template_key: &str,
) -> Result<Option<MailTemplateSource>, Box<dyn std::error::Error>> {
    let definition = template_definition(template_key).ok_or("未知邮件模板")?;
    let conn = pool.get().await?;
    let row = conn
        .query_opt(
            "SELECT t.enabled, v.subject_template, v.html_template, v.text_template \
             FROM mail_template t LEFT JOIN mail_template_version v \
             ON v.template_key = t.template_key AND v.version = t.active_version \
             WHERE t.template_key = $1;",
            &[&template_key],
        )
        .await?;
    let Some(row) = row else {
        return Ok(Some(default_source(definition)));
    };
    if !row.get::<_, bool>("enabled") {
        return Ok(None);
    }
    let subject_template = row.get::<_, Option<String>>("subject_template");
    let html_template = row.get::<_, Option<String>>("html_template");
    let text_template = row.get::<_, Option<String>>("text_template");
    Ok(match (subject_template, html_template, text_template) {
        (Some(subject_template), Some(html_template), Some(text_template)) => {
            Some(MailTemplateSource {
                subject_template,
                html_template,
                text_template,
            })
        }
        _ => Some(default_source(definition)),
    })
}

async fn send_rendered_mail(
    pool: &Pool,
    encryption_key: &str,
    recipient: &str,
    rendered: RenderedMailTemplate,
    retry_policy: MailRetryPolicy,
) -> Result<(), Box<dyn std::error::Error>> {
    send_rendered_mail_with_id(
        pool,
        encryption_key,
        recipient,
        rendered,
        retry_policy,
        None,
    )
    .await
}

async fn send_rendered_mail_with_id(
    pool: &Pool,
    encryption_key: &str,
    recipient: &str,
    rendered: RenderedMailTemplate,
    retry_policy: MailRetryPolicy,
    message_id: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let settings = get_mail_settings_from_database(pool).await?;
    if settings.smtp_host.trim().is_empty() || settings.sender.trim().is_empty() {
        return Err("尚未配置 SMTP 邮件服务器".into());
    }
    let sender_key = get_mail_sender_key_from_database(pool, encryption_key)
        .await?
        .ok_or("尚未配置发件邮箱密钥")?;
    let email_config = EmailConfig {
        host: settings.smtp_host,
        account_username: settings.sender.clone(),
        account_password: sender_key,
    };
    let message = Message::builder()
        .from(Mailbox::new(
            Some("Network Mapping".to_owned()),
            settings.sender.parse()?,
        ))
        .to(recipient.parse()?)
        .subject(rendered.subject)
        .message_id(message_id)
        .multipart(MultiPart::alternative_plain_html(
            rendered.text_body,
            rendered.html_body,
        ))?;
    try_send_email(&email_config, settings.smtp_port, message, retry_policy).await?;
    Ok(())
}

pub async fn send_template_test(
    pool: &Pool,
    encryption_key: &str,
    template_key: &str,
    recipient: &str,
    source: &MailTemplateSource,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut context = sample_context(template_key)?;
    if matches!(
        template_key,
        REPORT_WEEKLY_TEMPLATE_KEY | REPORT_MONTHLY_TEMPLATE_KEY
    ) {
        let client = pool.get().await?;
        let settings = crate::reports::mail_config::load(&client)
            .await
            .map_err(std::io::Error::other)?;
        context.insert(
            "trend_image_url",
            &if settings.remote_images_enabled {
                settings.url("/mail/report-images/sample/trend.png")
            } else {
                String::new()
            },
        );
        context.insert("detail_url", &settings.url("/reports"));
    }
    let rendered = render_template(template_key, source, &context)?;
    send_rendered_mail(
        pool,
        encryption_key,
        recipient,
        rendered,
        MailRetryPolicy::Interactive,
    )
    .await
}

pub async fn send_login_notification(
    pool: &Pool,
    encryption_key: &str,
    user_id: i32,
    username: &str,
    source_ip: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let settings = get_mail_settings_from_database(pool).await?;
    if !settings.notification_prefs.login_notify_enabled {
        return Ok(false);
    }
    let Some(recipient) = get_user_notification_recipient(pool, user_id).await? else {
        return Ok(false);
    };
    let Some(source) = get_published_source(pool, LOGIN_SUCCESS_TEMPLATE_KEY).await? else {
        return Ok(false);
    };
    let context = login_context(username, source_ip)?;
    let rendered = render_template(LOGIN_SUCCESS_TEMPLATE_KEY, &source, &context)?;
    send_rendered_mail(
        pool,
        encryption_key,
        &recipient,
        rendered,
        MailRetryPolicy::Background,
    )
    .await?;
    Ok(true)
}

/// 向所有启用中的管理员发送健康告警。
///
/// 发送前依次检查全局通知偏好、管理员收件人与已发布模板；任一条件不满足即静默跳过。
pub async fn send_health_alert(
    pool: &Pool,
    encryption_key: &str,
    event: &HealthEvent,
) -> Result<(), Box<dyn std::error::Error>> {
    let settings = get_mail_settings_from_database(pool).await?;
    if !settings.notification_prefs.health_alert_enabled {
        return Ok(());
    }
    if settings.smtp_host.trim().is_empty()
        || settings.sender.trim().is_empty()
        || !settings.sender_key_configured
    {
        return Ok(());
    }
    let recipients = get_admin_recipients(pool).await?;
    if recipients.is_empty() {
        return Ok(());
    }
    let Some(source) = get_published_source(pool, HEALTH_ALERT_TEMPLATE_KEY).await? else {
        return Ok(());
    };
    let context = health_alert_context(event)?;
    let rendered = render_template(HEALTH_ALERT_TEMPLATE_KEY, &source, &context)?;
    let recipient_count = recipients.len();
    let mut failure_count = 0_usize;
    let mut last_error = None;
    for (recipient_index, recipient) in recipients.into_iter().enumerate() {
        if let Err(error_value) = send_rendered_mail(
            pool,
            encryption_key,
            &recipient,
            rendered.clone(),
            MailRetryPolicy::Background,
        )
        .await
        {
            failure_count += 1;
            tracing::error!(
                event = "HealthAlertRecipientSendError",
                operation = "send_health_alert_email",
                error_kind = "email_delivery",
                error_code = "health_alert_recipient_delivery_failed",
                error_message = %error_value,
                retryable = false,
                outcome = "remaining_recipients_continued",
                recipient_index,
                recipient_count,
                failure_count,
                "单个健康告警收件人发送失败，继续发送其他收件人"
            );
            last_error = Some(error_value.to_string());
        }
    }
    if failure_count > 0 {
        let last_error = last_error.unwrap_or_else(|| "未知错误".to_owned());
        return Err(format!(
            "健康告警邮件有 {failure_count}/{recipient_count} 个收件人发送失败；最后错误: {last_error}"
        )
        .into());
    }
    Ok(())
}

pub struct ScannerOutageMail<'a> {
    pub kind: &'a str,
    pub scanner_id: &'a str,
    pub scanner_name: &'a str,
    pub location: &'a str,
    pub last_seen_at: DateTime<Utc>,
    pub event_at: DateTime<Utc>,
}

pub async fn send_scanner_outage_email(
    pool: &Pool,
    encryption_key: &str,
    recipient: &str,
    mail: &ScannerOutageMail<'_>,
) -> Result<bool, Box<dyn std::error::Error>> {
    let Some(source) = get_published_source(pool, SCANNER_OUTAGE_TEMPLATE_KEY).await? else {
        return Ok(false);
    };
    let context = Context::from_serialize(json!({
        "system_name": "Network Mapping",
        "event_label": if mail.kind == "offline" { "掉线" } else { "恢复" },
        "scanner_name": mail.scanner_name,
        "scanner_id": mail.scanner_id,
        "location": mail.location,
        "last_seen_at": mail.last_seen_at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        "event_at": mail.event_at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        "detail_path": format!("/scanner/{}", mail.scanner_id),
    }))?;
    let rendered = render_template(SCANNER_OUTAGE_TEMPLATE_KEY, &source, &context)?;
    send_rendered_mail(
        pool,
        encryption_key,
        recipient,
        rendered,
        MailRetryPolicy::Background,
    )
    .await?;
    Ok(true)
}

/// 枚举所有启用中的管理员（`role = 1`）邮箱，过滤掉无效或缺失的地址。
pub async fn get_admin_recipients(pool: &Pool) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let conn = pool.get().await?;
    let rows = conn
        .query(
            "SELECT email FROM users WHERE role = 1 AND disabled_at IS NULL AND deleted_at IS NULL \
             AND email IS NOT NULL AND trim(email) <> '';",
            &[],
        )
        .await?;
    let mut recipients = Vec::new();
    for row in rows {
        let email = row.get::<_, String>("email");
        if let Ok(Some(validated)) = normalize_user_notification_recipient(Some(&email)) {
            recipients.push(validated.to_owned());
        }
    }
    Ok(recipients)
}

fn health_alert_context(event: &HealthEvent) -> Result<Context, tera::Error> {
    let details = event
        .details
        .iter()
        .map(|(label, value)| json!({ "label": label, "value": value }))
        .collect::<Vec<_>>();
    Context::from_serialize(json!({
        "system_name": "Network Mapping",
        "alert_type": event.alert_type,
        "severity": event.severity,
        "occurred_at": crate::system_time::format_now(),
        "summary": event.summary,
        "details": details,
    }))
}

/// 获取真实通知的用户收件地址。系统级测试收件人不得在此处作为回退值。
pub(crate) async fn get_user_notification_recipient(
    pool: &Pool,
    user_id: i32,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let conn = pool.get().await?;
    let user_email = conn
        .query_opt(
            "SELECT email FROM users WHERE id = $1 AND role IN (1, 2) \
             AND disabled_at IS NULL AND deleted_at IS NULL LIMIT 1;",
            &[&user_id],
        )
        .await?
        .and_then(|row| row.get::<_, Option<String>>("email"));
    Ok(normalize_user_notification_recipient(user_email.as_deref())?.map(str::to_owned))
}

fn normalize_user_notification_recipient(
    email: Option<&str>,
) -> Result<Option<&str>, Box<dyn std::error::Error>> {
    let Some(email) = email.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    email.parse::<Mailbox>()?;
    Ok(Some(email))
}

pub fn validation_error_message(error: &dyn std::error::Error) -> String {
    let message = error.to_string();
    if message.len() > 500 {
        "模板校验失败，请检查 Tera 语法和变量".to_owned()
    } else {
        message
    }
}

pub fn audit_source_metadata(source: &MailTemplateSource) -> Value {
    json!({
        "subject_length": source.subject_template.chars().count(),
        "html_bytes": source.html_template.len(),
        "text_bytes": source.text_template.len()
    })
}

/// Capture the published source inside the report input transaction.
pub(crate) async fn load_report_template<C: deadpool_postgres::GenericClient + Sync>(
    client: &C,
    key: &str,
) -> Result<Option<(MailTemplateSource, i32)>, String> {
    let definition = template_definition(key).ok_or("未知报告模板")?;
    let row = client.query_opt("SELECT t.enabled, t.active_version, v.subject_template, v.html_template, v.text_template \
        FROM mail_template t LEFT JOIN mail_template_version v ON v.template_key = t.template_key AND v.version = t.active_version \
        WHERE t.template_key = $1;", &[&key]).await.map_err(|e| e.to_string())?;
    let mut version = 0;
    let mut source = default_source(definition);
    if let Some(row) = row {
        if !row.get::<_, bool>("enabled") {
            return Ok(None);
        }
        if let Some(subject) = row.get::<_, Option<String>>("subject_template") {
            version = row.get::<_, Option<i32>>("active_version").unwrap_or(0);
            source = MailTemplateSource {
                subject_template: subject,
                html_template: row.get("html_template"),
                text_template: row.get("text_template"),
            };
        }
    }
    Ok(Some((source, version)))
}

pub(crate) async fn send_archived_report(
    pool: &Pool,
    encryption_key: &str,
    recipient: &str,
    rendered: Value,
    delivery_id: uuid::Uuid,
) -> Result<(), String> {
    let rendered: RenderedMailTemplate =
        serde_json::from_value(rendered).map_err(|e| e.to_string())?;
    send_rendered_mail_with_id(
        pool,
        encryption_key,
        recipient,
        rendered,
        MailRetryPolicy::Background,
        Some(format!("<report-{delivery_id}@network-mapping.local>")),
    )
    .await
    .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        LOGIN_SUCCESS_TEMPLATE_KEY, MailTemplateSource, SCANNER_OUTAGE_TEMPLATE_KEY,
        default_source, login_context, normalize_user_notification_recipient, render_template,
        sample_context, sanitize_email_html, template_definition, validate_template,
    };

    #[test]
    fn default_login_template_renders_and_inlines_css() {
        let definition = template_definition(LOGIN_SUCCESS_TEMPLATE_KEY).unwrap();
        let rendered = render_template(
            LOGIN_SUCCESS_TEMPLATE_KEY,
            &default_source(definition),
            &login_context("alice", "192.0.2.10").unwrap(),
        )
        .unwrap();

        assert!(rendered.subject.contains("Network Mapping"));
        assert!(rendered.html_body.contains("alice"));
        assert!(rendered.html_body.contains("style="));
        assert!(rendered.text_body.contains("192.0.2.10"));
    }

    #[test]
    fn scanner_outage_template_renders_both_bodies() {
        let definition = template_definition(SCANNER_OUTAGE_TEMPLATE_KEY).unwrap();
        let rendered = render_template(
            SCANNER_OUTAGE_TEMPLATE_KEY,
            &default_source(definition),
            &sample_context(SCANNER_OUTAGE_TEMPLATE_KEY).unwrap(),
        )
        .unwrap();
        assert!(rendered.subject.contains("扫描器掉线"));
        assert!(rendered.html_body.contains("/scanner/01952f0c"));
        assert!(rendered.text_body.contains("最后心跳"));
    }

    #[test]
    fn missing_variable_is_rejected() {
        let source = MailTemplateSource {
            subject_template: "{{ unknown }}".to_owned(),
            html_template: "<p>ok</p>".to_owned(),
            text_template: "ok".to_owned(),
        };
        assert!(validate_template(LOGIN_SUCCESS_TEMPLATE_KEY, &source).is_err());
    }

    #[test]
    fn subject_header_injection_is_rejected() {
        let source = MailTemplateSource {
            subject_template: "hello\nBcc: attacker@example.com".to_owned(),
            html_template: "<p>ok</p>".to_owned(),
            text_template: "ok".to_owned(),
        };
        assert!(validate_template(LOGIN_SUCCESS_TEMPLATE_KEY, &source).is_err());
    }

    #[test]
    fn dangerous_html_is_removed() {
        let sanitized =
            sanitize_email_html("<p onclick=\"alert(1)\">safe</p><script>alert(2)</script>");
        assert!(sanitized.contains("safe"));
        assert!(!sanitized.contains("onclick"));
        assert!(!sanitized.contains("script"));
    }

    #[test]
    fn user_notification_recipient_uses_only_valid_profile_email() {
        assert_eq!(normalize_user_notification_recipient(None).unwrap(), None);
        assert_eq!(
            normalize_user_notification_recipient(Some("  ")).unwrap(),
            None
        );
        assert_eq!(
            normalize_user_notification_recipient(Some(" alice@example.com ")).unwrap(),
            Some("alice@example.com")
        );
        assert!(normalize_user_notification_recipient(Some("not-an-email")).is_err());
    }
}
