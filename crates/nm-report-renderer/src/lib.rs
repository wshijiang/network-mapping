//! Pure mail rendering and the replaceable report-render capability.
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tera::{Context, Tera};
pub mod module;
pub use module::*;

/// Host-side validation for results received from replaceable worker processes.
pub fn validate_rendered_mail(
    mail: &mut RenderedMailTemplate,
) -> Result<(), Box<dyn std::error::Error>> {
    if mail.subject.trim().is_empty()
        || mail.subject.chars().count() > 200
        || mail.subject.contains(['\r', '\n'])
    {
        return Err("渲染后的邮件主题无效".into());
    }
    if mail.html_body.len() > 1024 * 1024 || mail.text_body.len() > 1024 * 1024 {
        return Err("渲染后的邮件正文超过限制".into());
    }
    mail.html_body = sanitize_email_html(&mail.html_body);
    if mail.html_body.trim().is_empty() || mail.text_body.trim().is_empty() {
        return Err("渲染后的邮件正文不能为空".into());
    }
    Ok(())
}

pub const LOGIN_SUCCESS_TEMPLATE_KEY: &str = "login_success";

pub const HEALTH_ALERT_TEMPLATE_KEY: &str = "health_alert";

pub const SCANNER_OUTAGE_TEMPLATE_KEY: &str = "scanner_outage";

pub const REPORT_WEEKLY_TEMPLATE_KEY: &str = "report_weekly";

pub const REPORT_MONTHLY_TEMPLATE_KEY: &str = "report_monthly";

const MAX_SUBJECT_TEMPLATE_CHARS: usize = 500;

const MAX_BODY_TEMPLATE_BYTES: usize = 256 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MailTemplateSource {
    pub subject_template: String,
    pub html_template: String,
    pub text_template: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RenderedMailTemplate {
    pub subject: String,
    pub html_body: String,
    pub text_body: String,
}

pub fn validate_source_size(source: &MailTemplateSource) -> Result<(), Box<dyn std::error::Error>> {
    if source.subject_template.trim().is_empty() {
        return Err("邮件主题模板不能为空".into());
    }
    if source.subject_template.chars().count() > MAX_SUBJECT_TEMPLATE_CHARS {
        return Err("邮件主题模板不能超过 500 个字符".into());
    }
    if source.html_template.trim().is_empty() || source.text_template.trim().is_empty() {
        return Err("HTML 和纯文本模板均不能为空".into());
    }
    if source.html_template.len() > MAX_BODY_TEMPLATE_BYTES
        || source.text_template.len() > MAX_BODY_TEMPLATE_BYTES
    {
        return Err("邮件正文模板不能超过 256 KiB".into());
    }
    Ok(())
}

pub fn sanitize_email_html(html: &str) -> String {
    let mut sanitizer = ammonia::Builder::default();
    sanitizer
        .add_generic_attributes(&[
            "style",
            "width",
            "height",
            "align",
            "valign",
            "role",
            "aria-label",
        ])
        .filter_style_properties(HashSet::from([
            "background",
            "background-color",
            "border",
            "border-bottom",
            "border-color",
            "border-left",
            "border-radius",
            "border-right",
            "border-style",
            "border-top",
            "border-width",
            "color",
            "display",
            "font-family",
            "font-size",
            "font-style",
            "font-weight",
            "height",
            "letter-spacing",
            "line-height",
            "margin",
            "margin-bottom",
            "margin-left",
            "margin-right",
            "margin-top",
            "max-width",
            "min-width",
            "padding",
            "padding-bottom",
            "padding-left",
            "padding-right",
            "padding-top",
            "text-align",
            "text-decoration",
            "vertical-align",
            "white-space",
            "width",
        ]));
    sanitizer.clean(html).to_string()
}

pub fn render_template(
    template_key: &str,
    source: &MailTemplateSource,
    context: &Context,
) -> Result<RenderedMailTemplate, Box<dyn std::error::Error>> {
    if !matches!(
        template_key,
        LOGIN_SUCCESS_TEMPLATE_KEY
            | HEALTH_ALERT_TEMPLATE_KEY
            | SCANNER_OUTAGE_TEMPLATE_KEY
            | REPORT_WEEKLY_TEMPLATE_KEY
            | REPORT_MONTHLY_TEMPLATE_KEY
    ) {
        return Err("未知邮件模板".into());
    }
    validate_source_size(source)?;

    let mut tera = Tera::default();
    tera.add_raw_templates(vec![
        ("subject.txt", source.subject_template.as_str()),
        ("body.html", source.html_template.as_str()),
        ("body.txt", source.text_template.as_str()),
    ])?;

    let subject = tera.render("subject.txt", context)?.trim().to_owned();
    if subject.is_empty() || subject.chars().count() > 200 {
        return Err("渲染后的邮件主题必须为 1 到 200 个字符".into());
    }
    if subject.contains(['\r', '\n']) {
        return Err("渲染后的邮件主题不能包含换行符".into());
    }

    let html = tera.render("body.html", context)?;
    let inliner = css_inline::CSSInliner::options()
        .load_remote_stylesheets(false)
        .build();
    let html_body = sanitize_email_html(&inliner.inline(&html)?);
    let text_body = tera.render("body.txt", context)?;
    if html_body.trim().is_empty() || text_body.trim().is_empty() {
        return Err("渲染后的邮件正文不能为空".into());
    }

    Ok(RenderedMailTemplate {
        subject,
        html_body,
        text_body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nm_module_runtime::{ModuleError, ModuleRegistry, ModuleSlot};
    use serde_json::json;
    use std::{
        collections::{BTreeMap, BTreeSet},
        sync::Arc,
        time::Duration,
    };
    fn slot() -> ModuleSlot {
        ModuleSlot {
            rpc_version: 1,
            input_schema: INPUT_SCHEMA.into(),
            output_schema: OUTPUT_SCHEMA.into(),
            methods: BTreeSet::from(["render".into()]),
            max_inflight: 1,
            max_payload_bytes: 1024,
            request_timeout: Duration::from_secs(1),
            prepare_timeout: Duration::from_secs(1),
        }
    }
    #[tokio::test]
    async fn report_adapter_renders_published_input_with_existing_mail_validation() {
        let mut policy = slot();
        policy.input_schema = INPUT_SCHEMA.into();
        policy.output_schema = OUTPUT_SCHEMA.into();
        policy.methods = BTreeSet::from(["render".into()]);
        let registry = ModuleRegistry::new(BTreeMap::from([(MODULE_ID.into(), policy)])).unwrap();
        registry
            .publish(0, Arc::new(LocalReportRenderModule))
            .await
            .unwrap();
        let input = ReportRenderInput {
            template_key: crate::REPORT_WEEKLY_TEMPLATE_KEY.into(),
            template_version: 7,
            source: crate::MailTemplateSource {
                subject_template: "Weekly {{ count }}".into(),
                html_template: "<p>Count: {{ count }}</p><script>alert(1)</script>".into(),
                text_template: "Count: {{ count }}".into(),
            },
            context: json!({"count": 3}),
        };
        let lease = registry.acquire(MODULE_ID).await.unwrap();
        let output = lease
            .invoke("render", serde_json::to_value(&input).unwrap())
            .await
            .unwrap();
        let output: ReportRenderOutput = serde_json::from_value(output).unwrap();
        assert_eq!(output.template_version, 7);
        assert_eq!(output.rendered.subject, "Weekly 3");
        assert_eq!(output.rendered.text_body, "Count: 3");
        assert!(!output.rendered.html_body.contains("<script"));
        let invalid = ReportRenderInput {
            source: crate::MailTemplateSource {
                subject_template: "first\nsecond".into(),
                ..input.source
            },
            ..input
        };
        assert!(matches!(
            lease
                .invoke("render", serde_json::to_value(invalid).unwrap())
                .await,
            Err(ModuleError::Execution(_))
        ));
    }
}
