//! Pure report-render capability used by the server and the standalone worker.
//! Template input is captured by the host; DB, assets and SMTP stay with the host.
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{self as mail_template, MailTemplateSource, RenderedMailTemplate};
use nm_module_runtime::{Module, ModuleContract, ModuleError, ModuleFuture};

pub const MODULE_ID: &str = "report-render";
pub const INPUT_SCHEMA: &str = "report-render-input.v1";
pub const OUTPUT_SCHEMA: &str = "rendered-report-mail.v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReportRenderInput {
    pub template_key: String,
    pub template_version: i32,
    pub source: MailTemplateSource,
    pub context: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReportRenderOutput {
    pub template_version: i32,
    pub rendered: RenderedMailTemplate,
}

pub struct LocalReportRenderModule;

fn render(input: ReportRenderInput) -> Result<ReportRenderOutput, ModuleError> {
    if !matches!(
        input.template_key.as_str(),
        mail_template::REPORT_WEEKLY_TEMPLATE_KEY | mail_template::REPORT_MONTHLY_TEMPLATE_KEY
    ) || input.template_version < 0
    {
        return Err(ModuleError::Execution(
            "invalid report template identity".into(),
        ));
    }
    let context = tera::Context::from_serialize(input.context)
        .map_err(|e| ModuleError::Execution(e.to_string()))?;
    let rendered = mail_template::render_template(&input.template_key, &input.source, &context)
        .map_err(|e| ModuleError::Execution(e.to_string()))?;
    Ok(ReportRenderOutput {
        template_version: input.template_version,
        rendered,
    })
}

impl Module for LocalReportRenderModule {
    fn contract(&self) -> ModuleContract {
        ModuleContract {
            module_id: MODULE_ID.into(),
            release_id: format!("report-render-local-{}", env!("CARGO_PKG_VERSION")),
            rpc_version: 1,
            input_schema: INPUT_SCHEMA.into(),
            output_schema: OUTPUT_SCHEMA.into(),
            methods: BTreeSet::from(["render".into()]),
        }
    }

    fn self_test(&self) -> ModuleFuture<'_, ()> {
        Box::pin(async {
            tokio::task::spawn_blocking(|| {
                let output = render(ReportRenderInput {
                    template_key: mail_template::REPORT_WEEKLY_TEMPLATE_KEY.into(),
                    template_version: 0,
                    source: MailTemplateSource {
                        subject_template: "Report {{ count }}".into(),
                        html_template: "<p>Count: {{ count }}</p>".into(),
                        text_template: "Count: {{ count }}".into(),
                    },
                    context: serde_json::json!({ "count": 2 }),
                })?;
                if output.rendered.subject != "Report 2" {
                    return Err(ModuleError::Execution(
                        "report renderer self test failed".into(),
                    ));
                }
                Ok(())
            })
            .await
            .map_err(|e| ModuleError::Execution(e.to_string()))?
        })
    }

    fn invoke<'a>(&'a self, method: &'a str, payload: Value) -> ModuleFuture<'a, Value> {
        Box::pin(async move {
            if method != "render" {
                return Err(ModuleError::UnsupportedMethod);
            }
            let input: ReportRenderInput = serde_json::from_value(payload)
                .map_err(|e| ModuleError::Execution(e.to_string()))?;
            tokio::task::spawn_blocking(move || {
                serde_json::to_value(render(input)?)
                    .map_err(|e| ModuleError::Execution(e.to_string()))
            })
            .await
            .map_err(|e| ModuleError::Execution(e.to_string()))?
        })
    }
}
