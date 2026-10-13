//! Run from the server repository: cargo run --example report_module
//! Exercises the actual server library without DB, SMTP or production routes.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use network_mapping_server::mail_template::{MailTemplateSource, REPORT_WEEKLY_TEMPLATE_KEY};
use network_mapping_server::module_runtime::{ModuleRegistry, ModuleSlot};
use network_mapping_server::reports::render_module::{
    INPUT_SCHEMA, LocalReportRenderModule, MODULE_ID, OUTPUT_SCHEMA, ReportRenderInput,
    ReportRenderOutput,
};
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let slot = ModuleSlot {
        rpc_version: 1,
        input_schema: INPUT_SCHEMA.into(),
        output_schema: OUTPUT_SCHEMA.into(),
        methods: BTreeSet::from(["render".into()]),
        max_inflight: 8,
        max_payload_bytes: 1024 * 1024,
        request_timeout: Duration::from_secs(5),
        prepare_timeout: Duration::from_secs(30),
    };
    let registry = ModuleRegistry::new(BTreeMap::from([(MODULE_ID.into(), slot)]))?;
    registry
        .publish(0, Arc::new(LocalReportRenderModule))
        .await?;
    let input = ReportRenderInput {
        template_key: REPORT_WEEKLY_TEMPLATE_KEY.into(),
        template_version: 1,
        source: MailTemplateSource {
            subject_template: "Weekly report: {{ count }} tasks".into(),
            html_template: "<p>Completed tasks: {{ count }}</p>".into(),
            text_template: "Completed tasks: {{ count }}".into(),
        },
        context: json!({"count": 3}),
    };
    let lease = registry.acquire(MODULE_ID).await?;
    let result = lease.invoke("render", serde_json::to_value(input)?).await?;
    let result: ReportRenderOutput = serde_json::from_value(result)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "releaseId": lease.release_id(),
            "generation": lease.generation(),
            "result": result,
        }))?
    );
    Ok(())
}
