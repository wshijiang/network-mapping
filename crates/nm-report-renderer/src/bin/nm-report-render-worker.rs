//! An independently buildable report-render worker; stdout is reserved for IPC.
use nm_module_runtime::{
    Module,
    process::{RpcRequest, RpcResponse, read_frame, write_frame},
};
use nm_report_renderer::LocalReportRenderModule;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let module = LocalReportRenderModule;
    let mut contract = module.contract();
    contract.release_id = std::env::var("NM_MODULE_RELEASE_ID")?;
    let mut input = tokio::io::stdin();
    let mut output = tokio::io::stdout();
    write_frame(&mut output, &contract).await?;
    loop {
        let request: RpcRequest = match read_frame(&mut input).await {
            Ok(request) => request,
            Err(_) => break,
        };
        let result = if request.rpc_version != 1 {
            Err(nm_module_runtime::ModuleError::IncompatibleContract)
        } else if request.method == "__self_test" {
            module.self_test().await.map(|_| serde_json::Value::Null)
        } else {
            module.invoke(&request.method, request.payload).await
        };
        let (output_value, error) = match result {
            Ok(value) => (value, None),
            Err(error) => (serde_json::Value::Null, Some(error.to_string())),
        };
        write_frame(
            &mut output,
            &RpcResponse {
                request_id: request.request_id,
                rpc_version: 1,
                release_id: contract.release_id.clone(),
                output: output_value,
                error,
            },
        )
        .await?;
    }
    Ok(())
}
