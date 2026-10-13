//! web_support domain implementation, migrated from the library root.

use actix_web::HttpRequest;
use std::path::{Path, PathBuf};
use tera::{Context, Tera};
use tracing::{error, warn};

pub const TEXT_HTML_UTF_8: &str = "text/html; charset=utf-8";

pub const TEXT_CSS_UTF_8: &str = "text/css; charset=utf-8";

pub const APPLICATION_JAVASCRIPT_UTF_8: &str = "application/javascript; charset=utf-8";

pub const IMAGE_PNG: &str = "image/png";

pub const APPLICATION_OCTET_STREAM: &str = "application/octet-stream";

pub const APPLICATION_JSON: &str = "application/json";

pub(crate) struct FrontEndErrorInfo<'a> {
    pub(crate) status_code: u16,
    pub(crate) error_title: &'a str,
    pub(crate) error_message: &'a str,
    pub(crate) request_id: String,
}

pub struct _ProxySetting {
    _status: bool,
    _headers: String,
}

pub struct ReadFile {
    pub file_name: String,
    pub file_root_directory: String,
}

#[derive(Clone)]
pub struct TemplatesInit {
    pub templates_directory: String,
    pub templates_name: String,
}

///自实现MIME系统。接受一个&str类型的文件后缀，返回一个&str。
#[allow(dead_code)]
fn mime_system(file_suffix: &str) -> &str {
    match file_suffix.to_lowercase().as_str() {
        "html" => TEXT_HTML_UTF_8,
        "css" => TEXT_CSS_UTF_8,
        "png" => IMAGE_PNG,
        "js" => APPLICATION_JAVASCRIPT_UTF_8,
        _ => APPLICATION_OCTET_STREAM,
    }
}

///获取文件后缀，可以输入文件名或者是带路径的文件名 e.g example.png 、 directory/example.png
#[allow(dead_code)]
fn get_file_suffix(path_or_file_name: &Path) -> Result<&str, &str> {
    match path_or_file_name.extension().and_then(|s| s.to_str()) {
        Some(ext) => Ok(ext),
        None => {
            warn!("没有扩展名或无法获取扩展名");
            Err("没有扩展名或无法获取扩展名")
        }
    }
}

///# 前端错误页面
///
/// 该函数主要接受错误信息并根据模板返回错误页的HTML
pub(crate) fn front_end_error_page(info: &FrontEndErrorInfo, templates: &TemplatesInit) -> String {
    //在初始化模板时必须用相对路径
    let tera = match Tera::new(&templates.templates_directory) {
        Ok(t) => t,
        Err(e) => {
            error!(
                event = "FrontendTemplateInitializationError",
                operation = "initialize_frontend_templates",
                error_kind = "template",
                error_code = "frontend_template_initialization_failed",
                error_message = %e,
                retryable = false,
                outcome = "process_panicking",
            );
            panic!("tera初始化错误");
        }
    };

    let mut context = Context::new();
    context.insert("status_code", &info.status_code);
    context.insert("error_title", &info.error_title);
    context.insert("error_message", &info.error_message);
    context.insert("request_id", &info.request_id);

    match tera.render(&templates.templates_name, &context) {
        Ok(body) => body,
        Err(e) => {
            error!(
                event = "FrontendErrorPageRenderError",
                operation = "render_frontend_error_page",
                error_kind = "template",
                error_code = "frontend_error_page_render_failed",
                error_message = %e,
                retryable = false,
                outcome = "fallback_error_page_returned",
                http_status = info.status_code,
            );
            eprintln!("Render error: {}", e);
            "<h1>系统故障</h1><p>故障组件：模板系统</p>".to_string()
        }
    }
}

///调用者应当按照实际情况处理None值
/// 目前我感觉无需使用泛型 AsRef<Path>
pub fn path_secure_join(root: &str, input: &str) -> Option<PathBuf> {
    let root = Path::new(root);
    let full_path = root.join(input);
    let canonical = full_path.canonicalize().ok()?;

    if canonical.starts_with(root.canonicalize().ok()?) {
        Some(canonical)
    } else {
        None
    }
}

///通过该函数获取到访问者的ip，如果失败则会返回一个字符串
pub fn get_conn_ip(req: &HttpRequest) -> String {
    match crate::client_ip::request_ip(req) {
        Some(value) => value.to_string(),
        None => {
            warn!(
                event = "GetHTTPClientIPError",
                message = "无法获取到访问者IP"
            );
            "Unknown".to_string()
        }
    }
}

///通过该函数获取收到的http请求头，如果获取失败则会返回一个字符串
pub fn get_user_agent(req: &HttpRequest) -> String {
    // req.headers().get("User-Agent").and_then(|v| v.to_str().ok()).unwrap_or("unknown").to_string()
    match req.headers().get("User-Agent") {
        Some(o) => match o.to_str() {
            Ok(o) => o.to_string(),
            Err(e) => {
                warn!(event = "GetHTTPHeadersError", message = e.to_string());
                "Unknown".to_string()
            }
        },
        None => {
            warn!(
                event = "UserAgentMissing",
                operation = "read_user_agent_header",
                reason = "request has no User-Agent header",
                outcome = "unknown_user_agent_used",
            );
            "Unknown".to_string()
        }
    }
}
