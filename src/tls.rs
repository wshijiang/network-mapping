use std::io;

use openssl::ssl::{SslAcceptor, SslAcceptorBuilder, SslFiletype, SslMethod};

use crate::config::TlsConfig;

/// TLS listeners always use secure cookies, regardless of forwarding headers.
/// A loopback HTTP listener may sit behind a local HTTPS proxy; that proxy must
/// overwrite Forwarded/X-Forwarded-Proto rather than pass client values through.
pub fn request_uses_https(request: &actix_web::HttpRequest) -> bool {
    request
        .app_data::<actix_web::web::Data<TlsConfig>>()
        .is_none_or(|config| config.enabled)
        || request.connection_info().scheme() == "https"
}

pub fn build_acceptor(config: &TlsConfig) -> io::Result<SslAcceptorBuilder> {
    let mut tls = SslAcceptor::mozilla_intermediate(SslMethod::tls_server())
        .map_err(|error| io::Error::other(format!("创建 TLS 接收器失败: {error}")))?;

    tls.set_private_key_file(&config.private_key_file, SslFiletype::PEM)
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "读取 TLS 私钥文件 {} 失败: {error}",
                    config.private_key_file.display()
                ),
            )
        })?;
    tls.set_certificate_chain_file(&config.certificate_chain_file)
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "读取 TLS 证书链文件 {} 失败: {error}",
                    config.certificate_chain_file.display()
                ),
            )
        })?;
    tls.check_private_key().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("TLS 证书与私钥不匹配: {error}"),
        )
    })?;

    Ok(tls)
}

#[cfg(test)]
mod tests {
    use super::{build_acceptor, request_uses_https};
    use crate::config::TlsConfig;
    use std::path::PathBuf;

    #[test]
    fn secure_response_policy_preserves_tls_and_supports_local_http() {
        for (enabled, forwarded_proto, expected) in [
            (true, "http", true),
            (true, "https", true),
            (false, "http", false),
            (false, "https", true),
        ] {
            let request = actix_web::test::TestRequest::default()
                .app_data(actix_web::web::Data::new(TlsConfig {
                    enabled,
                    certificate_chain_file: PathBuf::new(),
                    private_key_file: PathBuf::new(),
                }))
                .insert_header(("x-forwarded-proto", forwarded_proto))
                .to_http_request();
            assert_eq!(request_uses_https(&request), expected);
        }
        let request = actix_web::test::TestRequest::default().to_http_request();
        assert!(request_uses_https(&request));
    }

    #[actix_web::test]
    async fn http_responses_omit_hsts_and_preserve_other_security_headers() {
        use actix_web::{App, HttpResponse, http::header, test, web};

        for enabled in [false, true] {
            let app = test::init_service(
                App::new()
                    .app_data(web::Data::new(TlsConfig {
                        enabled,
                        certificate_chain_file: PathBuf::new(),
                        private_key_file: PathBuf::new(),
                    }))
                    .wrap(crate::middlewares::hmiddleware::SHeaderM)
                    .default_service(web::to(|| async { HttpResponse::Ok().finish() })),
            )
            .await;
            let response =
                test::call_service(&app, test::TestRequest::default().to_request()).await;
            assert_eq!(
                response
                    .headers()
                    .contains_key(header::STRICT_TRANSPORT_SECURITY),
                enabled
            );
            assert_eq!(
                response.headers().get(header::X_FRAME_OPTIONS).unwrap(),
                "DENY"
            );
            assert_eq!(
                response
                    .headers()
                    .get(header::X_CONTENT_TYPE_OPTIONS)
                    .unwrap(),
                "nosniff"
            );
            assert!(
                response
                    .headers()
                    .contains_key(header::CONTENT_SECURITY_POLICY)
            );
        }
    }

    #[test]
    fn missing_private_key_error_contains_configured_path() {
        let config = TlsConfig {
            enabled: true,
            certificate_chain_file: PathBuf::from("missing-cert.pem"),
            private_key_file: PathBuf::from("missing-key.pem"),
        };

        let error = match build_acceptor(&config) {
            Ok(_) => panic!("missing TLS files must fail"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("missing-key.pem"));
    }
}
