use super::*;
#[test]
fn urls_are_bounded_and_credentials_never_appear_in_views_or_debug() {
    for url in [
        "http://user:secret@localhost:8080",
        "https://user:secret@proxy.example.com",
        "socks5://localhost:1080",
        "socks5h://user:secret@proxy.example.com:1080",
    ] {
        assert!(validate_url(url).is_ok(), "{url}");
        let endpoint = endpoint(url).unwrap();
        assert!(!endpoint.contains("secret"));
        assert!(!endpoint.contains("user@"));
        assert!(
            !format!(
                "{:?}",
                ProxyConfig {
                    mode: ProxyMode::Custom,
                    url: url.into()
                }
            )
            .contains("secret")
        );
    }
    for url in [
        "ftp://localhost:21",
        "socks4://localhost:1080",
        "socks5://localhost",
        "http://localhost/path",
        "http://localhost?x=1",
        "http://localhost/#x",
        "http://u%0d%0a:pw@localhost:8080",
        " http://localhost:8080",
        "http://localhost:0",
    ] {
        assert!(validate_url(url).is_err(), "{url}");
    }
}

fn certificates() -> (
    tokio_native_tls::TlsAcceptor,
    tokio_native_tls::TlsConnector,
) {
    use openssl::{
        asn1::Asn1Time,
        hash::MessageDigest,
        pkey::PKey,
        rsa::Rsa,
        x509::{
            X509, X509NameBuilder,
            extension::{BasicConstraints, SubjectAlternativeName},
        },
    };
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "smtp.fixture.test")
        .unwrap();
    let name = name.build();
    let mut cert = X509::builder().unwrap();
    cert.set_version(2).unwrap();
    cert.set_pubkey(&key).unwrap();
    cert.set_subject_name(&name).unwrap();
    cert.set_issuer_name(&name).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    cert.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();
    let san = SubjectAlternativeName::new()
        .dns("smtp.fixture.test")
        .dns("localhost")
        .ip("127.0.0.1")
        .build(&cert.x509v3_context(None, None))
        .unwrap();
    cert.append_extension(san).unwrap();
    cert.sign(&key, MessageDigest::sha256()).unwrap();
    let pem = cert.build().to_pem().unwrap();
    let identity =
        native_tls::Identity::from_pkcs8(&pem, &key.private_key_to_pem_pkcs8().unwrap()).unwrap();
    let acceptor =
        tokio_native_tls::TlsAcceptor::from(native_tls::TlsAcceptor::new(identity).unwrap());
    let connector = native_tls::TlsConnector::builder()
        .add_root_certificate(native_tls::Certificate::from_pem(&pem).unwrap())
        .build()
        .unwrap();
    (acceptor, tokio_native_tls::TlsConnector::from(connector))
}
async fn smtp_fixture(
    listener: tokio::net::TcpListener,
    tls: tokio_native_tls::TlsAcceptor,
) -> usize {
    use tokio::io::{AsyncBufReadExt, BufReader};
    let (stream, _) = listener.accept().await.unwrap();
    let Ok(stream) = tls.accept(stream).await else {
        return 0;
    };
    let mut stream = BufReader::new(stream);
    if stream.write_all(b"220 fixture ESMTP\r\n").await.is_err() {
        return 0;
    }
    let mut recipients = 0;
    let mut sent = false;
    loop {
        let mut line = String::new();
        if stream.read_line(&mut line).await.unwrap_or(0) == 0 {
            break;
        }
        let response = if line.starts_with("EHLO") {
            "250-fixture\r\n250-8BITMIME\r\n250-AUTH PLAIN LOGIN\r\n250 SMTPUTF8\r\n"
        } else if line.starts_with("AUTH PLAIN") {
            "235 authenticated\r\n"
        } else if line.starts_with("MAIL FROM") {
            "250 sender\r\n"
        } else if line.starts_with("RCPT TO") {
            recipients += 1;
            "250 recipient\r\n"
        } else if line.starts_with("DATA") {
            stream.write_all(b"354 data\r\n").await.unwrap();
            let mut body = String::new();
            loop {
                let mut part = String::new();
                stream.read_line(&mut part).await.unwrap();
                if part == ".\r\n" {
                    break;
                }
                body.push_str(&part);
            }
            assert!(!body.contains("Bcc:"));
            sent = true;
            "250 accepted\r\n"
        } else if line.starts_with("QUIT") {
            stream.write_all(b"221 bye\r\n").await.unwrap();
            break;
        } else {
            panic!("unexpected SMTP command")
        };
        stream.write_all(response.as_bytes()).await.unwrap();
    }
    if sent { recipients } else { 0 }
}
async fn proxy_fixture(
    listener: tokio::net::TcpListener,
    scheme: &str,
    smtp_port: u16,
    tls: tokio_native_tls::TlsAcceptor,
) {
    let (socket, _) = listener.accept().await.unwrap();
    let mut stream: Stream = Box::new(socket);
    if scheme == "https" {
        stream = Box::new(VerifiedTls(tls.accept(stream).await.unwrap()));
    }
    if scheme.starts_with("socks") {
        let mut greeting = [0; 3];
        stream.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 1, 2]);
        stream.write_all(&[5, 2]).await.unwrap();
        assert_eq!(stream.read_u8().await.unwrap(), 1);
        let len = stream.read_u8().await.unwrap();
        let mut user = vec![0; usize::from(len)];
        stream.read_exact(&mut user).await.unwrap();
        assert_eq!(user, b"user");
        let len = stream.read_u8().await.unwrap();
        let mut password = vec![0; usize::from(len)];
        stream.read_exact(&mut password).await.unwrap();
        assert_eq!(password, b"secret");
        stream.write_all(&[1, 0]).await.unwrap();
        let mut request = [0; 4];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request[..3], &[5, 1, 0]);
        if scheme == "socks5h" {
            assert_eq!(request[3], 3);
            let len = stream.read_u8().await.unwrap();
            let mut domain = vec![0; usize::from(len)];
            stream.read_exact(&mut domain).await.unwrap();
            assert_eq!(domain, b"smtp.fixture.test");
        } else {
            assert_eq!(request[3], 1);
            let mut address = [0; 4];
            stream.read_exact(&mut address).await.unwrap();
            assert_eq!(address, [127, 0, 0, 1]);
        }
        assert_eq!(stream.read_u16().await.unwrap(), smtp_port);
        stream
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
            .await
            .unwrap();
    } else {
        let mut header = vec![];
        while !header.ends_with(b"\r\n\r\n") {
            header.push(stream.read_u8().await.unwrap());
            assert!(header.len() < 8192);
        }
        let header = String::from_utf8(header).unwrap();
        assert!(
            header.starts_with("CONNECT ")
                && header.contains(&format!(":{smtp_port} HTTP/1.1\r\n"))
        );
        assert!(header.contains(&format!(
            "Proxy-Authorization: Basic {}",
            openssl::base64::encode_block(b"user:secret")
        )));
        stream
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await
            .unwrap();
    }
    let mut target = TcpStream::connect(("127.0.0.1", smtp_port)).await.unwrap();
    let _ = tokio::io::copy_bidirectional(&mut stream, &mut target).await;
}
fn message() -> Message {
    Message::builder()
        .from("sender@example.com".parse().unwrap())
        .to("one@example.com".parse().unwrap())
        .bcc("two@example.com".parse().unwrap())
        .subject("fixture")
        .body("test message".to_owned())
        .unwrap()
}

#[tokio::test]
async fn smtp_delivers_through_http_https_and_both_socks_dns_modes_with_verified_tls() {
    for scheme in ["http", "https", "socks5h", "socks5"] {
        let (acceptor, tls) = certificates();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let smtp_port = listener.local_addr().unwrap().port();
        let smtp = tokio::spawn(smtp_fixture(listener, acceptor.clone()));
        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = proxy_listener.local_addr().unwrap().port();
        let proxy = tokio::spawn(proxy_fixture(proxy_listener, scheme, smtp_port, acceptor));
        let config = ProxyConfig {
            mode: ProxyMode::Custom,
            url: format!("{scheme}://user:secret@localhost:{port}"),
        };
        let host = if scheme == "socks5" {
            "127.0.0.1"
        } else {
            "smtp.fixture.test"
        };
        tokio::time::timeout(
            Duration::from_secs(5),
            send_tunneled(
                &config,
                host,
                smtp_port,
                "sender@example.com",
                "smtp-secret",
                &message(),
                &tls,
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(smtp.await.unwrap(), 2);
        proxy.abort();
    }
}
#[tokio::test]
async fn proxy_authentication_failure_is_permanent_and_never_falls_back() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let proxy = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut header = vec![];
        while !header.ends_with(b"\r\n\r\n") {
            header.push(stream.read_u8().await.unwrap());
        }
        stream
            .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
            .await
            .unwrap();
    });
    let config = ProxyConfig {
        mode: ProxyMode::Custom,
        url: format!("http://user:secret@127.0.0.1:{port}"),
    };
    let error = send_smtp(
        &config,
        "smtp.fixture.test",
        465,
        "sender",
        "secret",
        &message(),
        Duration::from_secs(2),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code, "proxy_authentication_failed");
    assert!(!error.retryable);
    assert!(!error.to_string().contains("secret"));
    proxy.await.unwrap();
}
#[tokio::test]
async fn smtp_tls_identity_is_the_destination_and_untrusted_certificates_fail() {
    let (acceptor, _) = certificates();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let smtp_port = listener.local_addr().unwrap().port();
    let smtp = tokio::spawn(smtp_fixture(listener, acceptor.clone()));
    let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = proxy_listener.local_addr().unwrap().port();
    let proxy = tokio::spawn(proxy_fixture(proxy_listener, "http", smtp_port, acceptor));
    let config = ProxyConfig {
        mode: ProxyMode::Custom,
        url: format!("http://user:secret@localhost:{port}"),
    };
    let error = send_smtp(
        &config,
        "smtp.fixture.test",
        smtp_port,
        "sender",
        "secret",
        &message(),
        Duration::from_secs(2),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code, "smtp_tls_error");
    assert!(!error.retryable);
    assert_eq!(smtp.await.unwrap(), 0);
    proxy.abort();
}

#[tokio::test]
async fn a_trusted_certificate_for_the_proxy_is_not_a_valid_smtp_identity() {
    let (acceptor, tls) = certificates();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let smtp_port = listener.local_addr().unwrap().port();
    let smtp = tokio::spawn(smtp_fixture(listener, acceptor.clone()));
    let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = proxy_listener.local_addr().unwrap().port();
    let proxy = tokio::spawn(proxy_fixture(proxy_listener, "http", smtp_port, acceptor));
    let config = ProxyConfig {
        mode: ProxyMode::Custom,
        url: format!("http://user:secret@localhost:{port}"),
    };
    let error = tokio::time::timeout(
        Duration::from_secs(3),
        send_tunneled(
            &config,
            "wrong.fixture.test",
            smtp_port,
            "sender",
            "secret",
            &message(),
            &tls,
        ),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(error.code, "smtp_tls_error");
    assert_eq!(smtp.await.unwrap(), 0);
    proxy.abort();
}
#[tokio::test]
async fn a_stalled_proxy_consumes_only_the_attempt_budget() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let stalled = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
        std::future::pending::<()>().await;
    });
    let config = ProxyConfig {
        mode: ProxyMode::Custom,
        url: format!("socks5h://localhost:{port}"),
    };
    let error = send_smtp(
        &config,
        "smtp.fixture.test",
        465,
        "sender",
        "secret",
        &message(),
        Duration::from_millis(100),
    )
    .await
    .unwrap_err();
    assert_eq!(error.code, "delivery_timeout");
    assert!(error.retryable);
    stalled.abort();
}
