//! Per-channel proxy transport. No process-wide environment changes or direct fallback.
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    transport::smtp::{
        authentication::{Credentials, Mechanism},
        client::{AsyncSmtpConnection, AsyncTokioStream},
        extension::ClientId,
    },
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::{fmt, net::IpAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProxyMode {
    #[default]
    System,
    Direct,
    Custom,
}
impl ProxyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Direct => "direct",
            Self::Custom => "custom",
        }
    }
}
impl std::str::FromStr for ProxyMode {
    type Err = ProxyError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "system" => Ok(Self::System),
            "direct" => Ok(Self::Direct),
            "custom" => Ok(Self::Custom),
            _ => Err(ProxyError::permanent("proxy_invalid")),
        }
    }
}

#[derive(Clone, Default, Deserialize)]
pub struct ProxyConfig {
    #[serde(default)]
    pub mode: ProxyMode,
    #[serde(default)]
    pub url: String,
}
impl fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyConfig")
            .field("mode", &self.mode)
            .field("credential", &"[REDACTED]")
            .finish()
    }
}
#[derive(Clone, Copy, Debug)]
pub struct ProxyError {
    pub code: &'static str,
    pub retryable: bool,
    pub(crate) mail_kind: Option<crate::admin::MailFailureKind>,
}
impl ProxyError {
    fn permanent(code: &'static str) -> Self {
        Self {
            code,
            retryable: false,
            mail_kind: None,
        }
    }
    fn transient(code: &'static str) -> Self {
        Self {
            code,
            retryable: true,
            mail_kind: None,
        }
    }
}
impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code)
    }
}
impl std::error::Error for ProxyError {}
fn network(_: std::io::Error) -> ProxyError {
    ProxyError::transient("proxy_connection_failed")
}

pub fn validate_url(value: &str) -> Result<Url, ProxyError> {
    if value.len() > 2048 || value.trim() != value || value.chars().any(char::is_control) {
        return Err(ProxyError::permanent("proxy_invalid"));
    }
    let url = Url::parse(value).map_err(|_| ProxyError::permanent("proxy_invalid"))?;
    if !matches!(url.scheme(), "http" | "https" | "socks5" | "socks5h")
        || url.host_str().is_none()
        || url.port_or_known_default().is_none_or(|p| p == 0)
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ProxyError::permanent("proxy_invalid"));
    }
    if url.scheme().starts_with("socks")
        && (!url.username().is_empty() || url.password().is_some())
        && (url.username().is_empty() || url.password().is_none_or(str::is_empty))
    {
        return Err(ProxyError::permanent("proxy_invalid"));
    }
    for value in [url.username(), url.password().unwrap_or_default()] {
        let decoded = percent_encoding::percent_decode_str(value)
            .decode_utf8()
            .map_err(|_| ProxyError::permanent("proxy_invalid"))?;
        if decoded.len() > 255 || decoded.chars().any(char::is_control) {
            return Err(ProxyError::permanent("proxy_invalid"));
        }
    }
    Ok(url)
}
pub fn endpoint(value: &str) -> Result<String, ProxyError> {
    let mut url = validate_url(value)?;
    url.set_password(None)
        .map_err(|_| ProxyError::permanent("proxy_invalid"))?;
    url.set_username("")
        .map_err(|_| ProxyError::permanent("proxy_invalid"))?;
    Ok(url.to_string())
}
impl ProxyConfig {
    pub fn http_client(&self) -> Result<reqwest::Client, ProxyError> {
        let mut builder = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10));
        match self.mode {
            ProxyMode::System => {}
            ProxyMode::Direct => builder = builder.no_proxy(),
            ProxyMode::Custom => {
                let url = validate_url(&self.url)?;
                builder = builder.proxy(
                    reqwest::Proxy::all(url).map_err(|_| ProxyError::permanent("proxy_invalid"))?,
                );
            }
        }
        builder
            .build()
            .map_err(|_| ProxyError::permanent("proxy_invalid"))
    }
}
type Stream = Box<dyn AsyncTokioStream>;
#[derive(Debug)]
struct VerifiedTls(tokio_native_tls::TlsStream<Stream>);
impl tokio::io::AsyncRead for VerifiedTls {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}
impl tokio::io::AsyncWrite for VerifiedTls {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}
impl AsyncTokioStream for VerifiedTls {
    fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.0.get_ref().get_ref().get_ref().peer_addr()
    }
}

fn credentials(url: &Url) -> Result<(String, String), ProxyError> {
    let decode = |v: &str| {
        percent_encoding::percent_decode_str(v)
            .decode_utf8()
            .map(|s| s.into_owned())
            .map_err(|_| ProxyError::permanent("proxy_invalid"))
    };
    Ok((
        decode(url.username())?,
        decode(url.password().unwrap_or_default())?,
    ))
}
fn tls_connector() -> Result<tokio_native_tls::TlsConnector, ProxyError> {
    native_tls::TlsConnector::builder()
        .build()
        .map(tokio_native_tls::TlsConnector::from)
        .map_err(|_| ProxyError::permanent("smtp_tls_error"))
}
async fn tunnel(
    proxy: &ProxyConfig,
    host: &str,
    port: u16,
    tls: &tokio_native_tls::TlsConnector,
) -> Result<Stream, ProxyError> {
    if host.is_empty()
        || host.len() > 253
        || port == 0
        || (!host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b))
            && host.parse::<IpAddr>().is_err())
    {
        return Err(ProxyError::permanent("invalid_destination"));
    }
    let url = validate_url(&proxy.url)?;
    let proxy_host = url.host_str().unwrap().trim_matches(['[', ']']);
    let stream = TcpStream::connect((proxy_host, url.port_or_known_default().unwrap()))
        .await
        .map_err(network)?;
    let mut stream: Stream = Box::new(stream);
    if url.scheme() == "https" {
        stream = Box::new(VerifiedTls(
            tls.connect(proxy_host, stream)
                .await
                .map_err(|_| ProxyError::permanent("proxy_tls_error"))?,
        ));
    }
    if matches!(url.scheme(), "http" | "https") {
        let authority = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        let (user, password) = credentials(&url)?;
        let authorization = if !url.username().is_empty() || url.password().is_some() {
            format!(
                "Proxy-Authorization: Basic {}\r\n",
                openssl::base64::encode_block(format!("{user}:{password}").as_bytes())
            )
        } else {
            String::new()
        };
        let request =
            format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n{authorization}\r\n");
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(network)?;
        let mut header = vec![];
        // Do not consume bytes belonging to the tunneled TLS stream.
        while !header.ends_with(b"\r\n\r\n") {
            if header.len() >= 8192 {
                return Err(ProxyError::permanent("proxy_invalid_response"));
            }
            header.push(stream.read_u8().await.map_err(network)?);
        }
        let line = std::str::from_utf8(&header)
            .map_err(|_| ProxyError::permanent("proxy_invalid_response"))?
            .lines()
            .next()
            .unwrap_or_default();
        let mut parts = line.split_whitespace();
        let version = parts.next().unwrap_or_default();
        let status = parts.next().unwrap_or_default();
        if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
            return Err(ProxyError::permanent("proxy_invalid_response"));
        }
        if status == "407" {
            return Err(ProxyError::permanent("proxy_authentication_failed"));
        }
        if status != "200" {
            return Err(ProxyError::transient("proxy_connect_rejected"));
        }
    } else {
        let (user, password) = credentials(&url)?;
        let auth = !url.username().is_empty() || url.password().is_some();
        stream
            .write_all(&[5, 1, if auth { 2 } else { 0 }])
            .await
            .map_err(network)?;
        let mut reply = [0; 2];
        stream.read_exact(&mut reply).await.map_err(network)?;
        if reply != [5, if auth { 2 } else { 0 }] {
            return Err(ProxyError::permanent("proxy_authentication_failed"));
        }
        if auth {
            let mut request = vec![1, user.len() as u8];
            request.extend_from_slice(user.as_bytes());
            request.push(password.len() as u8);
            request.extend_from_slice(password.as_bytes());
            stream.write_all(&request).await.map_err(network)?;
            stream.read_exact(&mut reply).await.map_err(network)?;
            if reply != [1, 0] {
                return Err(ProxyError::permanent("proxy_authentication_failed"));
            }
        }
        let address = if url.scheme() == "socks5" {
            Some(
                tokio::net::lookup_host((host, port))
                    .await
                    .map_err(network)?
                    .next()
                    .ok_or_else(|| ProxyError::transient("proxy_dns_failed"))?
                    .ip(),
            )
        } else {
            host.parse::<IpAddr>().ok()
        };
        let mut request = vec![5, 1, 0];
        match address {
            Some(IpAddr::V4(ip)) => {
                request.push(1);
                request.extend_from_slice(&ip.octets());
            }
            Some(IpAddr::V6(ip)) => {
                request.push(4);
                request.extend_from_slice(&ip.octets());
            }
            None => {
                request.push(3);
                request.push(host.len() as u8);
                request.extend_from_slice(host.as_bytes());
            }
        }
        request.extend_from_slice(&port.to_be_bytes());
        stream.write_all(&request).await.map_err(network)?;
        let mut header = [0; 4];
        stream.read_exact(&mut header).await.map_err(network)?;
        if header[0] != 5 || header[2] != 0 {
            return Err(ProxyError::permanent("proxy_invalid_response"));
        }
        if header[1] != 0 {
            return Err(ProxyError::transient("proxy_connect_rejected"));
        }
        let count = match header[3] {
            1 => 4,
            4 => 16,
            3 => usize::from(stream.read_u8().await.map_err(network)?),
            _ => return Err(ProxyError::permanent("proxy_invalid_response")),
        };
        let mut remaining = vec![0; count + 2];
        stream.read_exact(&mut remaining).await.map_err(network)?;
    }
    Ok(stream)
}
fn smtp_error(error: lettre::transport::smtp::Error) -> ProxyError {
    let kind = crate::admin::classify_smtp_error(&error);
    let code = if error.is_tls() {
        "smtp_tls_error"
    } else if error.is_permanent() {
        "smtp_permanent_error"
    } else if error.is_client() {
        "smtp_client_error"
    } else {
        "smtp_delivery_failed"
    };
    ProxyError {
        code,
        retryable: kind.is_retryable(),
        mail_kind: Some(kind),
    }
}

pub async fn send_smtp(
    proxy: &ProxyConfig,
    host: &str,
    port: u16,
    username: &str,
    password: &str,
    message: &Message,
    budget: Duration,
) -> Result<(), ProxyError> {
    if proxy.mode != ProxyMode::Custom {
        let transport = AsyncSmtpTransport::<Tokio1Executor>::relay(host)
            .map_err(smtp_error)?
            .port(port)
            .credentials(Credentials::new(username.into(), password.into()))
            .timeout(Some(budget))
            .build();
        return tokio::time::timeout(budget, transport.send(message.clone()))
            .await
            .map_err(|_| ProxyError::transient("delivery_timeout"))?
            .map(|_| ())
            .map_err(smtp_error);
    }
    let tls = tls_connector()?;
    tokio::time::timeout(
        budget,
        send_tunneled(proxy, host, port, username, password, message, &tls),
    )
    .await
    .map_err(|_| ProxyError::transient("delivery_timeout"))?
}
async fn send_tunneled(
    proxy: &ProxyConfig,
    host: &str,
    port: u16,
    username: &str,
    password: &str,
    message: &Message,
    tls: &tokio_native_tls::TlsConnector,
) -> Result<(), ProxyError> {
    let stream = tunnel(proxy, host, port, tls).await?;
    // TLS identity is the final SMTP host, independently of proxy identity.
    let encrypted = tls
        .connect(host, stream)
        .await
        .map_err(|_| ProxyError::permanent("smtp_tls_error"))?;
    let mut connection = AsyncSmtpConnection::connect_with_transport(
        Box::new(VerifiedTls(encrypted)),
        &ClientId::default(),
    )
    .await
    .map_err(smtp_error)?;
    connection
        .auth(
            &[Mechanism::Plain, Mechanism::Login],
            &Credentials::new(username.into(), password.into()),
        )
        .await
        .map_err(smtp_error)?;
    connection
        .send(message.envelope(), &message.formatted())
        .await
        .map_err(smtp_error)?;
    let _ = connection.quit().await;
    Ok(())
}

#[cfg(test)]
mod tests;
