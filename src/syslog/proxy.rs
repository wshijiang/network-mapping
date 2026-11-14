//! SOCKS5 代理支持（RFC 1928 / RFC 1929）。
//!
//! syslog 转发跟随全局网络代理，但**仅当代理为 SOCKS5（socks5/socks5h）时使用**；
//! 其他类型（HTTP/HTTPS 等）或直连/未配置一律自动回退直连。
//! 代理作用于 TCP/TLS 目标；UDP 目标始终直连（SOCKS5 UDP ASSOCIATE 不在支持范围）。

use std::net::IpAddr;
use std::time::Duration;

use reqwest::Url;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::outbound_proxy::{ProxyConfig, ProxyMode};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Socks5Proxy {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    /// socks5h：目标域名由代理侧解析。
    pub remote_dns: bool,
}

/// 解析有效代理配置；非 SOCKS5 返回 None（调用方回退直连）。
pub fn from_proxy_config(config: &ProxyConfig) -> Option<Socks5Proxy> {
    match config.mode {
        ProxyMode::Custom => parse_socks5_url(&config.url),
        ProxyMode::System => environment_socks5(),
        ProxyMode::Direct => None,
    }
}

/// System 模式按环境变量代理判定：仅 SOCKS5 生效，其余回退直连。
fn environment_socks5() -> Option<Socks5Proxy> {
    for key in [
        "ALL_PROXY",
        "all_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
    ] {
        if let Ok(value) = std::env::var(key)
            && !value.trim().is_empty()
        {
            return parse_socks5_url(value.trim());
        }
    }
    None
}

pub fn parse_socks5_url(raw: &str) -> Option<Socks5Proxy> {
    let url = Url::parse(raw).ok()?;
    let remote_dns = match url.scheme() {
        "socks5" => false,
        "socks5h" => true,
        _ => return None,
    };
    let host = url.host_str()?.to_owned();
    if host.is_empty() {
        return None;
    }
    let username = (!url.username().is_empty()).then(|| {
        percent_encoding::percent_decode_str(url.username())
            .decode_utf8_lossy()
            .into_owned()
    });
    let password = url.password().map(|value| {
        percent_encoding::percent_decode_str(value)
            .decode_utf8_lossy()
            .into_owned()
    });
    Some(Socks5Proxy {
        host,
        port: url.port().unwrap_or(1080),
        username,
        password,
        remote_dns,
    })
}

/// 经 SOCKS5 代理建立到 host:port 的 TCP 连接（CONNECT 命令）。
pub async fn connect_tcp(
    proxy: &Socks5Proxy,
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<TcpStream, String> {
    tokio::time::timeout(timeout, async {
        let address = tokio::net::lookup_host((proxy.host.as_str(), proxy.port))
            .await
            .map_err(|error| format!("代理地址解析失败: {error}"))?
            .next()
            .ok_or_else(|| "代理地址解析结果为空".to_owned())?;
        let mut stream = TcpStream::connect(address)
            .await
            .map_err(|error| format!("代理连接失败: {error}"))?;
        let _ = stream.set_nodelay(true);
        handshake(&mut stream, proxy, host, port).await?;
        Ok(stream)
    })
    .await
    .map_err(|_| "SOCKS5 代理连接超时".to_owned())?
}

async fn handshake(
    stream: &mut TcpStream,
    proxy: &Socks5Proxy,
    host: &str,
    port: u16,
) -> Result<(), String> {
    // 方法协商：无认证，必要时提供用户名/密码认证。
    let mut methods = vec![0x00u8];
    if proxy.username.is_some() {
        methods.push(0x02);
    }
    let mut greeting = vec![0x05, methods.len() as u8];
    greeting.extend_from_slice(&methods);
    stream
        .write_all(&greeting)
        .await
        .map_err(|error| format!("SOCKS5 握手写入失败: {error}"))?;
    let mut choice = [0u8; 2];
    stream
        .read_exact(&mut choice)
        .await
        .map_err(|error| format!("SOCKS5 握手读取失败: {error}"))?;
    if choice[0] != 0x05 {
        return Err("SOCKS5 代理响应版本无效".to_owned());
    }
    match choice[1] {
        0x00 => {}
        0x02 => {
            let user = proxy.username.as_deref().unwrap_or("");
            let pass = proxy.password.as_deref().unwrap_or("");
            if user.len() > 255 || pass.len() > 255 {
                return Err("SOCKS5 代理凭据过长".to_owned());
            }
            let mut auth = vec![0x01, user.len() as u8];
            auth.extend_from_slice(user.as_bytes());
            auth.push(pass.len() as u8);
            auth.extend_from_slice(pass.as_bytes());
            stream
                .write_all(&auth)
                .await
                .map_err(|error| format!("SOCKS5 认证写入失败: {error}"))?;
            let mut auth_reply = [0u8; 2];
            stream
                .read_exact(&mut auth_reply)
                .await
                .map_err(|error| format!("SOCKS5 认证读取失败: {error}"))?;
            if auth_reply[1] != 0x00 {
                return Err("SOCKS5 代理认证失败".to_owned());
            }
        }
        0xFF => return Err("SOCKS5 代理无可接受的认证方法".to_owned()),
        _ => return Err("SOCKS5 代理选择了不支持的认证方法".to_owned()),
    }

    // CONNECT 请求。
    let mut request = vec![0x05, 0x01, 0x00];
    if proxy.remote_dns {
        if host.len() > 255 {
            return Err("目标域名过长".to_owned());
        }
        request.push(0x03);
        request.push(host.len() as u8);
        request.extend_from_slice(host.as_bytes());
    } else {
        let address = tokio::net::lookup_host((host, port))
            .await
            .map_err(|error| format!("目标地址解析失败: {error}"))?
            .next()
            .ok_or_else(|| "目标地址解析结果为空".to_owned())?;
        match address.ip() {
            IpAddr::V4(v4) => {
                request.push(0x01);
                request.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                request.push(0x04);
                request.extend_from_slice(&v6.octets());
            }
        }
    }
    request.extend_from_slice(&port.to_be_bytes());
    stream
        .write_all(&request)
        .await
        .map_err(|error| format!("SOCKS5 CONNECT 写入失败: {error}"))?;
    let mut head = [0u8; 4];
    stream
        .read_exact(&mut head)
        .await
        .map_err(|error| format!("SOCKS5 CONNECT 读取失败: {error}"))?;
    if head[0] != 0x05 {
        return Err("SOCKS5 代理响应版本无效".to_owned());
    }
    if head[1] != 0x00 {
        return Err(format!("SOCKS5 代理拒绝连接（代码 {}）", head[1]));
    }
    // 跳过绑定地址。
    match head[3] {
        0x01 => {
            let mut bound = [0u8; 6];
            stream.read_exact(&mut bound).await.ok();
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream
                .read_exact(&mut len)
                .await
                .map_err(|error| format!("SOCKS5 绑定地址读取失败: {error}"))?;
            let mut bound = vec![0u8; len[0] as usize + 2];
            stream
                .read_exact(&mut bound)
                .await
                .map_err(|error| format!("SOCKS5 绑定地址读取失败: {error}"))?;
        }
        0x04 => {
            let mut bound = [0u8; 18];
            stream.read_exact(&mut bound).await.ok();
        }
        _ => return Err("SOCKS5 代理绑定地址类型无效".to_owned()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn custom(url: &str) -> ProxyConfig {
        ProxyConfig {
            mode: ProxyMode::Custom,
            url: url.to_owned(),
        }
    }

    #[test]
    fn non_socks5_proxies_fall_back_to_direct() {
        assert!(from_proxy_config(&custom("http://127.0.0.1:7890")).is_none());
        assert!(from_proxy_config(&custom("https://proxy.example.com:443")).is_none());
        assert!(
            from_proxy_config(&ProxyConfig {
                mode: ProxyMode::Direct,
                url: String::new(),
            })
            .is_none()
        );
        assert!(parse_socks5_url("not a url").is_none());
    }

    #[test]
    fn socks5_urls_parse_with_defaults_and_credentials() {
        let proxy = from_proxy_config(&custom("socks5://10.0.0.9")).unwrap();
        assert_eq!(proxy.host, "10.0.0.9");
        assert_eq!(proxy.port, 1080);
        assert!(!proxy.remote_dns);
        assert!(proxy.username.is_none());

        let proxy = parse_socks5_url("socks5h://user:p%40ss@proxy.example.com:1081").unwrap();
        assert!(proxy.remote_dns);
        assert_eq!(proxy.port, 1081);
        assert_eq!(proxy.username.as_deref(), Some("user"));
        assert_eq!(proxy.password.as_deref(), Some("p@ss"));
    }

    /// 最小 SOCKS5 服务端：无认证 CONNECT，随后把字节原样转发到目标。
    async fn mock_socks5(listener: tokio::net::TcpListener, target: std::net::SocketAddr) {
        let (mut client, _) = listener.accept().await.unwrap();
        let mut greeting = [0u8; 2];
        client.read_exact(&mut greeting).await.unwrap();
        let mut methods = vec![0u8; greeting[1] as usize];
        client.read_exact(&mut methods).await.unwrap();
        client.write_all(&[0x05, 0x00]).await.unwrap();
        let mut head = [0u8; 4];
        client.read_exact(&mut head).await.unwrap();
        let address_len = match head[3] {
            0x01 => 4,
            0x04 => 16,
            0x03 => {
                let mut len = [0u8; 1];
                client.read_exact(&mut len).await.unwrap();
                len[0] as usize
            }
            _ => unreachable!(),
        };
        let mut rest = vec![0u8; address_len + 2];
        client.read_exact(&mut rest).await.unwrap();
        client
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut upstream = TcpStream::connect(target).await.unwrap();
        tokio::io::copy_bidirectional(&mut client, &mut upstream)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn connects_through_socks5_proxy_and_relays_data() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        tokio::spawn(mock_socks5(proxy_listener, echo_addr));
        tokio::spawn(async move {
            let (mut socket, _) = echo.accept().await.unwrap();
            let mut buffer = [0u8; 5];
            socket.read_exact(&mut buffer).await.unwrap();
            socket.write_all(&buffer).await.unwrap();
        });

        let proxy = Socks5Proxy {
            host: proxy_addr.ip().to_string(),
            port: proxy_addr.port(),
            username: None,
            password: None,
            remote_dns: false,
        };
        let mut stream = connect_tcp(
            &proxy,
            "127.0.0.1",
            echo_addr.port(),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        stream.write_all(b"hello").await.unwrap();
        let mut buffer = [0u8; 5];
        stream.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"hello");
    }

    #[tokio::test]
    async fn socks5h_sends_domain_to_proxy() {
        // 代理侧收到域名类型（0x03）即视为成功；用拒绝回复验证请求已完整到达。
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut client, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 2];
            client.read_exact(&mut greeting).await.unwrap();
            let mut methods = vec![0u8; greeting[1] as usize];
            client.read_exact(&mut methods).await.unwrap();
            client.write_all(&[0x05, 0x00]).await.unwrap();
            let mut head = [0u8; 4];
            client.read_exact(&mut head).await.unwrap();
            assert_eq!(head[3], 0x03, "socks5h 必须发送域名类型");
            let mut len = [0u8; 1];
            client.read_exact(&mut len).await.unwrap();
            let mut domain = vec![0u8; len[0] as usize];
            client.read_exact(&mut domain).await.unwrap();
            assert_eq!(domain, b"siem.example.com");
            // 拒绝连接（代码 2），验证客户端正确报错。
            client
                .write_all(&[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });
        let proxy = Socks5Proxy {
            host: addr.ip().to_string(),
            port: addr.port(),
            username: None,
            password: None,
            remote_dns: true,
        };
        let result = connect_tcp(&proxy, "siem.example.com", 514, Duration::from_secs(5)).await;
        assert!(result.is_err_and(|error| error.contains("代码 2")));
    }
}
