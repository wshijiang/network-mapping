//! SOCKS5 代理支持（RFC 1928 / RFC 1929）。
//!
//! syslog 转发跟随全局网络代理，但**仅当代理为 SOCKS5（socks5/socks5h）时使用**；
//! 其他类型（HTTP/HTTPS 等）或直连/未配置一律自动回退直连。
//! TCP/TLS 走 CONNECT；UDP 走 UDP ASSOCIATE（数据报经代理中继转发）。

use std::net::{IpAddr, SocketAddr};
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

/// 经 SOCKS5 代理建立 UDP 关联（UDP ASSOCIATE 命令）。
///
/// 返回代理侧 UDP 中继地址与目标数据报头；TCP 控制连接必须保持存活，
/// 关联存续期间代理才接受该客户端发往中继的数据报。
pub async fn connect_udp(
    proxy: &Socks5Proxy,
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<UdpAssociation, String> {
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
        negotiate(&mut stream, proxy).await?;
        // UDP ASSOCIATE：客户端源地址填 0.0.0.0:0，由代理接受任意来源。
        let request = [0x05u8, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        stream
            .write_all(&request)
            .await
            .map_err(|error| format!("SOCKS5 UDP ASSOCIATE 写入失败: {error}"))?;
        let mut head = [0u8; 4];
        stream
            .read_exact(&mut head)
            .await
            .map_err(|error| format!("SOCKS5 UDP ASSOCIATE 读取失败: {error}"))?;
        if head[0] != 0x05 {
            return Err("SOCKS5 代理响应版本无效".to_owned());
        }
        if head[1] != 0x00 {
            return Err(format!("SOCKS5 代理拒绝 UDP 关联（代码 {}）", head[1]));
        }
        let bound = read_bound_address(&mut stream, head[3]).await?;
        let bound_port = read_bound_port(&mut stream).await?;
        let relay_ip = match bound {
            BoundAddress::Ip(ip) if !ip.is_unspecified() => ip,
            BoundAddress::Domain(domain) => tokio::net::lookup_host((domain.as_str(), bound_port))
                .await
                .map_err(|error| format!("SOCKS5 中继地址解析失败: {error}"))?
                .next()
                .ok_or_else(|| "SOCKS5 中继地址解析结果为空".to_owned())?
                .ip(),
            // 部分代理返回 0.0.0.0：中继与控制连接同主机。
            _ => stream
                .peer_addr()
                .map_err(|error| format!("SOCKS5 代理地址无效: {error}"))?
                .ip(),
        };
        let mut header = vec![0x00, 0x00, 0x00]; // RSV(2) + FRAG(1)，不支持分片。
        header.extend(encode_target(proxy, host, port).await?);
        Ok(UdpAssociation {
            relay: SocketAddr::new(relay_ip, bound_port),
            header,
            control: stream,
        })
    })
    .await
    .map_err(|_| "SOCKS5 代理 UDP 关联超时".to_owned())?
}

/// 一次 UDP 关联：中继地址 + 固定目标的 SOCKS5 UDP 数据报头 + 保活控制连接。
pub struct UdpAssociation {
    pub relay: SocketAddr,
    pub header: Vec<u8>,
    pub control: TcpStream,
}

/// 目标地址编码（ATYP + DST.ADDR + DST.PORT）；socks5h 发域名，否则本地解析。
async fn encode_target(proxy: &Socks5Proxy, host: &str, port: u16) -> Result<Vec<u8>, String> {
    let mut request = Vec::new();
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
    Ok(request)
}

async fn handshake(
    stream: &mut TcpStream,
    proxy: &Socks5Proxy,
    host: &str,
    port: u16,
) -> Result<(), String> {
    negotiate(stream, proxy).await?;
    // CONNECT 请求。
    let mut request = vec![0x05, 0x01, 0x00];
    request.extend(encode_target(proxy, host, port).await?);
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
    let _ = read_bound_address(stream, head[3]).await?;
    let _ = read_bound_port(stream).await?;
    Ok(())
}

/// 方法协商：无认证，必要时提供用户名/密码认证。
async fn negotiate(stream: &mut TcpStream, proxy: &Socks5Proxy) -> Result<(), String> {
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
    Ok(())
}

enum BoundAddress {
    Ip(IpAddr),
    Domain(String),
}

/// 读取回复中的绑定地址（ATYP 已由调用方读取）。
async fn read_bound_address(stream: &mut TcpStream, atyp: u8) -> Result<BoundAddress, String> {
    match atyp {
        0x01 => {
            let mut octets = [0u8; 4];
            stream
                .read_exact(&mut octets)
                .await
                .map_err(|error| format!("SOCKS5 绑定地址读取失败: {error}"))?;
            Ok(BoundAddress::Ip(IpAddr::V4(octets.into())))
        }
        0x04 => {
            let mut octets = [0u8; 16];
            stream
                .read_exact(&mut octets)
                .await
                .map_err(|error| format!("SOCKS5 绑定地址读取失败: {error}"))?;
            Ok(BoundAddress::Ip(IpAddr::V6(octets.into())))
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream
                .read_exact(&mut len)
                .await
                .map_err(|error| format!("SOCKS5 绑定地址读取失败: {error}"))?;
            let mut domain = vec![0u8; len[0] as usize];
            stream
                .read_exact(&mut domain)
                .await
                .map_err(|error| format!("SOCKS5 绑定地址读取失败: {error}"))?;
            Ok(BoundAddress::Domain(
                String::from_utf8_lossy(&domain).into_owned(),
            ))
        }
        _ => Err("SOCKS5 代理绑定地址类型无效".to_owned()),
    }
}

async fn read_bound_port(stream: &mut TcpStream) -> Result<u16, String> {
    let mut port = [0u8; 2];
    stream
        .read_exact(&mut port)
        .await
        .map_err(|error| format!("SOCKS5 绑定地址读取失败: {error}"))?;
    Ok(u16::from_be_bytes(port))
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

    /// 最小 SOCKS5 服务端：接受 UDP ASSOCIATE，把中继数据报去掉请求头后转发到目标。
    async fn mock_udp_socks5(listener: tokio::net::TcpListener, target: std::net::SocketAddr) {
        use tokio::net::UdpSocket;
        let (mut client, _) = listener.accept().await.unwrap();
        let mut greeting = [0u8; 2];
        client.read_exact(&mut greeting).await.unwrap();
        let mut methods = vec![0u8; greeting[1] as usize];
        client.read_exact(&mut methods).await.unwrap();
        client.write_all(&[0x05, 0x00]).await.unwrap();
        let mut request = [0u8; 10];
        client.read_exact(&mut request).await.unwrap();
        assert_eq!(request[1], 0x03, "必须为 UDP ASSOCIATE 命令");
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_port = relay.local_addr().unwrap().port();
        let mut reply = vec![0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1];
        reply.extend_from_slice(&relay_port.to_be_bytes());
        client.write_all(&reply).await.unwrap();
        // 控制连接保持存活；中继一个数据报后校验目标地址并转发负载。
        let mut buffer = vec![0u8; 2048];
        let (size, _) = tokio::time::timeout(Duration::from_secs(5), relay.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        let datagram = &buffer[..size];
        assert_eq!(&datagram[..3], &[0x00, 0x00, 0x00], "RSV/FRAG 头");
        assert_eq!(datagram[3], 0x01, "目标为 IPv4 地址类型");
        assert_eq!(&datagram[4..8], &[127, 0, 0, 1]);
        assert_eq!(
            u16::from_be_bytes([datagram[8], datagram[9]]),
            target.port()
        );
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        upstream.send_to(&datagram[10..], target).await.unwrap();
        // 控制连接关闭前关联必须一直有效。
        drop(client);
    }

    #[tokio::test]
    async fn udp_target_reaches_server_through_socks5_associate() {
        use crate::syslog::config::{Protocol, TargetConfig, TlsOptions};
        use crate::syslog::transport;
        use tokio::net::UdpSocket;

        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_addr = receiver.local_addr().unwrap();
        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        tokio::spawn(mock_udp_socks5(proxy_listener, target_addr));

        let target = TargetConfig {
            id: uuid::Uuid::now_v7(),
            name: "udp-via-proxy".into(),
            host: "127.0.0.1".into(),
            port: target_addr.port(),
            protocol: Protocol::Udp,
            enabled: true,
            tls: TlsOptions::default(),
            sources: crate::syslog::config::default_sources(),
        };
        let proxy = Socks5Proxy {
            host: proxy_addr.ip().to_string(),
            port: proxy_addr.port(),
            username: None,
            password: None,
            remote_dns: false,
        };
        let mut connection = transport::connect(&target, Duration::from_secs(5), Some(&proxy))
            .await
            .unwrap();
        transport::send(&mut connection, b"hello udp", Duration::from_secs(5))
            .await
            .unwrap();
        let mut buffer = [0u8; 9];
        let (size, _) =
            tokio::time::timeout(Duration::from_secs(5), receiver.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(&buffer[..size], b"hello udp");
    }

    #[tokio::test]
    async fn udp_associate_socks5h_keeps_domain_in_datagram_header() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut client, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 2];
            client.read_exact(&mut greeting).await.unwrap();
            let mut methods = vec![0u8; greeting[1] as usize];
            client.read_exact(&mut methods).await.unwrap();
            client.write_all(&[0x05, 0x00]).await.unwrap();
            let mut request = [0u8; 10];
            client.read_exact(&mut request).await.unwrap();
            // 中继地址返回 0.0.0.0：客户端应回退到控制连接对端地址。
            client
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0x04, 0x38])
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
        });
        let proxy = Socks5Proxy {
            host: addr.ip().to_string(),
            port: addr.port(),
            username: None,
            password: None,
            remote_dns: true,
        };
        let association = connect_udp(&proxy, "siem.example.com", 514, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(association.relay.ip(), addr.ip());
        assert_eq!(association.relay.port(), 1080);
        let mut expected = vec![0x00, 0x00, 0x00, 0x03, b"siem.example.com".len() as u8];
        expected.extend_from_slice(b"siem.example.com");
        expected.extend_from_slice(&514u16.to_be_bytes());
        assert_eq!(association.header, expected);
    }
}
