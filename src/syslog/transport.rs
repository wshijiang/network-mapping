//! UDP / TCP / TLS 传输。TCP/TLS 使用 RFC 6587 octet-counting 帧。

use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};

use crate::syslog::config::{Protocol, TargetConfig};
use crate::syslog::format::frame_octet_counting;

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const SEND_TIMEOUT: Duration = Duration::from_secs(5);

pub enum Connection {
    Udp(UdpSocket),
    /// UDP 经 SOCKS5 UDP ASSOCIATE 中继；控制连接须保活。
    UdpSocks5 {
        socket: UdpSocket,
        header: Vec<u8>,
        _control: TcpStream,
    },
    Tcp(TcpStream),
    Tls(tokio_native_tls::TlsStream<TcpStream>),
}

/// 建立到目标的连接。SOCKS5 代理对 TCP/TLS 走 CONNECT、对 UDP 走 UDP ASSOCIATE；
/// 非 SOCKS5 代理由调用方解析为 None，即自动回退直连。
pub async fn connect(
    target: &TargetConfig,
    timeout: Duration,
    proxy: Option<&crate::syslog::proxy::Socks5Proxy>,
) -> Result<Connection, String> {
    match target.protocol {
        Protocol::Udp => {
            if let Some(proxy) = proxy {
                let association =
                    crate::syslog::proxy::connect_udp(proxy, &target.host, target.port, timeout)
                        .await
                        .map_err(|error| sanitize_error(&error))?;
                let socket = if association.relay.is_ipv4() {
                    UdpSocket::bind("0.0.0.0:0").await
                } else {
                    UdpSocket::bind("[::]:0").await
                }
                .map_err(|error| sanitize_error(&format!("UDP 绑定失败: {error}")))?;
                socket
                    .connect(association.relay)
                    .await
                    .map_err(|error| sanitize_error(&format!("UDP 连接失败: {error}")))?;
                return Ok(Connection::UdpSocks5 {
                    socket,
                    header: association.header,
                    _control: association.control,
                });
            }
            let address = tokio::time::timeout(
                timeout,
                tokio::net::lookup_host((target.host.as_str(), target.port)),
            )
            .await
            .map_err(|_| "DNS 解析超时".to_owned())?
            .map_err(|error| sanitize_error(&format!("地址解析失败: {error}")))?
            .next()
            .ok_or_else(|| "地址解析结果为空".to_owned())?;
            let socket = if address.is_ipv4() {
                UdpSocket::bind("0.0.0.0:0").await
            } else {
                UdpSocket::bind("[::]:0").await
            }
            .map_err(|error| sanitize_error(&format!("UDP 绑定失败: {error}")))?;
            socket
                .connect(address)
                .await
                .map_err(|error| sanitize_error(&format!("UDP 连接失败: {error}")))?;
            Ok(Connection::Udp(socket))
        }
        Protocol::Tcp => Ok(Connection::Tcp(tcp_stream(target, timeout, proxy).await?)),
        Protocol::Tls => {
            let stream = tcp_stream(target, timeout, proxy).await?;
            let connector = tokio_native_tls::TlsConnector::from(tls_connector(target)?);
            let domain = if target.tls.server_name.is_empty() {
                target.host.as_str()
            } else {
                target.tls.server_name.as_str()
            };
            let tls = tokio::time::timeout(timeout, connector.connect(domain, stream))
                .await
                .map_err(|_| "TLS 握手超时".to_owned())?
                .map_err(|error| sanitize_error(&format!("TLS 握手失败: {error}")))?;
            Ok(Connection::Tls(tls))
        }
    }
}

async fn tcp_stream(
    target: &TargetConfig,
    timeout: Duration,
    proxy: Option<&crate::syslog::proxy::Socks5Proxy>,
) -> Result<TcpStream, String> {
    if let Some(proxy) = proxy {
        return crate::syslog::proxy::connect_tcp(proxy, &target.host, target.port, timeout)
            .await
            .map_err(|error| sanitize_error(&error));
    }
    let address = tokio::time::timeout(
        timeout,
        tokio::net::lookup_host((target.host.as_str(), target.port)),
    )
    .await
    .map_err(|_| "DNS 解析超时".to_owned())?
    .map_err(|error| sanitize_error(&format!("地址解析失败: {error}")))?
    .next()
    .ok_or_else(|| "地址解析结果为空".to_owned())?;
    let stream = tokio::time::timeout(timeout, TcpStream::connect(address))
        .await
        .map_err(|_| "TCP 连接超时".to_owned())?
        .map_err(|error| sanitize_error(&format!("TCP 连接失败: {error}")))?;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

fn tls_connector(target: &TargetConfig) -> Result<native_tls::TlsConnector, String> {
    let mut builder = native_tls::TlsConnector::builder();
    if !target.tls.verify {
        builder.danger_accept_invalid_certs(true);
        builder.danger_accept_invalid_hostnames(true);
    }
    if !target.tls.ca_file.is_empty() {
        let bytes = std::fs::read(&target.tls.ca_file)
            .map_err(|error| sanitize_error(&format!("读取 CA 文件失败: {error}")))?;
        let certificate = native_tls::Certificate::from_pem(&bytes)
            .or_else(|_| native_tls::Certificate::from_der(&bytes))
            .map_err(|error| sanitize_error(&format!("CA 证书无效: {error}")))?;
        builder.add_root_certificate(certificate);
    }
    builder
        .build()
        .map_err(|error| sanitize_error(&format!("TLS 客户端构建失败: {error}")))
}

/// 发送一条已编码的 RFC 5424 消息；TCP/TLS 自动加 octet-counting 帧。
pub async fn send(
    connection: &mut Connection,
    payload: &[u8],
    timeout: Duration,
) -> Result<(), String> {
    match connection {
        Connection::Udp(socket) => {
            let sent = tokio::time::timeout(timeout, socket.send(payload))
                .await
                .map_err(|_| "UDP 发送超时".to_owned())?
                .map_err(|error| sanitize_error(&format!("UDP 发送失败: {error}")))?;
            if sent != payload.len() {
                return Err("UDP 报文部分发送".to_owned());
            }
            Ok(())
        }
        Connection::UdpSocks5 { socket, header, .. } => {
            // SOCKS5 UDP 请求头 + RFC 5424 负载，发往代理中继。
            let mut datagram = Vec::with_capacity(header.len() + payload.len());
            datagram.extend_from_slice(header);
            datagram.extend_from_slice(payload);
            let sent = tokio::time::timeout(timeout, socket.send(&datagram))
                .await
                .map_err(|_| "UDP 发送超时".to_owned())?
                .map_err(|error| sanitize_error(&format!("UDP 发送失败: {error}")))?;
            if sent != datagram.len() {
                return Err("UDP 报文部分发送".to_owned());
            }
            Ok(())
        }
        Connection::Tcp(stream) => {
            let framed = frame_octet_counting(payload);
            tokio::time::timeout(timeout, stream.write_all(&framed))
                .await
                .map_err(|_| "TCP 写入超时".to_owned())?
                .map_err(|error| sanitize_error(&format!("TCP 写入失败: {error}")))
        }
        Connection::Tls(stream) => {
            let framed = frame_octet_counting(payload);
            tokio::time::timeout(timeout, stream.write_all(&framed))
                .await
                .map_err(|_| "TLS 写入超时".to_owned())?
                .map_err(|error| sanitize_error(&format!("TLS 写入失败: {error}")))
        }
    }
}

/// 错误信息入库/展示前截断并去除控制字符。
pub fn sanitize_error(error: &str) -> String {
    error
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(200)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syslog::config::{SyslogConfig, TlsOptions};
    use crate::syslog::format::{Message, Severity, UDP_MAX_BYTES, render};
    use tokio::io::AsyncReadExt;
    use uuid::Uuid;

    fn target(protocol: Protocol, port: u16) -> TargetConfig {
        TargetConfig {
            id: Uuid::now_v7(),
            name: "loopback".into(),
            host: "127.0.0.1".into(),
            port,
            protocol,
            enabled: true,
            tls: TlsOptions::default(),
            sources: crate::syslog::config::default_sources(),
        }
    }

    fn payload() -> Vec<u8> {
        render(
            &Message {
                timestamp: chrono::Utc::now(),
                severity: Severity::Info,
                msgid: "Test",
                sd: vec![],
                text: "loopback test".into(),
            },
            16,
            "network-mapping",
            UDP_MAX_BYTES,
        )
    }

    #[tokio::test]
    async fn udp_loopback_receives_rfc5424_datagram() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = receiver.local_addr().unwrap().port();
        let mut connection = connect(&target(Protocol::Udp, port), CONNECT_TIMEOUT, None)
            .await
            .unwrap();
        let message = payload();
        send(&mut connection, &message, SEND_TIMEOUT).await.unwrap();
        let mut buffer = vec![0u8; 2048];
        let (size, _) =
            tokio::time::timeout(Duration::from_secs(2), receiver.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(&buffer[..size], message.as_slice());
        assert!(String::from_utf8_lossy(&buffer[..size]).starts_with("<134>1 "));
    }

    #[tokio::test]
    async fn tcp_loopback_receives_octet_counted_frame() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut connection = connect(&target(Protocol::Tcp, port), CONNECT_TIMEOUT, None)
            .await
            .unwrap();
        let message = payload();
        send(&mut connection, &message, SEND_TIMEOUT).await.unwrap();
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buffer = vec![0u8; 4096];
        let size = tokio::time::timeout(Duration::from_secs(2), socket.read(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        let expected = frame_octet_counting(&message);
        assert_eq!(&buffer[..size], expected.as_slice());
    }

    #[tokio::test]
    async fn connect_failure_is_reported_not_panicked() {
        // 127.0.0.1:1 几乎必然拒绝连接。
        let result = connect(&target(Protocol::Tcp, 1), Duration::from_secs(2), None).await;
        assert!(result.is_err());
    }

    #[test]
    fn default_config_has_no_targets() {
        assert!(SyslogConfig::default().targets.is_empty());
    }
}
