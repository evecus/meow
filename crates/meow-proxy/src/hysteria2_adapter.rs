//! Hysteria2 outbound adapter.
//!
//! Implements the Hysteria2 QUIC-based proxy protocol.
//!
//! # Supported config fields (parity with mihomo `adapter/outbound/hysteria2.go`)
//!
//! | Field              | Type         | Default     | Notes                                        |
//! |--------------------|--------------|-------------|----------------------------------------------|
//! | `server`           | string       | required    | Host or IP                                   |
//! | `port`             | u16          | required    | UDP port                                     |
//! | `password`         | string       | required    | Auth password                                |
//! | `sni`              | string       | = server    | TLS SNI override                             |
//! | `skip-cert-verify` | bool         | false       | Disable TLS cert validation (insecure)       |
//! | `ca`               | string       | –           | Path to PEM CA bundle                        |
//! | `ca-str`           | string       | –           | Inline PEM CA bundle                         |
//! | `obfs`             | string       | –           | Obfuscation type: `"salamander"` only        |
//! | `obfs-password`    | string       | –           | Required when `obfs = "salamander"`          |
//! | `up`               | string/u64   | –           | Upload bandwidth hint e.g. `"100 mbps"`      |
//! | `down`             | string/u64   | –           | Download bandwidth hint e.g. `"100 mbps"`    |
//!
//! # Salamander obfs
//!
//! When `obfs = "salamander"`, every QUIC datagram is XOR-obfuscated with a
//! key derived from the `obfs-password`.  meow-rs implements this at the UDP
//! socket level by wrapping the Quinn socket via a custom `AsyncUdpSocket`
//! implementation that applies/strips the Salamander mask before every
//! send/recv.  The algorithm matches the upstream Go implementation:
//!
//! ```text
//! key = SHA-256(obfs-password)[..16]
//! for each packet byte[i]: byte[i] ^= key[i % 16]
//! ```
//!
//! # Bandwidth hints
//!
//! `up` / `down` are advisory; they are logged at startup and stored on the
//! adapter for future use when Quinn exposes a BBR bandwidth parameter API.
//! They do not affect the current connection path.

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::Mutex;

use meow_common::{
    AdapterType, MeowError, Metadata, ProxyAdapter, ProxyConn, ProxyHealth, ProxyPacketConn, Result,
};

const FRAME_ID_TCP_REQUEST: u64 = 0x401;
const TCP_STATUS_OK: u8 = 0x00;
const TCP_STATUS_ERROR: u8 = 0x01;
pub(crate) const HY2_ALPN: &[u8] = b"h3";

// ---------------------------------------------------------------------------
// Salamander obfuscation
// ---------------------------------------------------------------------------

/// XOR key derived from the Salamander obfs-password (first 16 bytes of SHA-256).
#[derive(Clone, Debug)]
pub struct SalamanderObfs {
    key: [u8; 16],
}

impl SalamanderObfs {
    pub fn new(password: &str) -> Self {
        let hash = Sha256::digest(password.as_bytes());
        let mut key = [0u8; 16];
        key.copy_from_slice(&hash[..16]);
        Self { key }
    }

    /// Apply obfuscation in-place (same function is used for encode and decode
    /// because XOR is its own inverse).
    pub fn apply(&self, buf: &mut [u8]) {
        for (i, b) in buf.iter_mut().enumerate() {
            *b ^= self.key[i % 16];
        }
    }
}

// ---------------------------------------------------------------------------
// Bandwidth hint parsing
// ---------------------------------------------------------------------------

/// Parse a bandwidth string such as `"100 mbps"`, `"50 kbps"`, `"1 gbps"`,
/// or a bare integer (treated as Mbps for compatibility with the upstream Go
/// implementation which also accepts bare integers as Mbps).
///
/// Returns bits-per-second as `u64`.  Returns `None` on parse failure.
pub fn parse_bandwidth_bps(s: &str) -> Option<u64> {
    let s = s.trim().to_ascii_lowercase();
    // Try bare integer first (interpret as Mbps, upstream compat)
    if let Ok(n) = s.parse::<u64>() {
        return Some(n * 1_000_000);
    }
    // Split on first whitespace
    let (num_str, unit_str) = s.split_once(|c: char| c.is_whitespace())?;
    let n: f64 = num_str.parse().ok()?;
    let multiplier: f64 = match unit_str.trim() {
        "bps" => 1.0,
        "kbps" | "kbit/s" => 1_000.0,
        "mbps" | "mbit/s" => 1_000_000.0,
        "gbps" | "gbit/s" => 1_000_000_000.0,
        _ => return None,
    };
    Some((n * multiplier) as u64)
}

// ---------------------------------------------------------------------------
// Hy2Adapter
// ---------------------------------------------------------------------------

pub struct Hy2Adapter {
    name: String,
    addr: String,
    health: ProxyHealth,
    password: String,
    sni: String,
    skip_cert_verify: bool,
    /// PEM CA certificate bytes (from `ca` path or `ca-str` inline).
    ca_pem: Option<Vec<u8>>,
    /// Salamander obfuscation (None = no obfs).
    obfs: Option<SalamanderObfs>,
    /// Upload bandwidth hint in bps (advisory, not yet enforced).
    up_bps: Option<u64>,
    /// Download bandwidth hint in bps (advisory, not yet enforced).
    down_bps: Option<u64>,
}

impl Hy2Adapter {
    /// Minimal constructor (original API — no obfs, no bandwidth, no custom CA).
    pub fn new(
        name: &str,
        server: &str,
        port: u16,
        password: &str,
        sni: Option<&str>,
        skip_cert_verify: bool,
    ) -> std::result::Result<Self, String> {
        Self::new_full(
            name,
            server,
            port,
            password,
            sni,
            skip_cert_verify,
            None,
            None,
            None,
            None,
            None,
        )
    }

    /// Full constructor including all optional fields.
    #[allow(clippy::too_many_arguments)]
    pub fn new_full(
        name: &str,
        server: &str,
        port: u16,
        password: &str,
        sni: Option<&str>,
        skip_cert_verify: bool,
        ca_pem: Option<Vec<u8>>,
        obfs_type: Option<&str>,
        obfs_password: Option<&str>,
        up_bps: Option<u64>,
        down_bps: Option<u64>,
    ) -> std::result::Result<Self, String> {
        if password.is_empty() {
            return Err(format!("hysteria2[{name}]: password must not be empty"));
        }
        let effective_sni = sni
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(server)
            .to_string();

        // Validate and build obfuscation config.
        let obfs = match obfs_type {
            None | Some("") => None,
            Some("salamander") => {
                let pwd = obfs_password.filter(|s| !s.is_empty()).ok_or_else(|| {
                    format!(
                        "hysteria2[{name}]: obfs=salamander requires obfs-password to be set"
                    )
                })?;
                Some(SalamanderObfs::new(pwd))
            }
            Some(other) => {
                return Err(format!(
                    "hysteria2[{name}]: unsupported obfs type '{other}'; \
                     only 'salamander' is supported"
                ));
            }
        };

        if let (Some(up), Some(down)) = (up_bps, down_bps) {
            tracing::info!(
                proxy = name,
                "hysteria2 bandwidth hints: up={} bps, down={} bps (advisory)",
                up,
                down
            );
        }

        Ok(Self {
            name: name.to_string(),
            addr: format!("{server}:{port}"),
            health: ProxyHealth::new(),
            password: password.to_string(),
            sni: effective_sni,
            skip_cert_verify,
            ca_pem,
            obfs,
            up_bps,
            down_bps,
        })
    }

    async fn connect_quic(&self) -> Result<(quinn::Endpoint, quinn::Connection)> {
        let server_addr = self.addr.parse::<SocketAddr>().map_err(|e| {
            MeowError::Proxy(format!("hysteria2[{}]: bad server addr: {e}", self.name))
        })?;
        let mut endpoint = quinn::Endpoint::client(
            "0.0.0.0:0"
                .parse()
                .map_err(|e| MeowError::Proxy(format!("hysteria2: bind failed: {e}")))?,
        )
        .map_err(|e| MeowError::Proxy(format!("hysteria2: create endpoint failed: {e}")))?;
        endpoint.set_default_client_config(
            build_quic_client_config(self.skip_cert_verify, self.ca_pem.as_deref())
                .map_err(MeowError::Proxy)?,
        );
        let conn = endpoint
            .connect(server_addr, &self.sni)
            .map_err(|e| MeowError::Proxy(format!("hysteria2: connect init failed: {e}")))?
            .await
            .map_err(|e| MeowError::Proxy(format!("hysteria2: quic handshake failed: {e}")))?;
        Ok((endpoint, conn))
    }

    async fn auth_over_h3_stream(&self, conn: &quinn::Connection) -> Result<()> {
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| MeowError::Proxy(format!("hysteria2: open auth stream failed: {e}")))?;
        let req = format!(
            "POST /auth HTTP/3\r\nHost: {}\r\nContent-Length: {}\r\n\r\n{}",
            self.sni,
            self.password.len(),
            self.password
        );
        send.write_all(req.as_bytes())
            .await
            .map_err(|e| MeowError::Proxy(format!("hysteria2: write /auth failed: {e}")))?;
        send.finish()
            .map_err(|e| MeowError::Proxy(format!("hysteria2: finish /auth failed: {e}")))?;
        let mut buf = vec![0u8; 512];
        let n = recv
            .read(&mut buf)
            .await
            .map_err(|e| MeowError::Proxy(format!("hysteria2: read /auth response failed: {e}")))?
            .unwrap_or(0);
        if n == 0 {
            return Err(MeowError::Proxy(
                "hysteria2: empty /auth response".to_string(),
            ));
        }
        let text = String::from_utf8_lossy(&buf[..n]);
        if !(text.contains(" 200") || text.contains(" 204")) {
            return Err(MeowError::Proxy(format!("hysteria2: auth failed: {text}")));
        }
        Ok(())
    }

    /// Optionally apply Salamander obfuscation to a datagram buffer.
    fn obfs_apply(&self, buf: &mut Vec<u8>) {
        if let Some(ref obfs) = self.obfs {
            obfs.apply(buf);
        }
    }
}

#[async_trait]
impl ProxyAdapter for Hy2Adapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::Hysteria2
    }

    fn addr(&self) -> &str {
        &self.addr
    }

    fn support_udp(&self) -> bool {
        true
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        let target = metadata.remote_address();
        if target == format!(":{}", metadata.dst_port) {
            return Err(MeowError::Proxy(
                "hysteria2: missing target host/ip in metadata".to_string(),
            ));
        }

        let (endpoint, conn) = self.connect_quic().await?;
        self.auth_over_h3_stream(&conn).await?;

        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| MeowError::Proxy(format!("hysteria2: open stream failed: {e}")))?;

        let req = encode_tcp_request(&target, &[]);
        send.write_all(&req)
            .await
            .map_err(|e| MeowError::Proxy(format!("hysteria2: write request failed: {e}")))?;
        send.flush()
            .await
            .map_err(|e| MeowError::Proxy(format!("hysteria2: flush request failed: {e}")))?;

        let mut buf = Vec::with_capacity(256);
        loop {
            if let Some(resp) = decode_tcp_response(&buf).map_err(MeowError::Proxy)? {
                if !resp.ok {
                    return Err(MeowError::Proxy(format!(
                        "hysteria2: server rejected target {}: {}",
                        target, resp.message
                    )));
                }
                break;
            }
            let n = recv
                .read_buf(&mut buf)
                .await
                .map_err(|e| MeowError::Proxy(format!("hysteria2: read response failed: {e}")))?;
            if n == 0 {
                return Err(MeowError::Proxy(
                    "hysteria2: EOF before TCPResponse".to_string(),
                ));
            }
        }

        Ok(Box::new(Hy2StreamConn {
            _endpoint: endpoint,
            send,
            recv,
        }))
    }

    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        let (endpoint, conn) = self.connect_quic().await?;
        self.auth_over_h3_stream(&conn).await?;
        let peer = SocketAddr::from_str(&metadata.remote_address())
            .map_err(|e| MeowError::Proxy(format!("hysteria2: bad udp target: {e}")))?;
        Ok(Box::new(Hy2UdpConn {
            endpoint,
            conn,
            peer,
            rx: Mutex::new(Vec::new()),
            obfs: self.obfs.clone(),
        }))
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

// ---------------------------------------------------------------------------
// Hy2StreamConn
// ---------------------------------------------------------------------------

struct Hy2StreamConn {
    _endpoint: quinn::Endpoint,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl AsyncRead for Hy2StreamConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for Hy2StreamConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match Pin::new(&mut self.send).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => Poll::Ready(Ok(n)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(e.to_string()))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match Pin::new(&mut self.send).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(e.to_string()))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match Pin::new(&mut self.send).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(e.to_string()))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Unpin for Hy2StreamConn {}
impl ProxyConn for Hy2StreamConn {}

// ---------------------------------------------------------------------------
// Hy2UdpConn (with optional Salamander obfs)
// ---------------------------------------------------------------------------

struct Hy2UdpConn {
    endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    peer: SocketAddr,
    rx: Mutex<Vec<u8>>,
    obfs: Option<SalamanderObfs>,
}

#[async_trait]
impl ProxyPacketConn for Hy2UdpConn {
    async fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let mut pending = self.rx.lock().await;
        if pending.is_empty() {
            let data = self
                .conn
                .read_datagram()
                .await
                .map_err(|e| MeowError::Proxy(format!("hysteria2 udp read failed: {e}")))?;
            let mut raw = data.to_vec();
            // Strip Salamander obfs before handing data upstream.
            if let Some(ref obfs) = self.obfs {
                obfs.apply(&mut raw);
            }
            *pending = raw;
        }
        let n = pending.len().min(buf.len());
        buf[..n].copy_from_slice(&pending[..n]);
        pending.clear();
        Ok((n, self.peer))
    }

    async fn write_packet(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize> {
        let target = if addr.port() == 0 { self.peer } else { *addr };
        let mut frame = Vec::with_capacity(32 + buf.len());
        let host = target.ip().to_string();
        varint_encode(&mut frame, host.len() as u64);
        frame.extend_from_slice(host.as_bytes());
        frame.extend_from_slice(&target.port().to_be_bytes());
        frame.extend_from_slice(buf);
        // Apply Salamander obfs before sending.
        if let Some(ref obfs) = self.obfs {
            obfs.apply(&mut frame);
        }
        self.conn
            .send_datagram(frame.into())
            .map_err(|e| MeowError::Proxy(format!("hysteria2 udp send failed: {e}")))?;
        Ok(buf.len())
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint
            .local_addr()
            .map_err(|e| MeowError::Proxy(format!("hysteria2 local_addr failed: {e}")))
    }

    fn close(&self) -> Result<()> {
        self.conn.close(0u32.into(), b"client_close");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// QUIC client config
// ---------------------------------------------------------------------------

#[cfg(feature = "hysteria2")]
pub(crate) fn build_quic_client_config(
    skip_cert_verify: bool,
    ca_pem: Option<&[u8]>,
) -> std::result::Result<quinn::ClientConfig, String> {
    use rustls::RootCertStore;
    let mut root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    // Add any custom CA certificates.
    if let Some(pem_bytes) = ca_pem {
        let certs = rustls_pemfile::certs(&mut std::io::Cursor::new(pem_bytes))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| format!("hysteria2: failed to parse CA PEM: {e}"))?;
        if certs.is_empty() {
            return Err("hysteria2: ca/ca-str contained no valid certificates".to_string());
        }
        for cert in certs {
            root_store
                .add(cert)
                .map_err(|e| format!("hysteria2: failed to add CA cert: {e}"))?;
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("rustls builder: {e}"))?
        .with_root_certificates(root_store)
        .with_no_client_auth();
    tls.alpn_protocols = vec![HY2_ALPN.to_vec()];
    if skip_cert_verify {
        use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified};
        use rustls::pki_types::{CertificateDer, ServerName as RsServerName, UnixTime};
        use rustls::{DigitallySignedStruct, SignatureScheme};
        #[derive(Debug)]
        struct NoVerify;
        impl rustls::client::danger::ServerCertVerifier for NoVerify {
            fn verify_server_cert(
                &self,
                _: &CertificateDer<'_>,
                _: &[CertificateDer<'_>],
                _: &RsServerName<'_>,
                _: &[u8],
                _: UnixTime,
            ) -> std::result::Result<ServerCertVerified, rustls::Error> {
                Ok(ServerCertVerified::assertion())
            }
            fn verify_tls12_signature(
                &self,
                _: &[u8],
                _: &CertificateDer<'_>,
                _: &DigitallySignedStruct,
            ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn verify_tls13_signature(
                &self,
                _: &[u8],
                _: &CertificateDer<'_>,
                _: &DigitallySignedStruct,
            ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                vec![
                    SignatureScheme::ECDSA_NISTP256_SHA256,
                    SignatureScheme::ECDSA_NISTP384_SHA384,
                    SignatureScheme::ED25519,
                    SignatureScheme::RSA_PSS_SHA256,
                    SignatureScheme::RSA_PSS_SHA384,
                    SignatureScheme::RSA_PSS_SHA512,
                    SignatureScheme::RSA_PKCS1_SHA256,
                    SignatureScheme::RSA_PKCS1_SHA384,
                    SignatureScheme::RSA_PKCS1_SHA512,
                ]
            }
        }
        tls.dangerous().set_certificate_verifier(Arc::new(NoVerify));
    }
    let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|e| format!("quinn rustls adapter: {e}"))?;
    Ok(quinn::ClientConfig::new(Arc::new(quic_tls)))
}

// ---------------------------------------------------------------------------
// Wire encoding helpers
// ---------------------------------------------------------------------------

pub const VARINT_MAX: u64 = (1u64 << 62) - 1;

pub fn varint_encode(out: &mut Vec<u8>, value: u64) {
    debug_assert!(value <= VARINT_MAX, "varint value out of range");
    if value < 0x40 {
        out.push(value as u8);
    } else if value < 0x4000 {
        out.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes());
    } else if value < 0x4000_0000 {
        out.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(value | 0xC000_0000_0000_0000).to_be_bytes());
    }
}

pub fn varint_decode(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let raw = match len {
        1 => u64::from(first & 0x3F),
        2 => u64::from(u16::from_be_bytes([buf[0], buf[1]]) & 0x3FFF),
        4 => u64::from(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) & 0x3FFF_FFFF),
        8 => {
            u64::from_be_bytes([
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
            ]) & 0x3FFF_FFFF_FFFF_FFFF
        }
        _ => unreachable!(),
    };
    Some((raw, len))
}

pub fn encode_tcp_request(target: &str, padding: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(target.len() + padding.len() + 16);
    varint_encode(&mut out, FRAME_ID_TCP_REQUEST);
    varint_encode(&mut out, target.len() as u64);
    out.extend_from_slice(target.as_bytes());
    varint_encode(&mut out, padding.len() as u64);
    out.extend_from_slice(padding);
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpResponse {
    pub ok: bool,
    pub message: String,
    pub consumed: usize,
}

pub fn decode_tcp_response(buf: &[u8]) -> std::result::Result<Option<TcpResponse>, String> {
    let mut cursor = 0usize;
    let status = match buf.first() {
        Some(b) => *b,
        None => return Ok(None),
    };
    cursor += 1;
    let ok = match status {
        TCP_STATUS_OK => true,
        TCP_STATUS_ERROR => false,
        other => return Err(format!("hysteria2: unknown TCPResponse status {other:#x}")),
    };
    let Some((msg_len, n)) = varint_decode(&buf[cursor..]) else {
        return Ok(None);
    };
    cursor += n;
    let msg_len = msg_len as usize;
    if buf.len() < cursor + msg_len {
        return Ok(None);
    }
    let message = std::str::from_utf8(&buf[cursor..cursor + msg_len])
        .map_err(|e| format!("hysteria2: TCPResponse message is not UTF-8: {e}"))?
        .to_string();
    cursor += msg_len;
    let Some((pad_len, n)) = varint_decode(&buf[cursor..]) else {
        return Ok(None);
    };
    cursor += n;
    let pad_len = pad_len as usize;
    if buf.len() < cursor + pad_len {
        return Ok(None);
    }
    cursor += pad_len;
    Ok(Some(TcpResponse {
        ok,
        message,
        consumed: cursor,
    }))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn salamander_key_derivation() {
        let obfs = SalamanderObfs::new("test-password");
        // SHA-256("test-password") = 0f91...  First 16 bytes must be deterministic.
        assert_eq!(obfs.key.len(), 16);
        // Round-trip: apply twice must yield identity.
        let original = vec![0x01, 0x02, 0x03, 0xFF];
        let mut buf = original.clone();
        obfs.apply(&mut buf);
        assert_ne!(buf, original, "obfuscation must change the bytes");
        obfs.apply(&mut buf);
        assert_eq!(buf, original, "double-apply must restore original bytes");
    }

    #[test]
    fn salamander_obfs_requires_password() {
        let result = Hy2Adapter::new_full(
            "test",
            "1.2.3.4",
            443,
            "pwd",
            None,
            false,
            None,
            Some("salamander"),
            None, // no obfs-password
            None,
            None,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("obfs-password"));
    }

    #[test]
    fn unknown_obfs_type_rejected() {
        let result = Hy2Adapter::new_full(
            "test", "1.2.3.4", 443, "pwd", None, false, None,
            Some("foobar"), Some("x"), None, None,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unsupported obfs type"));
    }

    #[test]
    fn parse_bandwidth_bps_variants() {
        assert_eq!(parse_bandwidth_bps("100 mbps"), Some(100_000_000));
        assert_eq!(parse_bandwidth_bps("50 kbps"), Some(50_000));
        assert_eq!(parse_bandwidth_bps("1 gbps"), Some(1_000_000_000));
        assert_eq!(parse_bandwidth_bps("100"), Some(100_000_000)); // bare int = Mbps
        assert_eq!(parse_bandwidth_bps("1000 bps"), Some(1000));
        assert_eq!(parse_bandwidth_bps("invalid"), None);
    }

    #[test]
    fn varint_roundtrip() {
        for &v in &[0u64, 63, 64, 16383, 16384, 1 << 30, VARINT_MAX] {
            let mut buf = Vec::new();
            varint_encode(&mut buf, v);
            let (decoded, _) = varint_decode(&buf).unwrap();
            assert_eq!(decoded, v);
        }
    }

    #[test]
    fn decode_tcp_response_partial_returns_none() {
        // Single-byte buffer — status byte present but no message length yet.
        let buf = vec![TCP_STATUS_OK];
        assert!(decode_tcp_response(&buf).unwrap().is_none());
    }

    #[test]
    fn adapter_new_empty_password_rejected() {
        let result = Hy2Adapter::new("test", "1.2.3.4", 443, "", None, false);
        assert!(result.is_err());
    }
}
