//! Reusable TLS inspection: connect (without validating) and summarize the
//! presented certificate chain. Used by the `tls-inspect` CLI and by
//! `cert-expiry-watch`.

use anyhow::{Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use x509_parser::prelude::*;

#[derive(Debug, Clone)]
pub struct CertSummary {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: i64,
    pub not_after: i64,
    pub sans: Vec<String>,
}

impl CertSummary {
    pub fn is_expired(&self, now: i64) -> bool {
        self.not_after < now
    }
    pub fn days_until_expiry(&self, now: i64) -> i64 {
        (self.not_after - now) / 86_400
    }
}

#[derive(Debug, Clone)]
pub struct Inspection {
    pub protocol: Option<String>,
    pub cipher: Option<String>,
    pub alpn: Option<String>,
    pub certs: Vec<CertSummary>,
}

#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _e: &CertificateDer<'_>,
        _i: &[CertificateDer<'_>],
        _n: &ServerName<'_>,
        _o: &[u8],
        _t: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        use SignatureScheme::*;
        vec![
            RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512,
            ECDSA_NISTP256_SHA256, ECDSA_NISTP384_SHA384,
            RSA_PSS_SHA256, RSA_PSS_SHA384, RSA_PSS_SHA512, ED25519,
        ]
    }
}

/// Ensure a crypto provider is installed exactly once.
pub fn init_crypto() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn summarize(der: &CertificateDer<'_>) -> CertSummary {
    match X509Certificate::from_der(der.as_ref()) {
        Ok((_, c)) => {
            let sans = c
                .get_extension_unique(&x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)
                .ok()
                .flatten()
                .and_then(|ext| {
                    if let ParsedExtension::SubjectAlternativeName(n) = ext.parsed_extension() {
                        Some(n.general_names.iter().map(|g| format!("{g:?}")).collect())
                    } else {
                        None
                    }
                })
                .unwrap_or_default();
            CertSummary {
                subject: c.subject().to_string(),
                issuer: c.issuer().to_string(),
                serial: c.raw_serial_as_string(),
                not_before: c.validity().not_before.timestamp(),
                not_after: c.validity().not_after.timestamp(),
                sans,
            }
        }
        Err(e) => CertSummary {
            subject: format!("<parse error: {e}>"),
            issuer: String::new(),
            serial: String::new(),
            not_before: 0,
            not_after: 0,
            sans: vec![],
        },
    }
}

/// Connect to `host:port` with the given SNI and summarize the chain.
pub async fn inspect(host: &str, port: u16, sni: &str, to: Duration) -> Result<Inspection> {
    init_crypto();
    let server_name = ServerName::try_from(sni.to_string())
        .with_context(|| format!("invalid SNI name: {sni}"))?;
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));

    let tcp = timeout(to, TcpStream::connect((host, port)))
        .await
        .context("connect timed out")?
        .context("TCP connect failed")?;
    let tls = timeout(to, connector.connect(server_name, tcp))
        .await
        .context("TLS handshake timed out")?
        .context("TLS handshake failed")?;

    let (_, conn) = tls.get_ref();
    let certs = conn
        .peer_certificates()
        .map(|chain| chain.iter().map(summarize).collect())
        .unwrap_or_default();

    Ok(Inspection {
        protocol: conn.protocol_version().map(|p| format!("{p:?}")),
        cipher: conn.negotiated_cipher_suite().map(|c| format!("{:?}", c.suite())),
        alpn: conn.alpn_protocol().map(|a| String::from_utf8_lossy(a).into_owned()),
        certs,
    })
}

pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
