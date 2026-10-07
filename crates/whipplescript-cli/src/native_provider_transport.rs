//! Explicit provider transport custody. The embedding supplies admission;
//! this module prevents network realization from widening that capability.
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};
use ureq::rustls;
use url::{Host, Url};
use whipplescript_kernel::provider_contract;

use super::{HostRuntimeError, ModelProvider};

/// An embedding-approved endpoint, address set and TLS identity.
/// Construction validates transport material, never office or task authority.
#[derive(Clone)]
pub struct NativeProviderTransport {
    endpoint: String,
    authority: String,
    addresses: Vec<SocketAddr>,
    tls: Option<Arc<rustls::ClientConfig>>,
}

impl fmt::Debug for NativeProviderTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativeProviderTransport { [REDACTED] }")
    }
}

fn refused() -> HostRuntimeError {
    HostRuntimeError::Resolver("admitted provider transport refused".into())
}

impl NativeProviderTransport {
    /// Plaintext is supported only at a literal loopback address, at the
    /// endpoint's exact port. A hostname such as `localhost` is not an IP pin.
    pub fn loopback_http(
        endpoint: &str,
        addresses: Vec<SocketAddr>,
    ) -> Result<Self, HostRuntimeError> {
        Self::build(endpoint, addresses, None)
    }

    /// TLS uses only these DER trust roots and SHA-256 leaf certificate pins.
    /// Certificate pinning supplements ordinary trust/name/time/signature checks.
    pub fn pinned_https(
        endpoint: &str,
        addresses: Vec<SocketAddr>,
        trust_roots_der: Vec<Vec<u8>>,
        certificate_sha256: Vec<[u8; 32]>,
    ) -> Result<Self, HostRuntimeError> {
        if trust_roots_der.is_empty() || certificate_sha256.is_empty() {
            return Err(refused());
        }
        let mut roots = rustls::RootCertStore::empty();
        for root in trust_roots_der {
            roots
                .add(CertificateDer::from(root))
                .map_err(|_| refused())?;
        }
        let crypto = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            crypto.clone(),
        )
        .build()
        .map_err(|_| refused())?;
        let config = rustls::ClientConfig::builder_with_provider(crypto)
            .with_safe_default_protocol_versions()
            .map_err(|_| refused())?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedCertificateVerifier {
                inner: verifier,
                pins: certificate_sha256,
            }))
            .with_no_client_auth();
        Self::build(endpoint, addresses, Some(Arc::new(config)))
    }

    fn build(
        endpoint: &str,
        addresses: Vec<SocketAddr>,
        tls: Option<Arc<rustls::ClientConfig>>,
    ) -> Result<Self, HostRuntimeError> {
        let url = Url::parse(endpoint).map_err(|_| refused())?;
        if endpoint != endpoint.trim()
            || endpoint.trim_end_matches('/') != url.as_str().trim_end_matches('/')
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.host().is_none()
            || addresses.is_empty()
        {
            return Err(refused());
        }
        let port = url.port_or_known_default().ok_or_else(refused)?;
        let url_ip = match url.host() {
            Some(Host::Ipv4(ip)) => Some(std::net::IpAddr::V4(ip)),
            Some(Host::Ipv6(ip)) => Some(std::net::IpAddr::V6(ip)),
            _ => None,
        };
        if addresses.iter().any(|address| {
            address.port() != port
                || address.ip().is_unspecified()
                || address.ip().is_multicast()
                || url_ip.is_some_and(|ip| address.ip() != ip)
        }) {
            return Err(refused());
        }
        let permitted = match (url.scheme(), tls.is_some()) {
            ("https", true) => true,
            ("http", false) => {
                url_ip.is_some_and(|ip| ip.is_loopback())
                    && addresses.iter().all(|address| address.ip().is_loopback())
            }
            _ => false,
        };
        if !permitted {
            return Err(refused());
        }
        // ureq supplies the hostname and port to its resolver, including IPv6
        // brackets. Derive exactly that spelling from the parsed URL.
        let authority = format!(
            "{}:{port}",
            &url[url::Position::BeforeHost..url::Position::AfterHost]
        );
        Ok(Self {
            endpoint: endpoint.into(),
            authority,
            addresses,
            tls,
        })
    }

    pub(super) fn agent(
        &self,
        provider: ModelProvider,
        endpoint: &str,
        timeout: Duration,
    ) -> Result<(ureq::Agent, String), HostRuntimeError> {
        if endpoint != self.endpoint {
            return Err(refused());
        }
        // The identity's default wire's path, or the identity's own where it
        // replaces the wire's (the Codex backend), from the provider contract.
        let identity = provider_contract::provider(provider.as_str()).ok_or_else(refused)?;
        let suffix = identity.path_on(identity.default_wire());
        let request_url = format!("{}{suffix}", endpoint.trim_end_matches('/'));
        let authority = self.authority.clone();
        let addresses = self.addresses.clone();
        let mut builder = ureq::AgentBuilder::new()
            .timeout(timeout)
            .redirects(0)
            .try_proxy_from_env(false)
            .max_idle_connections(0)
            .user_agent("whipplescript-host-runtime")
            .resolver(move |requested: &str| {
                if requested != authority {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "admitted provider address refused",
                    ));
                }
                Ok(addresses.clone())
            });
        if let Some(tls) = &self.tls {
            builder = builder.https_only(true).tls_config(tls.clone());
        }
        Ok((builder.build(), request_url))
    }
}

#[derive(Debug)]
struct PinnedCertificateVerifier {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    pins: Vec<[u8; 32]>,
}

impl ServerCertVerifier for PinnedCertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let verified =
            self.inner
                .verify_server_cert(end_entity, intermediates, server_name, ocsp, now)?;
        let fingerprint: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if !self.pins.contains(&fingerprint) {
            return Err(rustls::Error::General(
                "admitted provider certificate refused".into(),
            ));
        }
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::super::{NativeHttpDriver, ResolvedProviderBinding};
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use whipplescript_kernel::sansio::{HostDriver, HttpRequest, IoRequest, IoResult};

    const ROOT: &[u8] = include_bytes!("test_provider_tls/root.der");
    const LEAF: &[u8] = include_bytes!("test_provider_tls/leaf.der");
    // Disposable synthetic fixture key. It is never an office or provider key.
    const KEY: &[u8] = include_bytes!("test_provider_tls/leaf-key.der");

    fn request(base: &str) -> IoRequest {
        IoRequest::Http(HttpRequest {
            url: format!("{base}/chat/completions"),
            headers: vec![("authorization".into(), "Bearer synthetic-test-key".into())],
            body: serde_json::json!({"messages": [{"content": "synthetic patient prompt"}]}),
            model_provenance: None,
        })
    }
    fn binding(base: &str, transport: NativeProviderTransport) -> ResolvedProviderBinding {
        ResolvedProviderBinding::new(
            ModelProvider::OpenAiCompat,
            "synthetic-test-key",
            "local",
            base,
            1024,
            Duration::from_secs(5),
        )
        .with_admitted_transport(transport)
    }
    fn read_request(stream: &mut impl Read) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut chunk = [0; 4096];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => return bytes,
                Ok(n) => bytes.extend_from_slice(&chunk[..n]),
            }
            if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                let header = String::from_utf8_lossy(&bytes[..end]);
                let length = header
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
                if bytes.len() >= end + 4 + length {
                    return bytes;
                }
            }
        }
    }
    fn accept_bounded(listener: &TcpListener) -> std::net::TcpStream {
        listener.set_nonblocking(true).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match listener.accept() {
                Ok((socket, _)) => {
                    socket.set_nonblocking(false).unwrap();
                    return socket;
                }
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock
                        && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => {
                    panic!("synthetic receiver did not receive an admitted connection: {error}")
                }
            }
        }
    }

    fn tls_server(listener: TcpListener) -> std::thread::JoinHandle<Vec<u8>> {
        std::thread::spawn(move || {
            let crypto = Arc::new(rustls::crypto::ring::default_provider());
            let config = rustls::ServerConfig::builder_with_provider(crypto)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(LEAF.to_vec())],
                    rustls::pki_types::PrivateKeyDer::Pkcs8(KEY.to_vec().into()),
                )
                .unwrap();
            let socket = accept_bounded(&listener);
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let session = rustls::ServerConnection::new(Arc::new(config)).unwrap();
            let mut stream = rustls::StreamOwned::new(session, socket);
            let bytes = read_request(&mut stream);
            if !bytes.is_empty() {
                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}").unwrap();
                stream.conn.send_close_notify();
                stream.flush().unwrap();
            }
            bytes
        })
    }

    #[test]
    fn native_transport_tls_uses_only_pinned_addresses_and_certificate_before_body() {
        for (hostname, pinned, success) in [
            ("provider.test", true, true),
            ("provider.test", false, false),
            ("wrong.test", true, false),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let base = format!("https://{hostname}:{}/v1", address.port());
            let fingerprint = if pinned {
                Sha256::digest(LEAF).into()
            } else {
                [0; 32]
            };
            let transport = NativeProviderTransport::pinned_https(
                &base,
                vec![address],
                vec![ROOT.to_vec()],
                vec![fingerprint],
            )
            .unwrap();
            let server = tls_server(listener);
            let driver = NativeHttpDriver::for_binding(&binding(&base, transport)).unwrap();
            let IoResult::Http(result) = driver.fulfill(&request(&base));
            let received = server.join().unwrap();
            if success {
                assert_eq!(result.unwrap().body["ok"], true);
                let body = String::from_utf8(received).unwrap();
                assert!(body.contains("synthetic patient prompt"));
                assert!(body.contains("Bearer synthetic-test-key"));
                assert!(body.starts_with("POST /v1/chat/completions HTTP/1.1"));
            } else {
                assert!(result.is_err());
                assert!(
                    received.is_empty(),
                    "TLS refusal released application bytes"
                );
            }
        }
    }

    #[test]
    fn native_transport_tls_material_time_and_resolver_refuse_without_fallback() {
        let base = "https://provider.test:8443/v1";
        let address = "127.0.0.1:8443".parse().unwrap();
        let pin = Sha256::digest(LEAF).into();
        for (roots, pins) in [
            (Vec::new(), vec![pin]),
            (vec![ROOT.to_vec()], Vec::new()),
            (vec![vec![0]], vec![pin]),
        ] {
            assert!(
                NativeProviderTransport::pinned_https(base, vec![address], roots, pins).is_err()
            );
        }
        for wrong in ["0.0.0.0:8443", "224.0.0.1:8443", "127.0.0.1:8444"] {
            assert!(NativeProviderTransport::pinned_https(
                base,
                vec![wrong.parse().unwrap()],
                vec![ROOT.to_vec()],
                vec![pin]
            )
            .is_err());
        }
        let transport = NativeProviderTransport::pinned_https(
            base,
            vec![address],
            vec![ROOT.to_vec()],
            vec![pin],
        )
        .unwrap();
        let (agent, _) = transport
            .agent(ModelProvider::OpenAiCompat, base, Duration::from_secs(1))
            .unwrap();
        // Exercise the resolver refusal separately from the request-URL refusal.
        assert!(agent
            .post("https://different.test:8443/v1/chat/completions")
            .send_string("synthetic")
            .is_err());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from(ROOT.to_vec())).unwrap();
        let inner = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .unwrap();
        let verifier = PinnedCertificateVerifier {
            inner,
            pins: vec![pin],
        };
        let leaf = CertificateDer::from(LEAF.to_vec());
        let name = ServerName::try_from("provider.test").unwrap();
        // A matching pin never substitutes for ordinary validity checks.
        for seconds in [0, 4_102_444_800] {
            assert!(verifier
                .verify_server_cert(
                    &leaf,
                    &[],
                    &name,
                    &[],
                    UnixTime::since_unix_epoch(Duration::from_secs(seconds))
                )
                .is_err());
        }
    }

    #[test]
    fn native_transport_cleartext_and_request_refusals_preserve_receiver() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let base = format!("http://{address}/v1");
        let transport = NativeProviderTransport::loopback_http(&base, vec![address]).unwrap();
        assert!(NativeHttpDriver::for_binding(&binding(
            &format!("{base}/changed"),
            transport.clone()
        ))
        .is_err());
        let driver = NativeHttpDriver::for_binding(&binding(&base, transport)).unwrap();
        for wrong in [
            format!("{base}/wrong"),
            format!("http://{address}/elsewhere"),
            format!("https://{address}/v1"),
        ] {
            let IoResult::Http(result) = driver.fulfill(&request(&wrong));
            assert!(result.is_err());
        }
        listener.set_nonblocking(true).unwrap();
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        for wrong in [
            format!("http://localhost:{}/v1", address.port()),
            format!("http://127.0.0.2:{}/v1", address.port()),
            format!("{base}?x=1"),
            format!("{base}#x"),
            format!("{base}/../elsewhere"),
            format!("http://user:pass@{address}/v1"),
            format!("https://{address}/v1"),
        ] {
            assert!(NativeProviderTransport::loopback_http(&wrong, vec![address]).is_err());
        }
        assert!(NativeProviderTransport::loopback_http(&base, Vec::new()).is_err());
        assert!(NativeProviderTransport::loopback_http(
            &base,
            vec!["127.0.0.1:1".parse().unwrap()]
        )
        .is_err());
    }

    #[test]
    fn native_transport_resolver_refusal_does_not_reach_an_approved_socket_under_a_changed_authority(
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let base = format!("http://{address}/v1");
        let transport = NativeProviderTransport::loopback_http(&base, vec![address]).unwrap();
        let (agent, _) = transport
            .agent(ModelProvider::OpenAiCompat, &base, Duration::from_secs(1))
            .unwrap();
        let changed = format!("http://127.0.0.2:{}/v1/chat/completions", address.port());
        assert!(agent
            .post(&changed)
            .send_string("synthetic patient prompt")
            .is_err());
        listener.set_nonblocking(true).unwrap();
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn native_transport_redirect_never_replays_prompt_to_another_receiver() {
        let destination = TcpListener::bind("127.0.0.1:0").unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let base = format!("http://{address}/v1");
        let redirect = format!("HTTP/1.1 302 Found\r\nLocation: http://{}/stolen\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", destination.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let mut socket = accept_bounded(&listener);
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let bytes = read_request(&mut socket);
            socket.write_all(redirect.as_bytes()).unwrap();
            bytes
        });
        let transport = NativeProviderTransport::loopback_http(&base, vec![address]).unwrap();
        let driver = NativeHttpDriver::for_binding(&binding(&base, transport)).unwrap();
        let IoResult::Http(result) = driver.fulfill(&request(&base));
        assert_eq!(result.unwrap().status, 302);
        assert!(!server.join().unwrap().is_empty());
        destination.set_nonblocking(true).unwrap();
        assert_eq!(
            destination.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
}
