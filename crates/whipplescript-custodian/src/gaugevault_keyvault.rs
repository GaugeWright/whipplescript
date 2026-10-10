//! Exact-version Azure Key Vault reader for the separate GaugeVault custodian.
//!
//! This is backing I/O, not admission. A future caller must first consume one
//! exact dispatch against current Cosmos and account authority. This module is
//! private to the custodian crate; nothing here adds `get` to CustodyOp.

use std::fmt;
use std::io::Read;
use std::net::IpAddr;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use serde::Deserialize;
use ureq::OrAnyStatus;
use zeroize::Zeroizing;

const API_VERSION: &str = "2025-07-01";
const MAX_VAULT_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_IDENTITY_RESPONSE_BYTES: usize = 64 * 1024;
// GaugeWright DR-0241: 18,750 opaque bytes encode to at most 25,000 bytes.
const MAX_SECRET_VALUE_BYTES: usize = 18_750;
const MAX_ENCODED_SECRET_VALUE_BYTES: usize = MAX_SECRET_VALUE_BYTES / 3 * 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Error {
    InvalidVault,
    InvalidNamespace,
    InvalidStorageName,
    WrongAccount,
    InvalidReference,
    Authentication,
    Transport,
    ResponseTooLarge,
    HttpStatus(u16),
    MalformedResponse,
    MismatchedReference,
    DisabledVersion,
    SecretTooLarge,
    InvalidValueEncoding,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never format provider bodies, values, tokens, or caller-supplied IDs.
        write!(f, "GaugeVault Key Vault read: {self:?}")
    }
}

impl std::error::Error for Error {}

/// A token or secret value held only within the trusted custodian. Its buffer
/// clears on drop and Debug cannot print it.
pub(crate) struct SecretMaterial(Zeroizing<String>);

impl SecretMaterial {
    fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretMaterial(<redacted>)")
    }
}

impl<'de> Deserialize<'de> for SecretMaterial {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::new)
    }
}

/// Opaque credential bytes; distinct from the textual Azure bearer/header.
pub(crate) struct SecretValue(Zeroizing<Vec<u8>>);

impl SecretValue {
    pub(crate) fn expose_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretValue(<redacted>)")
    }
}

/// The Key Vault JSON field remains zeroizing until canonical base64 decoding.
struct EncodedSecretValue(Zeroizing<String>);

impl<'de> Deserialize<'de> for EncodedSecretValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(|value| Self(Zeroizing::new(value)))
    }
}

impl EncodedSecretValue {
    fn decode(self) -> Result<SecretValue, Error> {
        if self.0.len() > MAX_ENCODED_SECRET_VALUE_BYTES {
            return Err(Error::SecretTooLarge);
        }
        let bytes = BASE64_STANDARD
            .decode(self.0.as_bytes())
            .map_err(|_| Error::InvalidValueEncoding)?;
        // STANDARD rejects noncanonical padding and trailing bits. At most
        // 25,000 encoded bytes can decode to at most 18,750 raw bytes, so the
        // encoded guard above also enforces the raw-value ceiling.
        Ok(SecretValue(Zeroizing::new(bytes)))
    }
}

#[derive(Clone)]
pub(crate) struct VaultName(String);

impl VaultName {
    pub(crate) fn parse(value: &str) -> Result<Self, Error> {
        let bytes = value.as_bytes();
        if !(3..=24).contains(&bytes.len())
            || !bytes.first().is_some_and(u8::is_ascii_alphanumeric)
            || !bytes.last().is_some_and(u8::is_ascii_alphanumeric)
            || bytes
                .iter()
                .any(|b| !b.is_ascii_alphanumeric() && *b != b'-')
            || bytes.windows(2).any(|pair| pair == b"--")
        {
            return Err(Error::InvalidVault);
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    fn origin(&self) -> String {
        format!("https://{}.vault.azure.net", self.0)
    }
}

/// Opaque 128-bit prefix supplied from authenticated account authority.
pub(crate) struct AccountPrefix(String);

impl AccountPrefix {
    pub(crate) fn parse(value: &str) -> Result<Self, Error> {
        if !lower_hex_128(value) {
            return Err(Error::InvalidNamespace);
        }
        Ok(Self(value.to_owned()))
    }
}

/// One random Azure object per candidate, as selected by current authority.
pub(crate) struct StorageName(String);

impl StorageName {
    pub(crate) fn parse(value: &str) -> Result<Self, Error> {
        let parts: Vec<_> = value.split('-').collect();
        if parts.len() != 3
            || parts[0] != "gv"
            || !lower_hex_128(parts[1])
            || !lower_hex_128(parts[2])
        {
            return Err(Error::InvalidStorageName);
        }
        Ok(Self(value.to_owned()))
    }

    fn account_prefix(&self) -> &str {
        &self.0[3..35]
    }
}

fn lower_hex_128(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Exact provider-issued version reference. No latest-version read exists.
pub(crate) struct VersionReference(String);

impl VersionReference {
    pub(crate) fn parse(vault: &VaultName, name: &StorageName, id: &str) -> Result<Self, Error> {
        let expected = format!("{}/secrets/{}/", vault.origin(), name.0);
        let version = id.strip_prefix(&expected).ok_or(Error::InvalidReference)?;
        if version.len() != 32 || !version.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::InvalidReference);
        }
        Ok(Self(id.to_owned()))
    }
}

pub(crate) trait VaultToken: Send + Sync {
    fn access_token(&self) -> Result<SecretMaterial, Error>;
}

/// VM managed identity. Its only network target is Azure's fixed IMDS address.
pub(crate) struct VmIdentityToken {
    client_id: Option<String>,
    http: ureq::Agent,
}

impl VmIdentityToken {
    pub(crate) fn new(client_id: Option<String>) -> Result<Self, Error> {
        if client_id.as_ref().is_some_and(|id| !valid_client_id(id)) {
            return Err(Error::Authentication);
        }
        Ok(Self {
            client_id,
            http: identity_http(),
        })
    }
}

impl VaultToken for VmIdentityToken {
    fn access_token(&self) -> Result<SecretMaterial, Error> {
        let mut url = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net".to_owned();
        if let Some(client_id) = &self.client_id {
            url.push_str("&client_id=");
            url.push_str(client_id);
        }
        let response = self
            .http
            .get(&url)
            .set("Metadata", "true")
            .call()
            .map_err(|_| Error::Authentication)?;
        parse_identity_token(response)
    }
}

/// Azure Container Apps managed identity. The platform supplies a local
/// endpoint and rotates the request header, which is read for each call.
pub(crate) struct ContainerAppIdentityToken {
    endpoint: url::Url,
    client_id: Option<String>,
    http: ureq::Agent,
}

impl ContainerAppIdentityToken {
    pub(crate) fn from_env(client_id: Option<String>) -> Result<Self, Error> {
        let endpoint = std::env::var("IDENTITY_ENDPOINT").map_err(|_| Error::Authentication)?;
        // The platform's rotating header is secret even during construction.
        // Check its presence without leaving a plaintext temporary behind.
        let _header = SecretMaterial::new(
            std::env::var("IDENTITY_HEADER").map_err(|_| Error::Authentication)?,
        );
        Self::with_endpoint(&endpoint, client_id)
    }

    fn with_endpoint(endpoint: &str, client_id: Option<String>) -> Result<Self, Error> {
        let endpoint = url::Url::parse(endpoint).map_err(|_| Error::Authentication)?;
        let local = match endpoint.host_str() {
            Some("localhost") => true,
            Some(host) => host.parse::<IpAddr>().is_ok_and(|ip| match ip {
                IpAddr::V4(ip) => ip.is_loopback() || ip.is_link_local(),
                IpAddr::V6(ip) => ip.is_loopback(),
            }),
            None => false,
        };
        if endpoint.scheme() != "http"
            || !local
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || client_id.as_ref().is_some_and(|id| !valid_client_id(id))
        {
            return Err(Error::Authentication);
        }
        Ok(Self {
            endpoint,
            client_id,
            http: identity_http(),
        })
    }
}

impl VaultToken for ContainerAppIdentityToken {
    fn access_token(&self) -> Result<SecretMaterial, Error> {
        let header = SecretMaterial::new(
            std::env::var("IDENTITY_HEADER").map_err(|_| Error::Authentication)?,
        );
        self.access_token_with_header(header.expose())
    }
}

impl ContainerAppIdentityToken {
    fn access_token_with_header(&self, header: &str) -> Result<SecretMaterial, Error> {
        if header.is_empty() {
            return Err(Error::Authentication);
        }
        let mut url = self.endpoint.clone();
        {
            let mut query = url.query_pairs_mut();
            query
                .append_pair("resource", "https://vault.azure.net")
                .append_pair("api-version", "2019-08-01");
            if let Some(client_id) = &self.client_id {
                query.append_pair("client_id", client_id);
            }
        }
        let response = self
            .http
            .get(url.as_str())
            .set("X-IDENTITY-HEADER", header)
            .call()
            .map_err(|_| Error::Authentication)?;
        parse_identity_token(response)
    }
}

fn valid_client_id(id: &str) -> bool {
    id.len() == 36
        && id.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn identity_http() -> ureq::Agent {
    ureq::AgentBuilder::new()
        // A proxy inherited from the worker's environment must not receive
        // the platform's rotating Container Apps identity header.
        .try_proxy_from_env(false)
        .redirects(0)
        .timeout(Duration::from_secs(5))
        .build()
}

fn parse_identity_token(response: ureq::Response) -> Result<SecretMaterial, Error> {
    #[derive(Deserialize)]
    struct TokenBody {
        access_token: SecretMaterial,
    }
    let body = bounded_response_text(response, MAX_IDENTITY_RESPONSE_BYTES)
        .map_err(|_| Error::Authentication)?;
    let parsed: TokenBody = serde_json::from_str(&body).map_err(|_| Error::Authentication)?;
    if parsed.access_token.expose().is_empty() {
        return Err(Error::Authentication);
    }
    Ok(parsed.access_token)
}

/// The production HTTP implementation follows no redirects and reads no
/// non-200 response body, so errors cannot echo provider-controlled material.
pub(crate) struct UreqVaultHttp(ureq::Agent);

impl Default for UreqVaultHttp {
    fn default() -> Self {
        Self(
            ureq::AgentBuilder::new()
                .try_proxy_from_env(false)
                .redirects(0)
                .timeout(Duration::from_secs(10))
                .build(),
        )
    }
}

pub(crate) trait VaultHttp: Send + Sync {
    fn get(&self, url: &str, bearer: &str) -> Result<(u16, Zeroizing<String>), Error>;
}

impl VaultHttp for UreqVaultHttp {
    fn get(&self, url: &str, bearer: &str) -> Result<(u16, Zeroizing<String>), Error> {
        let authorization = Zeroizing::new(format!("Bearer {bearer}"));
        let response = self
            .0
            .get(url)
            .set("Authorization", &authorization)
            .call()
            .or_any_status()
            .map_err(|_| Error::Transport)?;
        let status = response.status();
        if status != 200 {
            return Ok((status, Zeroizing::new(String::new())));
        }
        Ok((
            status,
            bounded_response_text(response, MAX_VAULT_RESPONSE_BYTES)?,
        ))
    }
}

fn bounded_response_text(response: ureq::Response, max: usize) -> Result<Zeroizing<String>, Error> {
    let mut bytes = Zeroizing::new(Vec::new());
    response
        .into_reader()
        .take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Transport)?;
    if bytes.len() > max {
        return Err(Error::ResponseTooLarge);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| Error::MalformedResponse)?;
    Ok(Zeroizing::new(text.to_owned()))
}

/// Backing reader for a future consumed dispatch. Construction is internal to
/// the custodian, and calling this does not itself establish authority.
pub(crate) struct FinalUseReader<T: VaultToken, H: VaultHttp = UreqVaultHttp> {
    vault: VaultName,
    token: T,
    http: H,
}

impl<T: VaultToken> FinalUseReader<T> {
    pub(crate) fn new(vault: VaultName, token: T) -> Self {
        Self {
            vault,
            token,
            http: UreqVaultHttp::default(),
        }
    }
}

impl<T: VaultToken, H: VaultHttp> FinalUseReader<T, H> {
    #[cfg(test)]
    fn with_http(vault: VaultName, token: T, http: H) -> Self {
        Self { vault, token, http }
    }

    pub(crate) fn read_exact(
        &self,
        expected_prefix: &AccountPrefix,
        name: &StorageName,
        reference: &VersionReference,
    ) -> Result<SecretValue, Error> {
        if name.account_prefix() != expected_prefix.0 {
            return Err(Error::WrongAccount);
        }
        // Revalidate the full reference at the trust boundary, even if a
        // caller previously parsed it against a different vault or object.
        let reference = VersionReference::parse(&self.vault, name, &reference.0)?;
        let url = format!("{}?api-version={API_VERSION}", reference.0);
        let bearer = self.token.access_token()?;
        let (status, body) = self.http.get(&url, bearer.expose())?;
        if status != 200 {
            return Err(Error::HttpStatus(status));
        }
        #[derive(Deserialize)]
        struct Attributes {
            enabled: Option<bool>,
        }
        #[derive(Deserialize)]
        struct Reply {
            id: String,
            value: Option<EncodedSecretValue>,
            attributes: Attributes,
        }
        let parsed: Reply = serde_json::from_str(&body).map_err(|_| Error::MalformedResponse)?;
        if parsed.id != reference.0 {
            return Err(Error::MismatchedReference);
        }
        if parsed.attributes.enabled != Some(true) {
            return Err(Error::DisabledVersion);
        }
        parsed.value.ok_or(Error::MalformedResponse)?.decode()
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use super::*;

    const PREFIX: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const OTHER: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const OBJECT: &str = "11111111111111111111111111111111";
    const VERSION: &str = "22222222222222222222222222222222";

    struct Token(AtomicUsize);
    impl VaultToken for Token {
        fn access_token(&self) -> Result<SecretMaterial, Error> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(SecretMaterial::new("synthetic-token".into()))
        }
    }

    struct Http {
        status: u16,
        body: String,
        calls: Mutex<Vec<String>>,
    }
    impl VaultHttp for Http {
        fn get(&self, url: &str, bearer: &str) -> Result<(u16, Zeroizing<String>), Error> {
            assert_eq!(bearer, "synthetic-token");
            self.calls.lock().unwrap().push(url.to_owned());
            Ok((self.status, Zeroizing::new(self.body.clone())))
        }
    }

    fn name(prefix: &str) -> StorageName {
        StorageName::parse(&format!("gv-{prefix}-{OBJECT}")).unwrap()
    }

    fn id(prefix: &str) -> String {
        format!("https://gv-test.vault.azure.net/secrets/gv-{prefix}-{OBJECT}/{VERSION}")
    }

    fn reader(status: u16, body: String) -> FinalUseReader<Token, Http> {
        FinalUseReader::with_http(
            VaultName::parse("gv-test").unwrap(),
            Token(AtomicUsize::new(0)),
            Http {
                status,
                body,
                calls: Mutex::new(Vec::new()),
            },
        )
    }

    /// Run only through scripts/gaugevault-custodian-keyvault-live.py. Its
    /// disposable vault contains synthetic material, and the operator's
    /// short-lived Azure token arrives on stdin without entering test output.
    #[test]
    #[ignore = "requires disposable Azure Key Vault and operator token on stdin"]
    fn live_exact_version_refusal_and_read() {
        struct LiveToken(Zeroizing<String>, AtomicUsize);
        impl VaultToken for LiveToken {
            fn access_token(&self) -> Result<SecretMaterial, Error> {
                self.1.fetch_add(1, Ordering::SeqCst);
                Ok(SecretMaterial::new(self.0.as_str().to_owned()))
            }
        }

        let vault = VaultName::parse(&std::env::var("GV_LIVE_VAULT").unwrap()).unwrap();
        let prefix = AccountPrefix::parse(&std::env::var("GV_LIVE_PREFIX").unwrap()).unwrap();
        let other = AccountPrefix::parse(&std::env::var("GV_LIVE_OTHER_PREFIX").unwrap()).unwrap();
        let name = StorageName::parse(&std::env::var("GV_LIVE_NAME").unwrap()).unwrap();
        let reference =
            VersionReference::parse(&vault, &name, &std::env::var("GV_LIVE_REFERENCE").unwrap())
                .unwrap();
        let expected_case = std::env::var("GV_LIVE_CASE").unwrap();

        let mut bearer = Zeroizing::new(String::new());
        std::io::stdin().read_to_string(&mut bearer).unwrap();
        let token_length = bearer.trim_end_matches(['\r', '\n']).len();
        bearer.truncate(token_length);
        assert!(!bearer.is_empty(), "Azure bearer was absent");
        let reader = FinalUseReader::new(vault, LiveToken(bearer, AtomicUsize::new(0)));

        assert!(matches!(
            reader.read_exact(&other, &name, &reference),
            Err(Error::WrongAccount)
        ));
        assert_eq!(reader.token.1.load(Ordering::SeqCst), 0);
        match expected_case.as_str() {
            "enabled" => {
                let material = reader.read_exact(&prefix, &name, &reference).unwrap();
                assert!(
                    material.expose_bytes() == b"synthetic-gaugevault-custodian-proof",
                    "synthetic material differed"
                );
            }
            "disabled" => match reader.read_exact(&prefix, &name, &reference) {
                Err(Error::DisabledVersion) => println!("CUSTODIAN_DISABLED_METADATA_REFUSAL"),
                Err(Error::HttpStatus(status)) if (400..500).contains(&status) && status != 401 => {
                    println!("CUSTODIAN_DISABLED_HTTP_STATUS_{status}");
                }
                Err(other) => panic!("unexpected disabled read error: {other:?}"),
                Ok(_) => panic!("disabled version returned material"),
            },
            _ => panic!("unknown live proof case"),
        }
        assert_eq!(reader.token.1.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn reads_only_the_bound_exact_enabled_version() {
        let reference = VersionReference::parse(
            &VaultName::parse("gv-test").unwrap(),
            &name(PREFIX),
            &id(PREFIX),
        )
        .unwrap();
        let body = serde_json::json!({"id": id(PREFIX), "value": BASE64_STANDARD.encode(b"synthetic-secret"),
            "attributes": {"enabled": true}})
        .to_string();
        let reader = reader(200, body);
        let material = reader
            .read_exact(
                &AccountPrefix::parse(PREFIX).unwrap(),
                &name(PREFIX),
                &reference,
            )
            .unwrap();
        assert_eq!(material.expose_bytes(), b"synthetic-secret");
        assert_eq!(format!("{material:?}"), "SecretValue(<redacted>)");
        assert_eq!(
            reader.http.calls.lock().unwrap().as_slice(),
            &[format!("{}?api-version={API_VERSION}", id(PREFIX))]
        );
    }

    #[test]
    fn copied_account_reference_refuses_before_token_or_http() {
        let reference = VersionReference::parse(
            &VaultName::parse("gv-test").unwrap(),
            &name(PREFIX),
            &id(PREFIX),
        )
        .unwrap();
        let reader = reader(200, String::new());
        assert!(matches!(
            reader.read_exact(
                &AccountPrefix::parse(OTHER).unwrap(),
                &name(PREFIX),
                &reference
            ),
            Err(Error::WrongAccount)
        ));
        assert_eq!(reader.token.0.load(Ordering::SeqCst), 0);
        assert!(reader.http.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn mismatched_or_disabled_response_never_yields_material() {
        let vault = VaultName::parse("gv-test").unwrap();
        let name = name(PREFIX);
        let reference = VersionReference::parse(&vault, &name, &id(PREFIX)).unwrap();
        let prefix = AccountPrefix::parse(PREFIX).unwrap();
        let wrong = reader(
            200,
            serde_json::json!({"id": id(OTHER), "value": BASE64_STANDARD.encode(b"synthetic-secret"),
            "attributes": {"enabled": true}})
            .to_string(),
        );
        assert!(matches!(
            wrong.read_exact(&prefix, &name, &reference),
            Err(Error::MismatchedReference)
        ));
        let disabled = reader(
            200,
            serde_json::json!({"id": id(PREFIX), "value": BASE64_STANDARD.encode(b"synthetic-secret"),
            "attributes": {"enabled": false}})
            .to_string(),
        );
        assert!(matches!(
            disabled.read_exact(&prefix, &name, &reference),
            Err(Error::DisabledVersion)
        ));
    }

    #[test]
    fn exact_version_read_decodes_binary_and_enforces_the_backing_byte_ceiling() {
        let vault = VaultName::parse("gv-test").unwrap();
        let name = name(PREFIX);
        let reference = VersionReference::parse(&vault, &name, &id(PREFIX)).unwrap();
        let prefix = AccountPrefix::parse(PREFIX).unwrap();
        let at_limit = vec![0xff; MAX_SECRET_VALUE_BYTES];
        let admitted = reader(
            200,
            serde_json::json!({"id": id(PREFIX), "value": BASE64_STANDARD.encode(&at_limit),
                "attributes": {"enabled": true}})
            .to_string(),
        );
        assert_eq!(
            admitted
                .read_exact(&prefix, &name, &reference)
                .unwrap()
                .expose_bytes(),
            at_limit
        );
        let over_limit = reader(
            200,
            serde_json::json!({"id": id(PREFIX), "value": BASE64_STANDARD.encode(vec![0xff; MAX_SECRET_VALUE_BYTES + 1]),
                "attributes": {"enabled": true}})
            .to_string(),
        );
        assert_eq!(
            over_limit
                .read_exact(&prefix, &name, &reference)
                .unwrap_err(),
            Error::SecretTooLarge
        );
    }

    #[test]
    fn exact_version_read_refuses_noncanonical_and_plaintext_values() {
        let vault = VaultName::parse("gv-test").unwrap();
        let name = name(PREFIX);
        let reference = VersionReference::parse(&vault, &name, &id(PREFIX)).unwrap();
        let prefix = AccountPrefix::parse(PREFIX).unwrap();
        for encoded in ["synthetic-secret", "Zg==\n", "Zh==", "Zg="] {
            let response = reader(
                200,
                serde_json::json!({"id": id(PREFIX), "value": encoded,
                    "attributes": {"enabled": true}})
                .to_string(),
            );
            assert_eq!(
                response.read_exact(&prefix, &name, &reference).unwrap_err(),
                Error::InvalidValueEncoding
            );
        }
    }

    #[test]
    fn bad_names_and_reference_cannot_choose_another_endpoint() {
        assert!(VaultName::parse("gv-test.evil").is_err());
        assert!(StorageName::parse("gv-a/../../secret").is_err());
        assert!(StorageName::parse("plain-name").is_err());
        assert!(StorageName::parse("gv-no-separator").is_err());
        assert!(StorageName::parse(&format!("gv-{}-{OBJECT}", PREFIX.to_uppercase())).is_err());
        assert!(AccountPrefix::parse("ACCOUNT-LABEL").is_err());
        let vault = VaultName::parse("gv-test").unwrap();
        let name = name(PREFIX);
        assert!(VersionReference::parse(
            &vault,
            &name,
            "https://other.vault.azure.net/secrets/name/22222222222222222222222222222222"
        )
        .is_err());
        assert!(VersionReference::parse(
            &vault,
            &name,
            &format!("{}?api-version=latest", id(PREFIX))
        )
        .is_err());
    }

    #[test]
    fn status_and_malformed_responses_refuse_without_echoing_material() {
        let vault = VaultName::parse("gv-test").unwrap();
        let name = name(PREFIX);
        let reference = VersionReference::parse(&vault, &name, &id(PREFIX)).unwrap();
        let prefix = AccountPrefix::parse(PREFIX).unwrap();
        let denied = reader(403, "synthetic-secret".into());
        assert_eq!(
            denied.read_exact(&prefix, &name, &reference).unwrap_err(),
            Error::HttpStatus(403)
        );
        let malformed = reader(200, "synthetic-secret".into());
        let error = malformed
            .read_exact(&prefix, &name, &reference)
            .unwrap_err();
        assert_eq!(error, Error::MalformedResponse);
        assert!(!error.to_string().contains("synthetic-secret"));
    }

    #[test]
    fn identity_sources_reject_remote_endpoints_and_invalid_client_ids() {
        assert!(
            ContainerAppIdentityToken::with_endpoint("https://example.com/token", None).is_err()
        );
        assert!(
            ContainerAppIdentityToken::with_endpoint("http://example.com/token", None).is_err()
        );
        assert!(
            ContainerAppIdentityToken::with_endpoint("http://127.0.0.1/token?x=1", None).is_err()
        );
        assert!(VmIdentityToken::new(Some("not-a-uuid".into())).is_err());
        assert!(ContainerAppIdentityToken::with_endpoint("http://127.0.0.1/token", None).is_ok());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}/token", listener.local_addr().unwrap());
        let container = ContainerAppIdentityToken::with_endpoint(&endpoint, None).unwrap();
        assert_eq!(
            container.access_token_with_header("").unwrap_err(),
            Error::Authentication
        );
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
    }

    fn one_reply(response: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/secret", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 1024];
            while !request.ends_with(b"\r\n\r\n") {
                let read = stream.read(&mut buffer).unwrap();
                assert!(read > 0 && request.len() + read <= 8192);
                request.extend_from_slice(&buffer[..read]);
            }
            stream.write_all(response.as_bytes()).unwrap();
        });
        url
    }

    #[test]
    fn production_http_never_follows_a_redirect_or_reads_its_body() {
        let url = one_reply("HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/leak\r\nContent-Length: 16\r\nConnection: close\r\n\r\nsynthetic-secret");
        let (status, body) = UreqVaultHttp::default()
            .get(&url, "synthetic-token")
            .unwrap();
        assert_eq!(status, 302);
        assert!(body.is_empty());
    }

    #[test]
    fn provider_response_is_bounded_before_full_allocation() {
        let url = one_reply(
            "HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\nsynthetic-secret",
        );
        let response = ureq::AgentBuilder::new()
            .try_proxy_from_env(false)
            .build()
            .get(&url)
            .call()
            .unwrap();
        assert_eq!(
            bounded_response_text(response, 8).unwrap_err(),
            Error::ResponseTooLarge
        );
    }

    #[test]
    fn identity_reply_cannot_supply_an_empty_access_token() {
        let url = one_reply("HTTP/1.1 200 OK\r\nContent-Length: 19\r\nConnection: close\r\n\r\n{\"access_token\":\"\"}");
        let response = ureq::AgentBuilder::new()
            .try_proxy_from_env(false)
            .build()
            .get(&url)
            .call()
            .unwrap();
        assert_eq!(
            parse_identity_token(response).unwrap_err(),
            Error::Authentication
        );
    }
}
