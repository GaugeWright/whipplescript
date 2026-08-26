//! Credential custody protocol (DR-0053).
//!
//! whip holds **handles**; a custodian in a separate security principal holds
//! material and performs operations. This crate is the seam between them: the
//! handle/sentinel types, the operation vocabulary, and the transport trait.
//! It contains no backend and no cryptography — those live in
//! `whipplescript-custodian`.
//!
//! The vocabulary is deliberately closed and there is **no `get(handle)` at
//! any layer** (DR-0053 §2): the only power the custodian offers is
//! *substitute / sign / verify / derive / wrap / unwrap / mint under policy*.
//! One caller with a legitimate reason to fetch plaintext would re-establish
//! extractability for all, so the operation does not exist to be called.
//! `models/maude/credential-no-eliminator.maude` proves the language side of
//! this; the `-REVEAL` sibling carries the rejected `get` design.
//!
//! The custodian stays semantically dumb (§3): whip constructs entire
//! requests with a typed [`Sentinel`] exactly where material belongs, and the
//! custodian's whole power is substitution at the marked slot if policy
//! permits. It does not parse payloads, choose endpoints, or know what an API
//! is.

pub mod canon;
#[cfg(target_family = "unix")]
pub mod client;

use std::fmt;

use serde::{Deserialize, Serialize};

/// Wire protocol identifier, carried on every call so a custodian can refuse
/// a caller from a different protocol generation.
pub const CUSTODY_PROTOCOL: &str = "whipplescript.custody.v1";

/// The conventional environment variable naming the custodian socket.
///
/// Vocabulary, not transport: the *name* a caller reads to learn whether an
/// operator asked for a custodian is meaningful on every target, while the
/// Unix-socket [`client`] that connects to it is not. It lives here so a
/// non-Unix build can still tell a configured custodian from an absent one and
/// refuse accordingly, rather than losing the distinction along with the
/// transport.
pub const CUSTODIAN_SOCKET_ENV: &str = "WHIPPLESCRIPT_CUSTODIAN_SOCKET";

// ---------------------------------------------------------------------------
// Names and kinds
// ---------------------------------------------------------------------------

/// A credential's stable name. Resource identity is `credential:<name>` —
/// deliberately not backend-qualified (`vault:`, `kms:`), so identity survives
/// backend migration and grants keep working (DR-0053 §5).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CredentialName(String);

impl CredentialName {
    /// Validated constructor. Names are one or more `/`-separated segments of
    /// `[a-z0-9_-]`, e.g. `stripe_api` or `acme/stripe-live`.
    pub fn new(name: &str) -> Result<Self, String> {
        if name.is_empty() {
            return Err("credential name is empty".to_string());
        }
        let ok_segment = |s: &str| {
            !s.is_empty()
                && s.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
        };
        if !name.split('/').all(ok_segment) {
            return Err(format!(
                "invalid credential name {name:?}: segments must be non-empty [a-z0-9_-]"
            ));
        }
        Ok(Self(name.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The governance resource identifier: `credential:<name>`.
    pub fn resource_id(&self) -> String {
        format!("credential:{}", self.0)
    }

    /// Parse a `credential:<name>` resource identifier.
    pub fn from_resource_id(id: &str) -> Result<Self, String> {
        match id.strip_prefix("credential:") {
            Some(rest) => Self::new(rest),
            None => Err(format!("not a credential resource id: {id:?}")),
        }
    }
}

impl fmt::Display for CredentialName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One parsed operator-config credential reference (DR-0053 *Migration*).
///
/// Five subsystems arrived at reference-not-value independently with four
/// spellings (`env:OPENAI_API_KEY`, `secret:claude`, `credential:model`,
/// `credential:account:openai`); this is the one namespace they unify onto.
/// `credential:<name>` names a custodian entry; every legacy spelling still
/// parses but resolves **degraded at r0** — visible, never silent — and is
/// removed at the first release that requires a rung.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialRef {
    /// `credential:<name>` — a custodian entry; the rung is whatever the
    /// custodian derives from evidence.
    Custodian(CredentialName),
    /// `env:<VAR>` — the legacy environment shim: material read from whip's
    /// own environment, so the honest resolution is r0 and degraded.
    LegacyEnv { var: String },
    /// A pre-unification spelling (`secret:<x>`, `credential:account:<x>`,
    /// or a legacy `credential:<x>` that names no custodian entry). Carried
    /// as an opaque tag so existing bindings keep matching; r0 degraded.
    LegacyTag { tag: String },
}

impl CredentialRef {
    pub fn parse(raw: &str) -> Result<Self, String> {
        if raw.trim().is_empty() {
            return Err("empty credential reference".to_string());
        }
        if let Some(var) = raw.strip_prefix("env:") {
            if var.is_empty() {
                return Err("env: credential reference names no variable".to_string());
            }
            return Ok(CredentialRef::LegacyEnv {
                var: var.to_string(),
            });
        }
        if let Some(rest) = raw.strip_prefix("credential:") {
            // The canonical namespace — but pre-unification ids like
            // `credential:account:openai` are not valid custodian names and
            // stay legacy tags rather than parse errors (no config break).
            if let Ok(name) = CredentialName::new(rest) {
                return Ok(CredentialRef::Custodian(name));
            }
            return Ok(CredentialRef::LegacyTag {
                tag: raw.to_string(),
            });
        }
        if raw.starts_with("secret:") {
            return Ok(CredentialRef::LegacyTag {
                tag: raw.to_string(),
            });
        }
        Err(format!(
            "unrecognized credential reference {raw:?}: use `credential:<name>` (custodian \
             entry) or the legacy `env:<VAR>` shim"
        ))
    }

    /// The honest rung/degraded pair this reference can claim WITHOUT asking
    /// a custodian: legacy shims are r0 degraded by construction. For
    /// `Custodian` references the truth is whatever the custodian's reply
    /// derives — this method reports the r0 floor and the caller must prefer
    /// the reply's values (`credential-rung-evidence.maude`: configuration
    /// is not evidence).
    pub fn shim_rung(&self) -> (Rung, bool) {
        (Rung::Process, true)
    }

    /// Whether this reference is a legacy spelling that the unification will
    /// retire once a rung is required.
    pub fn is_legacy(&self) -> bool {
        !matches!(self, CredentialRef::Custodian(_))
    }
}

/// The declared kind of a credential. `kind` exists so the checker can
/// statically reject `sign … with stripe_api` (DR-0053 §5); the custodian's
/// registered kind is authoritative and mismatch is a check error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialKind {
    /// An opaque bearer token (Authorization: Bearer …).
    Bearer,
    /// HTTP basic credentials.
    Basic,
    /// Raw material substituted verbatim at the marked slot.
    Raw,
    /// A symmetric HMAC-SHA-256 key (Stripe/GitHub/Slack webhooks).
    HmacSha256,
    /// An Ed25519 signing key.
    Ed25519,
    /// An AWS SigV4 secret key (signs via the §7 derivation chain).
    AwsSigv4,
    /// An RS256 private key (GitHub App JWTs, service accounts).
    JwtRs256,
}

impl CredentialKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            CredentialKind::Bearer => "bearer",
            CredentialKind::Basic => "basic",
            CredentialKind::Raw => "raw",
            CredentialKind::HmacSha256 => "hmac-sha256",
            CredentialKind::Ed25519 => "ed25519",
            CredentialKind::AwsSigv4 => "aws-sigv4",
            CredentialKind::JwtRs256 => "jwt-rs256",
        }
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "bearer" => Ok(CredentialKind::Bearer),
            "basic" => Ok(CredentialKind::Basic),
            "raw" => Ok(CredentialKind::Raw),
            "hmac-sha256" => Ok(CredentialKind::HmacSha256),
            "ed25519" => Ok(CredentialKind::Ed25519),
            "aws-sigv4" => Ok(CredentialKind::AwsSigv4),
            "jwt-rs256" => Ok(CredentialKind::JwtRs256),
            other => Err(format!("unknown credential kind {other:?}")),
        }
    }

    /// Which operations this kind supports. A `sign` against a `bearer`
    /// credential is a kind mismatch, statically and at the custodian.
    pub fn supports(&self, op: Operation) -> bool {
        match op {
            Operation::Request => matches!(
                self,
                CredentialKind::Bearer
                    | CredentialKind::Basic
                    | CredentialKind::Raw
                    | CredentialKind::AwsSigv4
            ),
            Operation::Sign | Operation::Verify => matches!(
                self,
                CredentialKind::HmacSha256
                    | CredentialKind::Ed25519
                    | CredentialKind::AwsSigv4
                    | CredentialKind::JwtRs256
            ),
            Operation::Derive => matches!(
                self,
                CredentialKind::HmacSha256 | CredentialKind::AwsSigv4 | CredentialKind::Raw
            ),
            Operation::Wrap | Operation::Unwrap => {
                matches!(self, CredentialKind::Raw | CredentialKind::HmacSha256)
            }
            Operation::Mint => matches!(
                self,
                CredentialKind::Bearer | CredentialKind::Basic | CredentialKind::Raw
            ),
        }
    }
}

impl fmt::Display for CredentialKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// The rung ladder
// ---------------------------------------------------------------------------

/// Sealing rung, ordered (DR-0053 §4). Derived from evidence by the
/// custodian, never asserted in configuration — `require credential <rung>`
/// in the signed policy compares against what the custodian *derived*
/// (`models/maude/credential-rung-evidence.maude`: configuration is not
/// evidence).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Rung {
    /// r0: in-process, sealed at rest under a passphrase-derived key. whip's
    /// *language* cannot read it; an escape can. Dev only, tagged degraded.
    Process,
    /// r1: OS keyring (libsecret / Keychain / DPAPI). Survives file read;
    /// session-bound.
    OsKeyring,
    /// r2: TPM 2.0 PCR-sealed / Secure Enclave / PKCS#11 — non-extractability
    /// is literally true.
    Hardware,
    /// r3: OpenBao / Vault / KMS / Home broker — material never exists on the
    /// box.
    Remote,
}

impl Rung {
    pub fn as_str(&self) -> &'static str {
        match self {
            Rung::Process => "process",
            Rung::OsKeyring => "os-keyring",
            Rung::Hardware => "hardware",
            Rung::Remote => "remote",
        }
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "process" | "r0" => Ok(Rung::Process),
            "os-keyring" | "r1" => Ok(Rung::OsKeyring),
            "hardware" | "r2" => Ok(Rung::Hardware),
            "remote" | "r3" => Ok(Rung::Remote),
            other => Err(format!("unknown sealing rung {other:?}")),
        }
    }

    /// Short ladder label (`r0`…`r3`), for run records and diagnostics.
    pub fn ladder_label(&self) -> &'static str {
        match self {
            Rung::Process => "r0",
            Rung::OsKeyring => "r1",
            Rung::Hardware => "r2",
            Rung::Remote => "r3",
        }
    }
}

impl fmt::Display for Rung {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Operations and the two grant classes
// ---------------------------------------------------------------------------

/// The closed operation vocabulary (DR-0053 §2). There is no `Get` variant
/// and never will be; a wire message naming an unknown operation fails to
/// deserialize.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Operation {
    Request,
    Sign,
    Verify,
    Derive,
    Wrap,
    Unwrap,
    Mint,
}

impl Operation {
    pub const ALL: [Operation; 7] = [
        Operation::Request,
        Operation::Sign,
        Operation::Verify,
        Operation::Derive,
        Operation::Wrap,
        Operation::Unwrap,
        Operation::Mint,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Operation::Request => "request",
            Operation::Sign => "sign",
            Operation::Verify => "verify",
            Operation::Derive => "derive",
            Operation::Wrap => "wrap",
            Operation::Unwrap => "unwrap",
            Operation::Mint => "mint",
        }
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "request" => Ok(Operation::Request),
            "sign" => Ok(Operation::Sign),
            "verify" => Ok(Operation::Verify),
            "derive" => Ok(Operation::Derive),
            "wrap" => Ok(Operation::Wrap),
            "unwrap" => Ok(Operation::Unwrap),
            "mint" => Ok(Operation::Mint),
            other => Err(format!("unknown custody operation {other:?}")),
        }
    }

    /// The grant classes of DR-0053 §14, extended to three by DR-0074 §2.
    ///
    /// A form that accepted narrowing uniformly would over-promise — a clause
    /// that reads as narrowed while meaning nothing — so each operation
    /// declares which axis, if any, it narrows on.
    pub fn grant_class(&self) -> GrantClass {
        match self {
            Operation::Request | Operation::Mint => GrantClass::Narrowable,
            Operation::Unwrap => GrantClass::TypeNarrowed,
            Operation::Sign | Operation::Verify | Operation::Derive | Operation::Wrap => {
                GrantClass::NonNarrowable
            }
        }
    }

    /// Whether this operation narrows by a glob list. Kept as the name DR-0053
    /// §14 used, defined in terms of the class so there is one authority.
    pub fn narrowable(&self) -> bool {
        matches!(self.grant_class(), GrantClass::Narrowable)
    }
}

/// How an operation may be narrowed in a grant (DR-0053 §14, DR-0074 §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GrantClass {
    /// `request` (host/method/path globs) and `mint` (vendor scope strings).
    /// The glob list is REQUIRED — a bare name is a check error.
    Narrowable,
    /// `unwrap`, which narrows by the wrapped payload's TYPE rather than by an
    /// address pattern (DR-0074 §2). The type is REQUIRED; a glob list on it is
    /// a check error. §14 originally classed `unwrap` non-narrowable because no
    /// natural glob exists for it, which is true and is why the axis is a type.
    TypeNarrowed,
    /// `sign`, `verify`, `derive`, `wrap`. Named bare, granting the whole
    /// operation; any narrowing clause is a check error rather than ignored.
    ///
    /// `wrap` stays here deliberately: sealing *into* a type is an author's own
    /// act on data it already holds, so narrowing it protects nobody. The
    /// dangerous direction is out, not in.
    NonNarrowable,
}

impl GrantClass {
    /// What a grant for this class must carry, for a diagnostic to quote.
    pub fn requirement(&self) -> &'static str {
        match self {
            GrantClass::Narrowable => "a glob list",
            GrantClass::TypeNarrowed => "a type after `for`",
            GrantClass::NonNarrowable => "no narrowing clause",
        }
    }
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Sentinels — the marked slot
// ---------------------------------------------------------------------------

/// Presentation form for material at a marked slot (DR-0053 §5): usable in
/// any string position, lowering the handle to a sentinel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PresentationForm {
    /// `Bearer <material>`
    Bearer,
    /// `Basic <base64(user:material)>` — the custodian holds `user:pass`
    /// material for `basic`-kind credentials and encodes at substitution.
    Basic,
    /// Material verbatim.
    Raw,
}

impl PresentationForm {
    pub fn as_str(&self) -> &'static str {
        match self {
            PresentationForm::Bearer => "bearer",
            PresentationForm::Basic => "basic",
            PresentationForm::Raw => "raw",
        }
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "bearer" => Ok(PresentationForm::Bearer),
            "basic" => Ok(PresentationForm::Basic),
            "raw" => Ok(PresentationForm::Raw),
            other => Err(format!("unknown presentation form {other:?}")),
        }
    }
}

impl fmt::Display for PresentationForm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Encode a request/response body for the `body_b64` field.
///
/// The convention lives here rather than at each call site because this crate
/// owns the wire type: base64 rather than a string so binary bodies survive,
/// and standard alphabet with padding, matching what the custodian decodes.
pub fn encode_body_b64(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    STANDARD.encode(bytes)
}

/// Decode a `body_b64` field.
pub fn decode_body_b64(encoded: &str) -> Result<Vec<u8>, String> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    STANDARD
        .decode(encoded)
        .map_err(|err| format!("bad base64: {err}"))
}

const SENTINEL_OPEN: &str = "{{whipplescript-credential:";
const SENTINEL_CLOSE: &str = "}}";

/// A typed placeholder marking exactly where material belongs in a request
/// whip constructs. The custodian substitutes at marked slots and nowhere
/// else. The textual form is `{{whipplescript-credential:<name>:<form>}}`.
///
/// This generalizes DR-0042's fixed `whipplescript-model-broker` marker: the
/// sentinel names its handle and presentation form, so one request may carry
/// slots for several credentials.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Sentinel {
    pub credential: CredentialName,
    pub form: PresentationForm,
}

impl Sentinel {
    pub fn new(credential: CredentialName, form: PresentationForm) -> Self {
        Self { credential, form }
    }

    /// The textual slot marker embedded in headers/bodies whip constructs.
    pub fn render(&self) -> String {
        format!(
            "{SENTINEL_OPEN}{}:{}{SENTINEL_CLOSE}",
            self.credential, self.form
        )
    }

    /// Parse one rendered sentinel.
    pub fn parse(text: &str) -> Result<Self, String> {
        let inner = text
            .strip_prefix(SENTINEL_OPEN)
            .and_then(|t| t.strip_suffix(SENTINEL_CLOSE))
            .ok_or_else(|| format!("not a credential sentinel: {text:?}"))?;
        let (name, form) = inner
            .rsplit_once(':')
            .ok_or_else(|| format!("malformed credential sentinel: {text:?}"))?;
        Ok(Self {
            credential: CredentialName::new(name)?,
            form: PresentationForm::parse(form)?,
        })
    }

    /// Every sentinel occurring in `text`, in order, with its byte range.
    /// Malformed markers (an opener with no valid close/name/form) are
    /// reported as errors rather than skipped: a slot the author believes is
    /// marked but the custodian would not substitute is a silent
    /// authentication failure at best.
    pub fn find_all(text: &str) -> Result<Vec<(std::ops::Range<usize>, Sentinel)>, String> {
        let mut out = Vec::new();
        let mut at = 0usize;
        while let Some(rel) = text[at..].find(SENTINEL_OPEN) {
            let start = at + rel;
            let close_rel = text[start..]
                .find(SENTINEL_CLOSE)
                .ok_or_else(|| "unterminated credential sentinel".to_string())?;
            let end = start + close_rel + SENTINEL_CLOSE.len();
            let sentinel = Sentinel::parse(&text[start..end])?;
            out.push((start..end, sentinel));
            at = end;
        }
        Ok(out)
    }
}

impl fmt::Display for Sentinel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

// ---------------------------------------------------------------------------
// Requests, envelopes, and operation payloads
// ---------------------------------------------------------------------------

/// An outbound HTTP request whip constructed in full, with sentinels at the
/// marked slots. The custodian substitutes and egresses; it never chooses any
/// part of this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    /// Base64 of the body bytes, absent for bodiless requests. Base64 rather
    /// than a string so binary bodies survive the wire; sentinels inside a
    /// body are found after decoding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_b64: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_b64: Option<String>,
}

/// Signature algorithm for `sign`/`verify`. Distinct from [`CredentialKind`]:
/// the kind is what the credential *is*, the alg is what this call asks it to
/// do, and the custodian refuses mismatches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignatureAlg {
    HmacSha256,
    Ed25519,
    /// RSASSA-PKCS1-v1_5 with SHA-256 (JWT RS256).
    RsaSha256,
}

/// A label-carrying envelope (DR-0053 §13). The envelope records the caller's
/// IFC label and `unwrap` restores it, so the wrap → store → unwrap roundtrip
/// cannot launder; AEAD associated data binds the ciphertext to
/// (credential, context, label) so envelopes are not swappable between
/// contexts even with every label intact
/// (`models/maude/credential-wrap-carriage.maude`, `-UNBOUND` sibling).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// The wrapping credential. A different credential does not open the
    /// envelope.
    pub credential: CredentialName,
    /// The context the envelope was produced for; unwrap under a different
    /// context is refused by AEAD, not by comparison.
    pub context: String,
    /// The carried label, recorded at wrap and restored at unwrap. Opaque to
    /// the custodian: whatever the caller's IFC layer serializes.
    pub label: serde_json::Value,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

/// How the custodian extracts the minted material from an exchange response
/// (DR-0053 *Open*, OAuth response capture): whip declares the path, the
/// custodian applies it — a dumb instruction, not protocol semantics. Only
/// simple dotted paths (`access_token`, `data.token`) are supported;
/// extraction is not a query language.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintExtraction {
    /// Dotted JSON path to the secret member of the exchange response body.
    pub token_path: String,
    /// Dotted paths to non-secret members returned to whip alongside the
    /// handle (expiry, scope echo, token type).
    #[serde(default)]
    pub public_paths: Vec<String>,
}

/// One custody operation. Externally tagged by `op`, and the vocabulary is
/// closed: a message with `"op": "get"` — or any name outside this list —
/// fails to deserialize.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum CustodyOp {
    /// Substitute at marked slots, egress, return the response.
    Request {
        credential: CredentialName,
        request: EgressRequest,
        /// How many sentinel slots the CONSTRUCTING program placed, declared
        /// out of band from the request text itself. The custodian finds
        /// sentinels by scanning finished text, which cannot tell a slot the
        /// author wrote from one that arrived inside interpolated data; if a
        /// value could carry a sentinel into a header, URL or body, the
        /// custodian would fill it with real material at a position the author
        /// never designated — and the `raw` form would put the bare secret
        /// there. Declaring the count out of band makes any such injection a
        /// refusal rather than a substitution: data can add an occurrence but
        /// cannot remove the author's, so the totals disagree.
        slots: usize,
    },
    /// Keyed signature, optionally through a derivation chain (§7): the
    /// custodian folds `HMAC` over the chain from the sealed material, then
    /// signs the payload with the final key. For AWS SigV4 the chain is
    /// `[date, region, service, "aws4_request"]` and whip never holds
    /// `kSigning`, which is itself a credential.
    Sign {
        credential: CredentialName,
        alg: SignatureAlg,
        #[serde(default)]
        derivation: Vec<String>,
        payload_b64: String,
    },
    /// Constant-time verification (§6) — in the custodian, since a timing
    /// oracle in whip leaks the key.
    Verify {
        credential: CredentialName,
        alg: SignatureAlg,
        payload_b64: String,
        signature_b64: String,
    },
    /// HKDF subkey; returns a handle, never material.
    Derive {
        credential: CredentialName,
        context: String,
    },
    /// Envelope-encrypt application data whip may persist but not read back
    /// without the custodian (§13).
    Wrap {
        credential: CredentialName,
        plaintext_b64: String,
        label: serde_json::Value,
        context: String,
    },
    /// Open an envelope. Legitimately returns plaintext to whip — wrapped
    /// data is application data, not credential material — so unwrap is
    /// scoped, budgeted, and audited like any other use (§13).
    Unwrap {
        credential: CredentialName,
        envelope: Envelope,
        context: String,
    },
    /// Credential exchange, custodian-executed so whip never sees the token
    /// in the response body. Returns a handle plus the non-secret half.
    Mint {
        credential: CredentialName,
        scope: Vec<String>,
        ttl_secs: u64,
        exchange: EgressRequest,
        extraction: MintExtraction,
        /// Slots the constructing program placed in `exchange`, declared out of
        /// band for the same reason as [`CustodyOp::Request::slots`]: the
        /// exchange is whip-constructed text carrying the PARENT credential's
        /// sentinels, so an injected slot here would present the parent to a
        /// position the author never designated.
        exchange_slots: usize,
    },
}

impl CustodyOp {
    pub fn operation(&self) -> Operation {
        match self {
            CustodyOp::Request { .. } => Operation::Request,
            CustodyOp::Sign { .. } => Operation::Sign,
            CustodyOp::Verify { .. } => Operation::Verify,
            CustodyOp::Derive { .. } => Operation::Derive,
            CustodyOp::Wrap { .. } => Operation::Wrap,
            CustodyOp::Unwrap { .. } => Operation::Unwrap,
            CustodyOp::Mint { .. } => Operation::Mint,
        }
    }

    pub fn credential(&self) -> &CredentialName {
        match self {
            CustodyOp::Request { credential, .. }
            | CustodyOp::Sign { credential, .. }
            | CustodyOp::Verify { credential, .. }
            | CustodyOp::Derive { credential, .. }
            | CustodyOp::Wrap { credential, .. }
            | CustodyOp::Unwrap { credential, .. }
            | CustodyOp::Mint { credential, .. } => credential,
        }
    }
}

// ---------------------------------------------------------------------------
// Calls, replies, attribution
// ---------------------------------------------------------------------------

/// Who is using the credential, recorded with every use — §1 claims every
/// use is attributable, and `UsesAreRecorded` in `CredentialCustody.tla`
/// exists so the rung floor cannot be satisfied by an unrecorded use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UseAttribution {
    /// The run performing the use.
    pub run_id: String,
    /// The acting agent/instance within the run, when one exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// The effect key of the effect this use serves, when one exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect_key: Option<String>,
}

/// One call over the transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyCall {
    /// Must equal [`CUSTODY_PROTOCOL`]; the custodian refuses others.
    pub protocol: String,
    pub attribution: UseAttribution,
    #[serde(flatten)]
    pub op: CustodyOp,
}

impl CustodyCall {
    pub fn new(attribution: UseAttribution, op: CustodyOp) -> Self {
        Self {
            protocol: CUSTODY_PROTOCOL.to_string(),
            attribution,
            op,
        }
    }
}

/// Success payloads, one per operation. None yields sealed material: `Derived`
/// and `Minted` return handles; `Unwrapped` returns application data that was
/// whip's to begin with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "lowercase")]
pub enum CustodyOk {
    Requested {
        response: EgressResponse,
    },
    Signed {
        signature_b64: String,
    },
    Verified {
        /// Constant-time comparison result. `false` is a *successful* call
        /// whose answer is "signature invalid" — the caller turns it into a
        /// typed effect failure.
        valid: bool,
    },
    Derived {
        credential: CredentialName,
    },
    Wrapped {
        envelope: Envelope,
    },
    Unwrapped {
        plaintext_b64: String,
        /// The label recorded at wrap, restored (§13): the boundary does not
        /// launder.
        label: serde_json::Value,
    },
    Minted {
        credential: CredentialName,
        /// Fingerprint of the minted material (non-secret).
        fingerprint: String,
        /// The non-secret half extracted via `public_paths`.
        public: serde_json::Value,
    },
}

/// Typed refusals. `Refused` reasons are closed so callers can route them;
/// backend faults carry a message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "kebab-case")]
pub enum CustodyError {
    UnknownCredential {
        credential: CredentialName,
    },
    /// The declared kind does not support this operation, or the alg does not
    /// match the material.
    KindMismatch {
        credential: CredentialName,
        kind: CredentialKind,
        operation: Operation,
    },
    /// No grant covers this operation for this caller.
    OperationNotGranted {
        credential: CredentialName,
        operation: Operation,
    },
    /// A narrowable operation's grant list does not cover the target.
    ScopeRefused {
        credential: CredentialName,
        detail: String,
    },
    /// The signed policy requires a rung the credential's evidence does not
    /// reach.
    RungBelowFloor {
        required: Rung,
        actual: Rung,
    },
    Revoked {
        credential: CredentialName,
    },
    /// Per-credential use budget exhausted (DR-0053 §9).
    BudgetExhausted {
        credential: CredentialName,
    },
    /// AEAD refused the envelope: wrong context, wrong credential, or
    /// tampered ciphertext. Deliberately one variant — AEAD cannot say which.
    EnvelopeRefused,
    /// The egress or exchange failed at the network layer.
    EgressFailed {
        detail: String,
    },
    /// Custodian-side fault.
    Backend {
        detail: String,
    },
}

impl fmt::Display for CustodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CustodyError::UnknownCredential { credential } => {
                write!(f, "unknown credential {credential}")
            }
            CustodyError::KindMismatch {
                credential,
                kind,
                operation,
            } => write!(
                f,
                "credential {credential} has kind {kind}, which does not support {operation}"
            ),
            CustodyError::OperationNotGranted {
                credential,
                operation,
            } => write!(f, "{operation} on {credential} is not granted"),
            CustodyError::ScopeRefused { credential, detail } => {
                write!(f, "scope refused for {credential}: {detail}")
            }
            CustodyError::RungBelowFloor { required, actual } => write!(
                f,
                "sealing rung {} is below the required floor {}",
                actual.ladder_label(),
                required.ladder_label()
            ),
            CustodyError::Revoked { credential } => write!(f, "credential {credential} is revoked"),
            CustodyError::BudgetExhausted { credential } => {
                write!(f, "use budget exhausted for {credential}")
            }
            CustodyError::EnvelopeRefused => f.write_str("envelope refused"),
            CustodyError::EgressFailed { detail } => write!(f, "egress failed: {detail}"),
            CustodyError::Backend { detail } => write!(f, "custodian backend fault: {detail}"),
        }
    }
}

/// The custodian's reply. Every reply — refusals included — carries the use
/// id it was recorded under and the rung the credential's evidence derives,
/// with `degraded` set when the resolution is a compatibility shim (legacy
/// `env:` refs resolve at r0 **degraded**; DR-0053 *Migration*).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyReply {
    pub use_id: String,
    pub rung: Rung,
    pub degraded: bool,
    pub outcome: Result<CustodyOk, CustodyError>,
}

/// Transport faults, distinct from custody refusals: a refusal is the
/// custodian speaking; a transport error means it never did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    Unavailable(String),
    Protocol(String),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::Unavailable(d) => write!(f, "custodian unavailable: {d}"),
            TransportError::Protocol(d) => write!(f, "custody protocol error: {d}"),
        }
    }
}

impl std::error::Error for TransportError {}

/// The transport seam (DR-0053 §2, tracker slice 1). r0 may run in-process,
/// but it still speaks [`CustodyCall`]/[`CustodyReply`] through this trait —
/// wiring r0 as direct function calls would leave the principal-separation
/// seam unexercised and make r1+ a rewrite rather than a backend swap.
pub trait CustodyTransport: Send + Sync {
    fn call(&self, call: CustodyCall) -> Result<CustodyReply, TransportError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(s: &str) -> CredentialName {
        CredentialName::new(s).expect("valid name")
    }

    #[test]
    fn rungs_are_ordered() {
        assert!(Rung::Process < Rung::OsKeyring);
        assert!(Rung::OsKeyring < Rung::Hardware);
        assert!(Rung::Hardware < Rung::Remote);
        assert_eq!(Rung::parse("r2").expect("parse"), Rung::Hardware);
        assert_eq!(Rung::parse("hardware").expect("parse"), Rung::Hardware);
    }

    #[test]
    fn resource_identity_is_backend_free() {
        let n = name("acme/stripe-live");
        assert_eq!(n.resource_id(), "credential:acme/stripe-live");
        assert_eq!(
            CredentialName::from_resource_id("credential:acme/stripe-live").expect("roundtrip"),
            n
        );
        assert!(CredentialName::from_resource_id("vault:acme/stripe-live").is_err());
        assert!(CredentialName::new("Bad Name").is_err());
        assert!(CredentialName::new("trailing/").is_err());
    }

    #[test]
    fn sentinel_roundtrip_and_scan() {
        let s = Sentinel::new(name("stripe_api"), PresentationForm::Bearer);
        assert_eq!(s.render(), "{{whipplescript-credential:stripe_api:bearer}}");
        assert_eq!(Sentinel::parse(&s.render()).expect("parse"), s);

        let header = format!("Bearer {}", s.render());
        let found = Sentinel::find_all(&header).expect("scan");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].1, s);
        assert_eq!(&header[found[0].0.clone()], s.render());

        let two = format!(
            "{} and {}",
            Sentinel::new(name("a"), PresentationForm::Raw).render(),
            Sentinel::new(name("b"), PresentationForm::Basic).render()
        );
        assert_eq!(Sentinel::find_all(&two).expect("scan").len(), 2);

        assert!(Sentinel::find_all("{{whipplescript-credential:oops").is_err());
        assert!(Sentinel::find_all("{{whipplescript-credential:UPPER:bearer}}").is_err());
        assert!(Sentinel::find_all("no sentinels here")
            .expect("scan")
            .is_empty());
    }

    #[test]
    fn operation_grant_classes_match_dr0053_s14() {
        let narrowable: Vec<Operation> = Operation::ALL
            .iter()
            .copied()
            .filter(Operation::narrowable)
            .collect();
        assert_eq!(narrowable, vec![Operation::Request, Operation::Mint]);
        // DR-0074 §2: `unwrap` left the non-narrowable class for a third one.
        assert_eq!(Operation::Unwrap.grant_class(), GrantClass::TypeNarrowed);
        assert!(!Operation::Unwrap.narrowable());
        assert_eq!(Operation::Wrap.grant_class(), GrantClass::NonNarrowable);
    }

    #[test]
    fn credential_refs_unify_with_legacy_spellings_tagged_degraded() {
        // The canonical namespace.
        assert_eq!(
            CredentialRef::parse("credential:acme/stripe-live").expect("parse"),
            CredentialRef::Custodian(name("acme/stripe-live"))
        );
        // Every legacy spelling still parses — and every one is degraded.
        for legacy in [
            "env:OPENAI_API_KEY",
            "secret:claude",
            "credential:account:openai",
        ] {
            let parsed = CredentialRef::parse(legacy).expect("legacy parses");
            assert!(parsed.is_legacy(), "{legacy} must be legacy");
            assert_eq!(parsed.shim_rung(), (Rung::Process, true));
        }
        assert!(!CredentialRef::parse("credential:model")
            .expect("parse")
            .is_legacy());
        // Unknown schemes are errors, not silent passthrough — the resolver
        // that "silently passes plaintext through otherwise" is the exact
        // complaint DR-0053 records.
        assert!(CredentialRef::parse("sk_live_plaintext").is_err());
        assert!(CredentialRef::parse("env:").is_err());
    }

    #[test]
    fn there_is_no_get_on_the_wire() {
        // The vocabulary is closed by construction; this pins the negative at
        // the wire layer: a message asking for `get` does not deserialize.
        let get = serde_json::json!({
            "protocol": CUSTODY_PROTOCOL,
            "attribution": { "run_id": "r1" },
            "op": "get",
            "credential": "stripe_api",
        });
        assert!(serde_json::from_value::<CustodyCall>(get).is_err());
    }

    #[test]
    fn calls_roundtrip_on_the_wire() {
        let call = CustodyCall::new(
            UseAttribution {
                run_id: "run-1".into(),
                actor: Some("deployer".into()),
                effect_key: None,
            },
            CustodyOp::Sign {
                credential: name("release_signing"),
                alg: SignatureAlg::Ed25519,
                derivation: vec![],
                payload_b64: "cGF5bG9hZA==".into(),
            },
        );
        let wire = serde_json::to_string(&call).expect("serialize");
        let back: CustodyCall = serde_json::from_str(&wire).expect("deserialize");
        assert_eq!(back, call);
        assert_eq!(back.op.operation(), Operation::Sign);

        let reply = CustodyReply {
            use_id: "use-1".into(),
            rung: Rung::Process,
            degraded: true,
            outcome: Err(CustodyError::RungBelowFloor {
                required: Rung::Hardware,
                actual: Rung::Process,
            }),
        };
        let wire = serde_json::to_string(&reply).expect("serialize");
        let back: CustodyReply = serde_json::from_str(&wire).expect("deserialize");
        assert_eq!(back, reply);
    }

    #[test]
    fn kind_operation_support_is_static() {
        assert!(CredentialKind::Bearer.supports(Operation::Request));
        // The DR's own example: `sign … with stripe_api` is rejectable.
        assert!(!CredentialKind::Bearer.supports(Operation::Sign));
        assert!(CredentialKind::Ed25519.supports(Operation::Sign));
        assert!(!CredentialKind::Ed25519.supports(Operation::Request));
        assert!(CredentialKind::AwsSigv4.supports(Operation::Request));
        assert!(CredentialKind::AwsSigv4.supports(Operation::Sign));
    }
}
