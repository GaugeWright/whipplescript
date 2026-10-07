//! The provider contract: what a model backend is on the wire, read from
//! `provider_contract.json` beside this file (WhippleScript DR-0205).
//!
//! The same file is imported by the Durable Object worker
//! (`worker/src/provider-contract.ts`), so the kernel and the worker read one
//! artifact rather than two hand-synced tables. A fact the artifact holds — a
//! request path, a base URL, an authentication header, a fixed header, an
//! output-limit spelling, which dialects an identity admits — is looked up
//! here, never written out at a call site; `scripts/check-provider-contract.mjs`
//! fails a consumer that spells one itself.
//!
//! The file is parsed once, strictly: an unknown field is a parse failure, and
//! the tests below hold every [`ModelWire`] and every [`CoerceProvider`] to an
//! entry, so an artifact that disagrees with the enums is a red test rather
//! than a panic in a live turn.

use crate::coerce_native::CoerceProvider;
use crate::harness_model::ModelWire;
use serde::Deserialize;
use std::collections::BTreeMap;

/// The whole artifact.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderContract {
    pub schema: String,
    pub version: u32,
    pub about: Vec<String>,
    pub wires: BTreeMap<String, WireContract>,
    pub providers: BTreeMap<String, ProviderEntry>,
}

/// One request dialect: the facts every identity speaking it shares.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireContract {
    /// The request path appended to the base URL.
    pub path: String,
    pub base_url_version: BaseUrlVersion,
    pub auth_header: AuthHeader,
    /// Headers every request on this wire carries, in the order sent.
    pub fixed_headers: BTreeMap<String, String>,
    pub usage_shape: UsageShape,
    pub usage_fields: UsageFields,
    /// `always`, or the request field that must be set for a stream to report
    /// usage.
    pub streamed_usage: String,
    pub output_limit: OutputLimit,
    pub structured_output: String,
    pub tool_vocabulary: ToolVocabulary,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum BaseUrlVersion {
    /// The base is a bare origin and the path carries the version segment.
    Appended,
    /// The base ends in the version segment (the OpenAI-SDK convention).
    InBase,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum AuthHeader {
    XApiKey,
    AuthorizationBearer,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum UsageShape {
    Anthropic,
    Openai,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsageFields {
    pub input: Vec<String>,
    pub output: Vec<String>,
    pub cache_read: Vec<String>,
    pub cache_write: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputLimit {
    pub field: String,
    pub required: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum ToolVocabulary {
    Native,
    Coerced,
}

/// One payer identity: the facts that differ between identities on one wire.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderEntry {
    /// The dialects the identity admits; the first is its default.
    pub wires: Vec<String>,
    pub surface: Surface,
    /// `None` where the base is per deployment.
    pub default_base_url: Option<String>,
    /// A path that replaces the wire's for this identity.
    pub path: Option<String>,
    pub credential: Credential,
    /// Identity-specific headers beyond the wire's. `<model>` and `<account>`
    /// stand for values the request supplies.
    pub extra_headers: BTreeMap<String, String>,
    /// An output-limit spelling that replaces the wire's, keyed by wire.
    pub output_limit: BTreeMap<String, String>,
    pub cache_key_carrier: String,
    pub doors: Vec<String>,
    pub pricing: Pricing,
}

/// `fixed`, or a map from base-URL suffix to the wire that surface speaks.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Surface {
    Fixed(String),
    BySuffix(BTreeMap<String, String>),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub kind: String,
    pub env: Vec<String>,
    pub stored: Option<String>,
    pub rungs: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pricing {
    pub basis: String,
    pub key: Option<String>,
}

static CONTRACT: std::sync::LazyLock<ProviderContract> = std::sync::LazyLock::new(|| {
    serde_json::from_str(include_str!("provider_contract.json"))
        .expect("provider_contract.json is parsed strictly by the kernel's own tests")
});

/// The parsed artifact.
pub fn contract() -> &'static ProviderContract {
    &CONTRACT
}

/// The contract of one dialect. Every [`ModelWire`] has one; the tests hold it.
pub fn wire(wire: ModelWire) -> &'static WireContract {
    contract()
        .wires
        .get(wire.as_str())
        .expect("every ModelWire has a provider_contract.json entry (held by the tests)")
}

/// The entry of one payer identity by its canonical config name.
pub fn provider(name: &str) -> Option<&'static ProviderEntry> {
    contract().providers.get(name)
}

/// The entry of an identity the kernel itself speaks. Every [`CoerceProvider`]
/// has one; the tests hold it.
pub fn coerce_provider(provider: CoerceProvider) -> &'static ProviderEntry {
    self::provider(provider.as_str())
        .expect("every CoerceProvider has a provider_contract.json entry (held by the tests)")
}

impl ProviderEntry {
    /// The dialects this identity admits, parsed.
    pub fn admitted_wires(&self) -> impl Iterator<Item = ModelWire> + '_ {
        self.wires.iter().filter_map(|name| ModelWire::parse(name))
    }

    /// The dialect the identity speaks when the binding declares none.
    pub fn default_wire(&self) -> ModelWire {
        self.admitted_wires()
            .next()
            .expect("every provider admits at least one wire (held by the tests)")
    }

    pub fn admits(&self, wire: ModelWire) -> bool {
        self.admitted_wires().any(|admitted| admitted == wire)
    }

    /// The default base URL, for an identity that has one.
    pub fn base_url(&self) -> &str {
        self.default_base_url
            .as_deref()
            .expect("this identity's base URL is per deployment and has no default")
    }

    /// The request path this identity uses on `wire`.
    pub fn path_on(&self, wire: ModelWire) -> &str {
        self.path
            .as_deref()
            .unwrap_or_else(|| self::wire(wire).path.as_str())
    }

    /// The extra headers, with `<model>` and `<account>` filled in.
    pub fn headers(&self, model: &str, account: &str) -> Vec<(String, String)> {
        self.extra_headers
            .iter()
            .map(|(name, value)| {
                let value = match value.as_str() {
                    "<model>" => model.to_owned(),
                    "<account>" => account.to_owned(),
                    other => other.to_owned(),
                };
                (name.clone(), value)
            })
            .collect()
    }

    /// The header the per-effect cache scope travels in, when it travels in a
    /// header rather than in the body.
    pub fn cache_key_header(&self) -> Option<&str> {
        self.cache_key_carrier.strip_prefix("header:")
    }
}

impl WireContract {
    /// The full request URL on this wire for a configured base URL.
    pub fn url(&self, base_url: &str) -> String {
        format!("{}{}", base_url.trim_end_matches('/'), self.path)
    }

    /// The authentication header carrying `secret`, then the wire's fixed
    /// headers, in the order a request sends them.
    pub fn auth_headers(&self, secret: &str) -> Vec<(String, String)> {
        let auth = match self.auth_header {
            AuthHeader::XApiKey => ("x-api-key".to_owned(), secret.to_owned()),
            AuthHeader::AuthorizationBearer => {
                ("authorization".to_owned(), format!("Bearer {secret}"))
            }
        };
        std::iter::once(auth)
            .chain(
                self.fixed_headers
                    .iter()
                    .map(|(name, value)| (name.clone(), value.clone())),
            )
            .collect()
    }

    /// The request field and value a stream needs to report usage, when the
    /// wire does not report it unasked.
    pub fn streamed_usage_request(&self) -> Option<(&str, &str)> {
        if self.streamed_usage == "always" {
            None
        } else {
            self.streamed_usage.split_once('.')
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_COERCE_PROVIDERS: &[CoerceProvider] = &[
        CoerceProvider::OpenAi,
        CoerceProvider::OpenAiCompat,
        CoerceProvider::Anthropic,
        CoerceProvider::Xai,
    ];

    #[test]
    fn provider_contract_parses_strictly() {
        let contract = contract();
        assert_eq!(contract.schema, "whipplescript.provider-contract");
        assert_eq!(contract.version, 1);
        assert!(!contract.about.is_empty());
    }

    #[test]
    fn provider_contract_names_exactly_the_model_wires() {
        let declared: Vec<&str> = contract().wires.keys().map(String::as_str).collect();
        let mut known: Vec<&str> = ModelWire::ALL.iter().map(|wire| wire.as_str()).collect();
        known.sort_unstable();
        assert_eq!(declared, known);
    }

    #[test]
    fn provider_contract_covers_every_coerce_provider() {
        for provider in ALL_COERCE_PROVIDERS {
            let entry = coerce_provider(*provider);
            assert!(
                entry.default_base_url.is_some(),
                "{} has a default base URL",
                provider.as_str()
            );
            assert!(entry.doors.iter().any(|door| door == "cli-coerce"));
        }
    }

    #[test]
    fn provider_contract_entries_are_internally_consistent() {
        let contract = contract();
        for (name, entry) in &contract.providers {
            assert!(!entry.wires.is_empty(), "{name} admits no wire");
            for wire in &entry.wires {
                assert!(
                    ModelWire::parse(wire).is_some(),
                    "{name} admits unknown wire {wire}"
                );
            }
            for wire in entry.output_limit.keys() {
                assert!(
                    entry.wires.contains(wire),
                    "{name} overrides the output limit of a wire it does not admit: {wire}"
                );
            }
            if let Surface::BySuffix(map) = &entry.surface {
                for wire in map.values() {
                    assert!(entry.wires.contains(wire), "{name} surface names {wire}");
                }
                assert!(entry.default_base_url.is_none());
            } else if let Surface::Fixed(word) = &entry.surface {
                assert_eq!(word, "fixed", "{name}");
            }
            // A base URL with the version in it pairs with an in-base wire, and
            // a bare origin with an appended one, for the identity's default.
            if let (Some(base), None) = (&entry.default_base_url, &entry.path) {
                let default = wire(entry.default_wire());
                let versioned = base.trim_end_matches('/').ends_with("/v1");
                assert_eq!(
                    versioned,
                    default.base_url_version == BaseUrlVersion::InBase,
                    "{name}'s default base URL disagrees with its default wire's convention"
                );
            }
            for rung in &entry.credential.rungs {
                assert!(contract.providers.contains_key(rung), "{name} rung {rung}");
            }
            if entry.pricing.basis == "prices" {
                assert!(entry.pricing.key.is_some(), "{name} is priced with no key");
            }
        }
        for (name, wire) in &contract.wires {
            assert!(wire.path.starts_with('/'), "{name}");
            assert!(!wire.usage_fields.input.is_empty(), "{name}");
            assert!(!wire.usage_fields.output.is_empty(), "{name}");
            assert_eq!(
                wire.tool_vocabulary == ToolVocabulary::Native,
                ModelWire::parse(name).is_some_and(ModelWire::uses_native_tools),
                "{name}"
            );
        }
    }

    #[test]
    fn provider_contract_auth_headers_keep_their_order() {
        assert_eq!(
            wire(ModelWire::AnthropicMessages).auth_headers("k"),
            vec![
                ("x-api-key".to_owned(), "k".to_owned()),
                ("anthropic-version".to_owned(), "2023-06-01".to_owned()),
            ]
        );
        assert_eq!(
            wire(ModelWire::OpenAiResponses).auth_headers("k"),
            vec![("authorization".to_owned(), "Bearer k".to_owned())]
        );
        assert_eq!(
            wire(ModelWire::OpenAiChatCompat).streamed_usage_request(),
            Some(("stream_options", "include_usage"))
        );
        assert_eq!(
            wire(ModelWire::OpenAiResponses).streamed_usage_request(),
            None
        );
    }
}
