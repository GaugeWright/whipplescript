//! Sans-IO effect vocabulary (DR-0033, Decisions 1–3).
//!
//! An external-I/O effect is a **pure, resumable step machine**: `step` runs
//! synchronously on every host and returns either [`Outcome::NeedsIo`] (the host
//! must perform some I/O and re-enter with the result) or [`Outcome::Settle`]
//! (the machine is done). The *host* drives it — the native host runs it to
//! completion in one synchronous pass ([`run_to_completion`], `ureq`); the
//! durable-object host (Phase 5) awaits `fetch` on `NeedsIo` and re-enters
//! `step` across isolate wakes.
//!
//! This module is the neutral home for the transport-agnostic HTTP types and the
//! host/step contracts, so effects other than coerce (agent turns, later file
//! effects) reuse them without depending on coerce-specific code. The lifecycle
//! these types obey is proven in `models/tla/ResumableEffectLifecycle.tla`; the
//! native `run_to_completion` path is that model's eviction-free refinement
//! (`NativeExactlyOnce`).

use serde_json::Value;

/// Reader authority is a host concern. These labels describe where the
/// provider-bound content came from; they never grant access by themselves.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, Default)]
pub struct ModelContentProvenance {
    pub source_handles: Vec<String>,
    pub complete: bool,
}

/// Ordered conversation provenance at the model-call boundary. A host may
/// release the complete body only after authorizing every source in every
/// entry; an incomplete entry makes the request unknown. The message mapping
/// is deliberately separate from provider JSON because one logical message
/// may expand into several wire items or be joined with another on a wire.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ModelRequestProvenance {
    pub messages: Vec<ModelContentProvenance>,
    pub tools: ModelContentProvenance,
}

impl ModelContentProvenance {
    /// A transformation may reveal any of its inputs. Missing provenance is
    /// contagious, and duplicate handles do not change the authority result.
    pub fn derived_from<'a>(parts: impl IntoIterator<Item = &'a Self>) -> Self {
        let mut handles = std::collections::BTreeSet::new();
        let mut complete = true;
        for part in parts {
            complete &= part.complete;
            handles.extend(part.source_handles.iter().cloned());
        }
        Self {
            source_handles: handles.into_iter().collect(),
            complete,
        }
    }
}

/// Host-supplied source identities for the distinct initial input planes.
/// A host that cannot prove one plane leaves its default (unknown) value.
#[derive(Clone, Debug, Default)]
pub struct InitialModelProvenance {
    pub system: ModelContentProvenance,
    pub user: ModelContentProvenance,
    pub world: ModelContentProvenance,
    pub tools: ModelContentProvenance,
}

/// A transport-agnostic HTTP request. The kernel builds these; a host transport
/// (the CLI's `ureq`, or the DO's `fetch`) executes them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpRequest {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Value,
    /// Live host-only inspection metadata; never serialized into `body` or
    /// forwarded as an HTTP header.
    pub model_provenance: Option<ModelRequestProvenance>,
}

/// A transport-agnostic HTTP response (status code + decoded JSON body).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Value,
}

/// Why a transport call did not yield a response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransportError {
    /// The request exceeded its deadline.
    Timeout,
    /// Any other transport-level failure (connect/TLS/decode), redacted message.
    Transport(String),
}

/// A unit of external I/O the host must perform.
///
/// HTTP is the only variant today (DR-0033 Decision 6 — one transport). The sum
/// is deliberately left open for a future large-object/blob control variant
/// (Decision 4 / Phase 7 storage tiering), so adding it later is an additive
/// change, not a breaking corner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IoRequest {
    Http(HttpRequest),
}

/// The host's answer to an [`IoRequest`], fed back into the step machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IoResult {
    Http(Result<HttpResponse, TransportError>),
}

/// The outcome of a single `step`: either the machine needs the host to perform
/// I/O (and will be re-entered with the [`IoResult`]), or it has settled.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Outcome<T> {
    NeedsIo(IoRequest),
    Settle(T),
}

/// A pure, resumable effect step machine (DR-0033 Decision 1).
///
/// `step` is synchronous on every host and holds all its state in `self`, so a
/// host may suspend between a `NeedsIo` and the next `step` (the DO case) or run
/// straight through (the native case). `incoming` is `None` on the first call
/// and `Some(result)` after each `NeedsIo` the host has fulfilled.
pub trait StepMachine {
    /// What the machine settles to.
    type Output;

    fn step(&mut self, incoming: Option<IoResult>) -> Outcome<Self::Output>;
}

/// A host that performs the I/O a [`StepMachine`] asks for.
///
/// The native host (CLI) fulfills an HTTP request by running `ureq` synchronously
/// and returning immediately; the DO host awaits `fetch`. Every existing
/// [`crate::coerce_native::CoerceTransport`] is a `HostDriver` via a blanket impl,
/// so the transports the codebase already has need no change.
pub trait HostDriver {
    fn fulfill(&self, request: &IoRequest) -> IoResult;
}

/// Drive a step machine to completion in one synchronous pass — the native host
/// path. This is the concrete instance of the model's eviction-free refinement:
/// every `NeedsIo` is fulfilled immediately and re-entered, with no suspension,
/// so at-least-once delivery collapses to exactly-once (`NativeExactlyOnce`).
pub fn run_to_completion<M: StepMachine, H: HostDriver + ?Sized>(
    machine: &mut M,
    host: &H,
) -> M::Output {
    let mut incoming: Option<IoResult> = None;
    loop {
        match machine.step(incoming.take()) {
            Outcome::NeedsIo(request) => incoming = Some(host.fulfill(&request)),
            Outcome::Settle(output) => return output,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A host that echoes each request's URL back as a 200 body, and counts the
    /// I/O rounds it fulfilled.
    struct EchoHost {
        rounds: std::cell::Cell<u32>,
    }

    impl HostDriver for EchoHost {
        fn fulfill(&self, request: &IoRequest) -> IoResult {
            self.rounds.set(self.rounds.get() + 1);
            let IoRequest::Http(http) = request;
            IoResult::Http(Ok(HttpResponse {
                status: 200,
                body: json!({ "url": http.url }),
            }))
        }
    }

    /// A machine that needs `rounds` HTTP calls, then settles with the count of
    /// responses it received. Exercises the general `claim -> [NeedsIo ->
    /// io_done]* -> settle` lifecycle for 0, 1, and many rounds.
    struct CountingMachine {
        remaining: u32,
        received: u32,
    }

    impl StepMachine for CountingMachine {
        type Output = u32;

        fn step(&mut self, incoming: Option<IoResult>) -> Outcome<u32> {
            if incoming.is_some() {
                self.received += 1;
            }
            if self.remaining == 0 {
                Outcome::Settle(self.received)
            } else {
                self.remaining -= 1;
                Outcome::NeedsIo(IoRequest::Http(HttpRequest {
                    model_provenance: None,
                    url: format!("https://example/{}", self.remaining),
                    headers: vec![],
                    body: json!({}),
                }))
            }
        }
    }

    #[test]
    fn run_to_completion_drives_zero_one_and_many_rounds() {
        for rounds in [0u32, 1, 3] {
            let host = EchoHost {
                rounds: std::cell::Cell::new(0),
            };
            let mut machine = CountingMachine {
                remaining: rounds,
                received: 0,
            };
            let settled = run_to_completion(&mut machine, &host);
            // The machine received exactly one response per NeedsIo it raised,
            // and the host fulfilled exactly that many rounds.
            assert_eq!(settled, rounds, "responses folded in");
            assert_eq!(host.rounds.get(), rounds, "host fulfilled every NeedsIo");
        }
    }
}
