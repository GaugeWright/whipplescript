# HJSON parser provenance

This crate derives from the full MIT-licensed `deser-hjson` 2.2.6 source and
conformance tests from https://github.com/Canop/deser-hjson, as published at
https://crates.io/crates/deser-hjson/2.2.6. `LICENSE` retains the upstream notice.
The Cargo package is owned here so Cargo and native Buck2 consume identical
source. The Rust library name remains `deser_hjson` for upstream tests.

The owning delta recognizes only actual whitespace/comments, propagates
unterminated trailing-comment errors, and classifies unquoted scalar values
by complete tokens rather than numeric/boolean prefixes. This preserves HJSON
quoteless strings such as the source log's dates. Recursive duplicate-key
refusal is imposed by the importer's Serde visitor, not by dropping keys in
this parser. The original full source remains recorded in importer evidence.

Dynamic number tokens delegate to the existing `serde_json::Number` parser,
rather than introducing a second partial number grammar. The replaced upstream
`de_number.rs` helper is retained in the provenance packet, not compiled as
unused scaffolding; explicitly typed numeric deserializers in `de.rs` remain
unchanged. Ordinary workspace formatting is mechanical.

To inherit the owning workspace's unsafe-code prohibition, the upstream
unchecked UTF-8 helpers are replaced by safe standard `str::chars` / `find`
operations over the already validated string. Upstream test panic calls use
explicit `expect` text, debug-only prints are removed, and one empty vector type is explicit after the JSON
parser dependency introduces another `PartialEq` candidate; assertions are
unchanged. These are ownership/lint adaptations, not grammar or trust changes.

The scalar fallback is checked against the owning Company's `hjson` 3.2.2
reader and HJSON syntax (https://hjson.github.io/syntax.html). The optional
fraction digits in `1.` / `1.e2` are normalized only for number recognition;
the actual source bytes are never rewritten. The first real comment marker
ends a scalar candidate, while later markers remain comment text.

A reachable upstream single-quoted Unicode panic is fixed by recognizing triple
apostrophes as a byte prefix, never a three-byte UTF-8 string slice. Actual
catch-unwind fixtures preserve valid single-quoted Unicode and refuse malformed
Unicode strings/comments without panic.

Bounded malformed-Unicode probes also exposed inherited multiline root-column
underflow/truncated closing-quote indexing and escape-selector/hex-span UTF-8
boundaries. Root indentation saturates only at column zero; closing quotes use
a bounded byte prefix; quoted escape selectors consume one complete character;
four-hex spans use checked UTF-8 string access before advancing. Existing valid
ASCII/indented multiline behavior and typed numeric paths are unchanged. These
actual targeted controls are not a claim of exhaustive panic-free grammar.
