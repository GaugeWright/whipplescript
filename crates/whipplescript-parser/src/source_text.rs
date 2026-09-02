//! Text the AST holds on to, paired — in ONE value — with whether that text is
//! still the file's bytes and where they start.
//!
//! Every precise diagnostic in the compiler resolves an offset measured against
//! a fragment of text into a file position. That resolution is sound only while
//! the text IS the file's bytes: the moment a pass rewrites it (pattern
//! substitution, an alpha-renamed reprint, `then`/action expansion) an offset
//! into the new text names a token in the old one, and a caret placed on it
//! underlines whatever happens to be there.
//!
//! The fact and the text therefore live in one place, with private fields, in a
//! module that is not the one doing the rewriting. Rewriting is a METHOD, so
//! "set the text and forget the origin" is not a thing that can be written —
//! not a thing that must be remembered. It had to be remembered twice, and was
//! forgotten once each time: `BlockSource`'s text (tracker D2d) and then
//! `WhenClause::text`/`AssertDecl::expr` (D10).

use std::borrow::Borrow;
use std::fmt;
use std::ops::Deref;

use crate::SourceSpan;

use crate::body::{self, BodyLineMap};

/// Whether a [`SourceText`]'s bytes are still a slice of the file, and where.
///
/// Keeping only the text and the enclosing span loses the one fact every
/// precise diagnostic needs: where `text[0]` lives. Consumers used to
/// reconstruct it — from `span.start` (short by `1 + leading whitespace`) or
/// from `span.end - (2 + text.len())` (wrong whenever the closing `}` is not
/// preceded by exactly one newline) — and every reconstruction was wrong in
/// some program.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BodyOrigin {
    /// `text` is a verbatim slice of the file beginning at this byte offset.
    Source(usize),
    /// `text` was assembled by a line-based rewriter (`then` expansion, action
    /// inlining, region surgery) that copied most of its input verbatim. The
    /// map says which output lines are still the file's bytes and where they
    /// live; an offset anywhere else degrades to the enclosing span.
    Mapped(BodyLineMap),
    /// `text` was synthesized or rewritten token-by-token (pattern
    /// substitution, an alpha-renamed reprint, a lowered `table`), so no offset
    /// into it is a source position.
    Generated,
}

/// A string the compiler both READS as program text and RESOLVES offsets
/// against, carrying its own provenance.
///
/// Deref to `str` on purpose: every consumer that only wants to read the
/// program text keeps reading it unchanged, and only the handful of sites that
/// WRITE have to say which kind of write they are making. Reading is the
/// common case and is never unsafe; writing is the rare case and is exactly
/// where the bug lives.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceText {
    text: String,
    origin: BodyOrigin,
}

impl SourceText {
    /// Text that is `source[at..at + text.len()]` verbatim.
    ///
    /// The caller asserts the two agree, and recording that assertion is the
    /// whole point: `span.len() == text.len()` also holds by coincidence for a
    /// synthesized fragment, and a caret placed on a coincidence underlines
    /// whatever happens to be there.
    pub fn from_file(text: String, at: usize) -> Self {
        Self {
            text,
            origin: BodyOrigin::Source(at),
        }
    }

    /// Text that was synthesized: no offset into it is a source position.
    pub fn generated(text: String) -> Self {
        Self {
            text,
            origin: BodyOrigin::Generated,
        }
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The text alone, for a consumer that stores program text and never asks
    /// where it came from (the IR, a report, a hash).
    pub fn into_string(self) -> String {
        self.text
    }

    pub fn origin(&self) -> &BodyOrigin {
        &self.origin
    }

    /// The file offset of `text[0]` while the whole text is a verbatim slice of
    /// the file, `None` otherwise.
    ///
    /// Deliberately `None` for `Mapped`: a caller that wants a single base for
    /// the whole fragment has nowhere to put a per-line map, and answering with
    /// the first line's origin would be the reconstruction this type exists to
    /// delete. Such a caller degrades; a caller that can carry the map uses
    /// [`SourceText::body_base`].
    pub fn file_offset(&self) -> Option<usize> {
        match self.origin {
            BodyOrigin::Source(start) => Some(start),
            BodyOrigin::Mapped(_) | BodyOrigin::Generated => None,
        }
    }

    /// The base to hand [`body::parse_rule_body`], so no AST span is a lie.
    pub fn body_base(&self, fallback: SourceSpan) -> body::BodyBase<'_> {
        match &self.origin {
            BodyOrigin::Source(start) => body::BodyBase::Source(*start),
            BodyOrigin::Mapped(map) => body::BodyBase::Mapped { map, fallback },
            BodyOrigin::Generated => body::BodyBase::Generated(fallback),
        }
    }

    /// The file offset a byte offset into the CURRENT text names, or `None`
    /// when the text has no source position for it.
    fn source_offset(&self, offset: usize) -> Option<usize> {
        match &self.origin {
            BodyOrigin::Source(start) => Some(start + offset),
            BodyOrigin::Mapped(map) => map.source_offset(offset),
            BodyOrigin::Generated => None,
        }
    }

    /// Replace the text, downgrading the origin unless the rewrite was a no-op.
    ///
    /// A no-op keeps the origin because a rewrite that produced byte-identical
    /// text left the file's bytes in place — a pattern whose substitutions do
    /// not appear in a particular clause keeps its precise carets.
    pub fn rewrite(&mut self, text: String) {
        if text != self.text {
            self.text = text;
            self.origin = BodyOrigin::Generated;
        }
    }

    /// Replace the text with a rewrite the caller guarantees is byte-for-byte
    /// positionally identical — same length, same offsets, different bytes.
    ///
    /// One caller: blanking full-line comments to spaces, which is done exactly
    /// so that every downstream span keeps pointing at the source. The
    /// assertion is what stops that guarantee from being claimed falsely; a
    /// length change is the only failure mode a check can see, and it is the
    /// one that actually happens.
    pub fn rewrite_byte_preserving(&mut self, text: String) {
        debug_assert_eq!(
            text.len(),
            self.text.len(),
            "rewrite_byte_preserving changed the length, so every offset into \
             this text moved; use rewrite() instead"
        );
        if text.len() == self.text.len() {
            self.text = text;
        } else {
            self.rewrite(text);
        }
    }

    /// Replace the text with a line-based rewriter's output, carrying its
    /// per-output-line provenance.
    ///
    /// `input_offsets` holds one entry per line of `text`: the byte offset in
    /// the CURRENT text of the line those bytes were copied from, or `None` for
    /// a line the rewriter generated. Resolving each of those through the
    /// origin the text already has IS the composition — action inlining, then
    /// `then` expansion, then region surgery each report offsets into the text
    /// they were handed, so the maps never have to be composed with each other
    /// and a body may be rewritten any number of times without drifting.
    pub fn rewrite_mapped(&mut self, text: String, input_offsets: Vec<Option<usize>>) {
        if text == self.text {
            return;
        }
        let resolved = input_offsets
            .into_iter()
            .map(|offset| offset.and_then(|offset| self.source_offset(offset)))
            .collect();
        self.origin = match BodyLineMap::new(&text, resolved) {
            Some(map) => BodyOrigin::Mapped(map),
            None => BodyOrigin::Generated,
        };
        self.text = text;
    }
}

impl Deref for SourceText {
    type Target = str;

    fn deref(&self) -> &str {
        &self.text
    }
}

impl AsRef<str> for SourceText {
    fn as_ref(&self) -> &str {
        &self.text
    }
}

impl Borrow<str> for SourceText {
    fn borrow(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for SourceText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

/// A braced block's source text, and the block's outer extent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockSource {
    /// The text between the braces, trimmed, with its origin.
    pub text: SourceText,
    /// The block's OUTER extent: `{` through `}` wherever the surface has
    /// braces, and the whole construct that stands in for a block where it does
    /// not (the prompt-only `coerce` sugar, a `table` lowered to a rule). It is
    /// the fallback span for anything genuinely about the block as a whole.
    ///
    /// It is NOT where `text` starts — `text` is trimmed of the brace and the
    /// surrounding whitespace. `text`'s own origin is what carries that; use
    /// [`BlockSource::span_of`] to turn a text offset into a source span.
    pub span: SourceSpan,
}

impl BlockSource {
    /// A block whose text is `source[at..at + text.len()]` verbatim.
    pub fn from_file(text: String, at: usize, span: SourceSpan) -> Self {
        Self {
            text: SourceText::from_file(text, at),
            span,
        }
    }

    /// A block whose text was synthesized: every diagnostic in it reports at
    /// `span`.
    pub fn generated(text: String, span: SourceSpan) -> Self {
        Self {
            text: SourceText::generated(text),
            span,
        }
    }

    /// The base to hand [`body::parse_rule_body`], so no AST span is a lie.
    pub fn body_base(&self) -> body::BodyBase<'_> {
        self.text.body_base(self.span)
    }

    /// The source span for `text[range]`, degrading to the block span when the
    /// text has no source position for it. Never panics: the arithmetic is on
    /// byte offsets and the renderer clamps a span it cannot place.
    pub fn span_of(&self, range: std::ops::Range<usize>) -> SourceSpan {
        self.body_base().span(range.start, range.end)
    }

    /// Replace the text, downgrading the origin unless the rewrite was a no-op.
    pub fn rewrite(&mut self, text: String) {
        self.text.rewrite(text);
    }

    /// Replace the text with a line-based rewriter's output, carrying its
    /// per-output-line provenance. See [`SourceText::rewrite_mapped`].
    pub fn rewrite_mapped(&mut self, text: String, input_offsets: Vec<Option<usize>>) {
        self.text.rewrite_mapped(text, input_offsets);
    }
}
