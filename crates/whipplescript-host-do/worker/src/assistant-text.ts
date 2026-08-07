/**
 * The durable assistant message for a settled turn.
 *
 * The runtime's `assistant_text` is authoritative *when it says something*. It
 * is a Rust `String`, so it is always present and an absent answer arrives as
 * `""` rather than as `undefined` — and a turn whose last assistant message
 * carried tool calls leaves it empty by construction (`host_projection.rs` only
 * assigns it when `calls.is_empty()`). Selecting with `??` therefore chose that
 * empty string over text the provider had actually streamed, wrote nothing, and
 * advanced the delta cursor so the streamed copy was consumed and lost: the
 * reader watched an answer arrive and then vanish at settle.
 *
 * Falling back on emptiness rather than on `undefined` is the whole fix.
 */
export function selectAssistantText(
  authoritativeText: string | undefined,
  streamed: string,
): string {
  return authoritativeText && authoritativeText.length > 0 ? authoritativeText : streamed;
}
