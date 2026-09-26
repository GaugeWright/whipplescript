/** Short-lived provider-body capture for the privileged owning host.
 *
 * This is deliberately separate from WhippleScript observations and DO storage.
 * A fresh isolate has no captures, and settlement clears the whole turn. The
 * owning product still has to authorize and redact a read for its person.
 */

// The owning host's read transport caps a response at 32 MiB. Leave room for
// JSON framing and escaping so an accepted capture can actually be read.
const MAX_TURN_BYTES = 8 * 1024 * 1024;

export interface LiveModelCall {
  readonly ordinal: number;
  readonly body: unknown;
  /** Conservative source set supplied by the admitted turn. This does not
   * certify that arbitrary tool output has no additional source. */
  readonly source_handles: readonly string[];
  readonly provenance_complete: false;
  readonly ordered_provenance: ModelRequestProvenance | null;
}

export interface ModelContentProvenance {
  readonly source_handles: readonly string[];
  readonly complete: boolean;
}

export interface ModelRequestProvenance {
  readonly messages: readonly ModelContentProvenance[];
  readonly tools: ModelContentProvenance;
}

export interface LiveModelContextView {
  readonly calls: readonly LiveModelCall[];
  readonly incomplete: boolean;
}

interface TurnCapture {
  calls: LiveModelCall[];
  bytes: number;
  incomplete: boolean;
}

export class LiveModelContext {
  private readonly turns = new Map<string, TurnCapture>();

  record(
    turn: string,
    body: unknown,
    sourceHandles: readonly string[],
    provenance: ModelRequestProvenance | null = null,
  ): void {
    const capture = this.turns.get(turn) ?? { calls: [], bytes: 0, incomplete: false };
    this.turns.set(turn, capture);
    if (capture.incomplete) return;
    let encoded: string | undefined;
    try {
      encoded = JSON.stringify(body);
    } catch {
      capture.incomplete = true;
      return;
    }
    if (encoded === undefined) {
      capture.incomplete = true;
      return;
    }
    const bytes = new TextEncoder().encode(encoded).byteLength;
    if (capture.bytes + bytes > MAX_TURN_BYTES) {
      capture.incomplete = true;
      return;
    }
    capture.calls.push({
      ordinal: capture.calls.length,
      body: JSON.parse(encoded) as unknown,
      source_handles: [...new Set(sourceHandles)],
      provenance_complete: false,
      ordered_provenance: provenance === null
        ? null
        : JSON.parse(JSON.stringify(provenance)) as ModelRequestProvenance,
    });
    capture.bytes += bytes;
  }

  read(turn: string): LiveModelContextView | null {
    const capture = this.turns.get(turn);
    return capture
      ? { calls: capture.calls, incomplete: capture.incomplete }
      : null;
  }

  clear(turn: string): void {
    this.turns.delete(turn);
  }
}
