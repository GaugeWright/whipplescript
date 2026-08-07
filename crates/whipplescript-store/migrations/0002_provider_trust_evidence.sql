-- DR-0062 §6: the evidence half of model trust tiers.
--
-- Its OWN table rather than a corner of `effect_providers.config_json`, and the
-- reason is circularity: the pin freezes the endpoint's CONFIG DIGEST, so
-- evidence stored inside `config_json` would mutate the very bytes it attests —
-- writing a pin would change the digest and invalidate the pin it just wrote.
-- The two also have different authority stories. `config_json` is package
-- registration territory; this table is written by day-to-day `whip provider`
-- commands, which is exactly why the DEMAND it is judged against lives in the
-- signed envelope instead of here.
--
-- Note what is deliberately absent: there is no `live_digest` column. The live
-- digest is computed from the endpoint's current configuration at resolution
-- time and never stored — a stored one would be compared against itself, and
-- drift would become undetectable. Freshness has to be recomputed to mean
-- anything (the DR-0053 stale-quote lesson).
--
-- Also absent: any column for what configuration CLAIMS the custody class is.
-- Configuration is not evidence; giving it no column is how that is enforced.
CREATE TABLE provider_trust_evidence (
    effect_kind TEXT NOT NULL,
    provider TEXT NOT NULL,

    -- Rung evidence: the digest frozen by `whip provider pin`. NULL = never
    -- pinned, which is the floor and cannot be missing.
    pinned_digest TEXT,

    -- Custody evidence: a filed claim. `c1`-`c3` are testimony — whip cannot
    -- verify a retention claim — so the signer rides with it for the audit
    -- trail, and the term is mandatory. A claim with no end date is precisely
    -- the thing that rots: contracts get renegotiated and nobody revisits the
    -- registry row.
    claim_class TEXT,
    claim_signer TEXT,
    claim_filed_at TEXT,
    claim_expires_at TEXT,

    -- The one self-checkable class (c4 operator-held): whip supervises the
    -- endpoint. Not testimony, so it carries no signer and no expiry.
    operator_run INTEGER NOT NULL DEFAULT 0,

    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (effect_kind, provider),

    -- Testimony expires; a filed claim without a term is refused at write time
    -- rather than silently treated as perpetual.
    CHECK (claim_class IS NULL OR (claim_signer IS NOT NULL AND claim_expires_at IS NOT NULL))
);
