import { MODEL_AUTH_SENTINEL } from "./model-broker.ts";

export type HostedProvider =
  | "openai"
  | "openai-generic"
  | "anthropic"
  | "openai-codex"
  /** xAI's Grok API: the Chat Completions wire, same surface as
   *  `openai-generic`, but a first-class id because the credential is an xAI
   *  key and never an OpenAI one. */
  | "xai"
  /** Metered upstream egress through a Cloudflare AI Gateway on unified
   *  billing. Distinct from `openai-generic` even though both speak the
   *  OpenAI-compatible surface, because *who pays* differs: a generic endpoint
   *  is the customer's own BYOK credential, while this is a service-held
   *  gateway token whose cost is billed onward to the deployment owner
   *  (ADR 0085 §1 "managed plan", §6). Conflating them would make funding a
   *  property of the URL. */
  | "cloudflare-ai-gateway";

export interface HostTurnAdmission {
  provider_binding_id: string;
  credential_id: string;
  placement_ceiling_ref: string;
  provider: HostedProvider;
  model: string;
  base_url: string;
}

export interface ResolvedHostProviderBinding {
  credential_id: string;
  /** Signed non-secret class used to constrain an exact public credential. */
  credential_class?: string;
  provider: HostedProvider;
  model: string;
  base_url: string;
  execution: "model-broker" | "direct" | "managed";
  api_key: string;
}

export interface ProviderRealizationEnv {
  WHIP_MODEL_BROKER_URL?: string;
  WHIP_MODEL_BROKER_TOKEN?: string;
  WHIP_MODEL_BROKER_EXECUTION_GRANT?: string;
  WHIP_MODEL_BROKER_EXECUTION_SIGNATURE?: string;
  /** The service-held AI Gateway token for managed funding. Never a customer
   *  credential and never per-deployment: one token bills GaugeWright's
   *  unified-billing credits, and the deployment owner is billed onward from
   *  metered usage rather than by holding a provider key. */
  WHIP_GATEWAY_TOKEN?: string;
}

const supportedProviders = new Set<HostedProvider>([
  "openai",
  "openai-generic",
  "anthropic",
  "openai-codex",
  "xai",
  "cloudflare-ai-gateway",
]);

function validateAdmission(admission: HostTurnAdmission): void {
  if (
    !admission.provider_binding_id.trim()
    || !admission.credential_id.trim()
    || !admission.placement_ceiling_ref.trim()
    || !supportedProviders.has(admission.provider)
    || !admission.model.trim()
    || !admission.base_url.trim()
  ) {
    throw new Error("admitted provider capability has no exact hosted realization");
  }
}

/**
 * Realize a provider only after Rust has returned the signed-policy tuple.
 * Every governed host turn uses the secret-free dynamic broker. Provider
 * credentials and deployment-wide provider maps are not Worker bindings.
 */
export function resolveAdmittedProvider(
  admission: HostTurnAdmission,
  env: ProviderRealizationEnv,
  execution: "model-broker" | "direct" | "managed" = "model-broker",
): ResolvedHostProviderBinding {
  validateAdmission(admission);
  if (execution === "managed") {
    // Managed funding: no customer provider secret exists, so there is nothing
    // to bind to a deployment. The gateway token is a Worker secret read at the
    // final fetch, exactly as a direct credential is — the difference is whose
    // money it spends, which is why this is its own execution class rather than
    // a flag on `direct`.
    if (admission.provider !== "cloudflare-ai-gateway") {
      throw new Error(
        `managed funding requires the metered gateway, not ${admission.provider}`,
      );
    }
    if (!env.WHIP_GATEWAY_TOKEN?.trim()) {
      // Loud rather than a fallback. A managed-funded session that quietly ran
      // on some other credential would bill the wrong party, which is the whole
      // failure this execution class exists to prevent.
      throw new Error("managed funding has no gateway token on this runtime");
    }
    return {
      credential_id: admission.credential_id,
      // The class the *release* declared, carried so the final-fetch boundary
      // can still check that the token it injects is the one this admission
      // asked for. There is no customer credential to match against — that check
      // is meaningless here — but the binding must stay internally coherent
      // rather than carry an empty class the fetch has to special-case.
      credential_class: admission.credential_id,
      provider: admission.provider,
      model: admission.model,
      base_url: admission.base_url,
      execution: "managed",
      api_key: MODEL_AUTH_SENTINEL,
    };
  }
  if (execution === "direct") {
    if (admission.provider === "openai-codex") {
      throw new Error("public sessions cannot receive an account OAuth credential");
    }
    return {
      credential_id: admission.credential_id,
      provider: admission.provider,
      model: admission.model,
      base_url: admission.base_url,
      execution: "direct",
      // WhippleScript/Wasm receives only this public sentinel. The actual
      // provider credential is read and injected inside
      // performDirectProviderFetch immediately before fetch.
      api_key: MODEL_AUTH_SENTINEL,
    };
  }
  const hasToken = Boolean(env.WHIP_MODEL_BROKER_TOKEN?.trim());
  const hasGrant = Boolean(
    env.WHIP_MODEL_BROKER_EXECUTION_GRANT?.trim()
      && env.WHIP_MODEL_BROKER_EXECUTION_SIGNATURE?.trim(),
  );
  if (!env.WHIP_MODEL_BROKER_URL?.trim() || (!hasToken && !hasGrant)) {
    throw new Error(`admitted provider credential ${admission.credential_id} has no model broker`);
  }
  return {
    credential_id: admission.credential_id,
    provider: admission.provider,
    model: admission.model,
    base_url: admission.base_url,
    execution: "model-broker",
    api_key: MODEL_AUTH_SENTINEL,
  };
}

/** Bind the deployment's exact public lookup reference after signed-policy
 * admission. The admitted credential id becomes the immutable class
 * constraint; it is never used as a registry fallback. */
export function bindExactPublicCredential(
  binding: ResolvedHostProviderBinding,
  exactCredentialRef: string,
): ResolvedHostProviderBinding {
  if (
    binding.execution !== "direct" ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/.test(exactCredentialRef)
  ) {
    throw new Error("public credential binding requires an exact deployment reference");
  }
  return {
    ...binding,
    credential_id: exactCredentialRef,
    credential_class: binding.credential_id,
  };
}
