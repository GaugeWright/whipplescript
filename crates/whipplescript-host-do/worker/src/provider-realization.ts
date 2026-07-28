import { MODEL_AUTH_SENTINEL } from "./model-broker.ts";

export type HostedProvider =
  | "openai"
  | "openai-generic"
  | "anthropic"
  | "openai-codex";

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
  execution: "model-broker" | "direct";
  api_key: string;
}

export interface ProviderRealizationEnv {
  WHIP_MODEL_BROKER_URL?: string;
  WHIP_MODEL_BROKER_TOKEN?: string;
}

const supportedProviders = new Set<HostedProvider>([
  "openai",
  "openai-generic",
  "anthropic",
  "openai-codex",
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
  execution: "model-broker" | "direct" = "model-broker",
): ResolvedHostProviderBinding {
  validateAdmission(admission);
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
  if (!env.WHIP_MODEL_BROKER_URL?.trim() || !env.WHIP_MODEL_BROKER_TOKEN?.trim()) {
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
