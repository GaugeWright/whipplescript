var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// src/index.ts
import wasmModule from "./32b91106457fc4bdc01512c0b2e42a7a0a2c3a59-whipplescript_host_do_bg.wasm";

// pkg/whipplescript_host_do_bg.js
var whipplescript_host_do_bg_exports = {};
__export(whipplescript_host_do_bg_exports, {
  WasmDurableInstance: () => WasmDurableInstance,
  __wbg___wbindgen_debug_string_c25d447a39f5578f: () => __wbg___wbindgen_debug_string_c25d447a39f5578f,
  __wbg___wbindgen_is_undefined_c05833b95a3cf397: () => __wbg___wbindgen_is_undefined_c05833b95a3cf397,
  __wbg___wbindgen_throw_344f42d3211c4765: () => __wbg___wbindgen_throw_344f42d3211c4765,
  __wbg_exec_329a6101a5cf929b: () => __wbg_exec_329a6101a5cf929b,
  __wbg_getRandomValues_cc7f052a444bb2ce: () => __wbg_getRandomValues_cc7f052a444bb2ce,
  __wbg_getTime_d6f070c088c9b5ed: () => __wbg_getTime_d6f070c088c9b5ed,
  __wbg_getTimezoneOffset_dc9862c79e5a81a3: () => __wbg_getTimezoneOffset_dc9862c79e5a81a3,
  __wbg_new_0_3da9e97f24fc69be: () => __wbg_new_0_3da9e97f24fc69be,
  __wbg_new_cc984128914cfc6f: () => __wbg_new_cc984128914cfc6f,
  __wbg_new_with_year_month_day_hr_min_sec_c04713baa3b5e1a0: () => __wbg_new_with_year_month_day_hr_min_sec_c04713baa3b5e1a0,
  __wbg_now_86c0d4ba3fa605b8: () => __wbg_now_86c0d4ba3fa605b8,
  __wbg_now_e7c6795a7f81e10f: () => __wbg_now_e7c6795a7f81e10f,
  __wbg_performance_3fcf6e32a7e1ed0a: () => __wbg_performance_3fcf6e32a7e1ed0a,
  __wbg_query_d38581f5f9f47264: () => __wbg_query_d38581f5f9f47264,
  __wbg_set_wasm: () => __wbg_set_wasm,
  __wbg_static_accessor_GLOBAL_4ef717fb391d88b7: () => __wbg_static_accessor_GLOBAL_4ef717fb391d88b7,
  __wbg_static_accessor_GLOBAL_THIS_8d1badc68b5a74f4: () => __wbg_static_accessor_GLOBAL_THIS_8d1badc68b5a74f4,
  __wbg_static_accessor_SELF_146583524fe1469b: () => __wbg_static_accessor_SELF_146583524fe1469b,
  __wbg_static_accessor_WINDOW_f2829a2234d7819e: () => __wbg_static_accessor_WINDOW_f2829a2234d7819e,
  __wbindgen_cast_0000000000000001: () => __wbindgen_cast_0000000000000001,
  __wbindgen_cast_0000000000000002: () => __wbindgen_cast_0000000000000002,
  __wbindgen_init_externref_table: () => __wbindgen_init_externref_table,
  host_begin_turn: () => host_begin_turn,
  host_cancel_turn: () => host_cancel_turn,
  host_current_position: () => host_current_position,
  host_export_thread: () => host_export_thread,
  host_import_fork: () => host_import_fork,
  host_open_instance: () => host_open_instance,
  host_project_turn: () => host_project_turn,
  host_validate_turn: () => host_validate_turn,
  verify_host_policy: () => verify_host_policy
});
var WasmDurableInstance = class _WasmDurableInstance {
  static {
    __name(this, "WasmDurableInstance");
  }
  static __wrap(ptr) {
    const obj = Object.create(_WasmDurableInstance.prototype);
    obj.__wbg_ptr = ptr;
    WasmDurableInstanceFinalization.register(obj, obj.__wbg_ptr, obj);
    return obj;
  }
  __destroy_into_raw() {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    WasmDurableInstanceFinalization.unregister(this);
    return ptr;
  }
  free() {
    const ptr = this.__destroy_into_raw();
    wasm.__wbg_wasmdurableinstance_free(ptr, 0);
  }
  /**
   * Attach to an instance already opened through `host_open_instance` and
   * drive its queued governed turns. Package bytes are resolved through the
   * same placement-neutral package implementation used during admission.
   * @param {any} bridge
   * @param {string} instance_id
   * @param {string} package_manifest
   * @param {string} package_source
   * @param {string} system_prompt
   * @param {string | null} [agent_config_json]
   * @returns {WasmDurableInstance}
   */
  static attach_host(bridge, instance_id, package_manifest, package_source, system_prompt, agent_config_json) {
    const ptr0 = passStringToWasm0(instance_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(package_manifest, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(package_source, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(system_prompt, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    var ptr4 = isLikeNone(agent_config_json) ? 0 : passStringToWasm0(agent_config_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len4 = WASM_VECTOR_LEN;
    const ret = wasm.wasmdurableinstance_attach_host(bridge, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return _WasmDurableInstance.__wrap(ret[0]);
  }
  /**
   * Capture a restorable checkpoint (P3 — the DO operator command). Returns
   * the checkpoint report as JSON, or a JS error if the instance is not
   * quiescent.
   * @param {string} cut_id
   * @returns {string}
   */
  checkpoint(cut_id) {
    let deferred3_0;
    let deferred3_1;
    try {
      const ptr0 = passStringToWasm0(cut_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
      const len0 = WASM_VECTOR_LEN;
      const ret = wasm.wasmdurableinstance_checkpoint(this.__wbg_ptr, ptr0, len0);
      var ptr2 = ret[0];
      var len2 = ret[1];
      if (ret[3]) {
        ptr2 = 0;
        len2 = 0;
        throw takeFromExternrefTable0(ret[2]);
      }
      deferred3_0 = ptr2;
      deferred3_1 = len2;
      return getStringFromWasm0(ptr2, len2);
    } finally {
      wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
  }
  /**
   * Compile `program` and create + start a fresh instance over the JS-backed DO
   * SQLite. Called once when the object is first addressed. Both config args are
   * optional and carry provider creds from DO secrets, same JSON shape
   * `{"provider":"anthropic"|"openai","base_url","api_key","model","max_tokens"}`:
   * `coerce_config_json` for `coerce` effects, `agent_config_json` for the
   * (multi-round) `agent.tell` turn. A live agent turn with tools also needs a
   * tool executor over an HTTP sidecar (the remaining async-tool seam).
   * Two further optional args wire the Class-A compute plane (P8):
   * `exec_config_json` = `{"base_url", "env"?: {NAME: value}, "environment_epoch"?,
   * "timeout_ms"?}` pointing at the executor sidecar; `scripts_json` = an
   * array of `{"name", "argv": [.., "{script}", ..], "sha256", "env"?,
   * "hermetic"?, "body"}` script capabilities registered into the DO store
   * (each body verified against its pin, fail-closed).
   * @param {any} bridge
   * @param {string} program
   * @param {string} input
   * @param {string} principal
   * @param {string | null} [coerce_config_json]
   * @param {string | null} [agent_config_json]
   * @param {string | null} [project_context_json]
   * @param {string | null} [exec_config_json]
   * @param {string | null} [scripts_json]
   * @param {string | null} [turn_config_json]
   * @returns {WasmDurableInstance}
   */
  static create(bridge, program, input, principal, coerce_config_json, agent_config_json, project_context_json, exec_config_json, scripts_json, turn_config_json) {
    const ptr0 = passStringToWasm0(program, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(input, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(principal, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    var ptr3 = isLikeNone(coerce_config_json) ? 0 : passStringToWasm0(coerce_config_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len3 = WASM_VECTOR_LEN;
    var ptr4 = isLikeNone(agent_config_json) ? 0 : passStringToWasm0(agent_config_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len4 = WASM_VECTOR_LEN;
    var ptr5 = isLikeNone(project_context_json) ? 0 : passStringToWasm0(project_context_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len5 = WASM_VECTOR_LEN;
    var ptr6 = isLikeNone(exec_config_json) ? 0 : passStringToWasm0(exec_config_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len6 = WASM_VECTOR_LEN;
    var ptr7 = isLikeNone(scripts_json) ? 0 : passStringToWasm0(scripts_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len7 = WASM_VECTOR_LEN;
    var ptr8 = isLikeNone(turn_config_json) ? 0 : passStringToWasm0(turn_config_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len8 = WASM_VECTOR_LEN;
    const ret = wasm.wasmdurableinstance_create(bridge, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5, ptr6, len6, ptr7, len7, ptr8, len8);
    if (ret[2]) {
      throw takeFromExternrefTable0(ret[1]);
    }
    return _WasmDurableInstance.__wrap(ret[0]);
  }
  /**
   * Restore the three planes to a prior checkpoint (P3 — the DO operator
   * command). Returns the restore report as JSON, or a JS error on refusal /
   * failure (a refusal mutates nothing).
   * @param {string} cut_id
   * @returns {string}
   */
  restore(cut_id) {
    let deferred3_0;
    let deferred3_1;
    try {
      const ptr0 = passStringToWasm0(cut_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
      const len0 = WASM_VECTOR_LEN;
      const ret = wasm.wasmdurableinstance_restore(this.__wbg_ptr, ptr0, len0);
      var ptr2 = ret[0];
      var len2 = ret[1];
      if (ret[3]) {
        ptr2 = 0;
        len2 = 0;
        throw takeFromExternrefTable0(ret[2]);
      }
      deferred3_0 = ptr2;
      deferred3_1 = len2;
      return getStringFromWasm0(ptr2, len2);
    } finally {
      wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
  }
  /**
   * The instance's durable status (`"running"` / `"completed"` / …).
   * @returns {string}
   */
  status() {
    let deferred2_0;
    let deferred2_1;
    try {
      const ret = wasm.wasmdurableinstance_status(this.__wbg_ptr);
      var ptr1 = ret[0];
      var len1 = ret[1];
      if (ret[3]) {
        ptr1 = 0;
        len1 = 0;
        throw takeFromExternrefTable0(ret[2]);
      }
      deferred2_0 = ptr1;
      deferred2_1 = len1;
      return getStringFromWasm0(ptr1, len1);
    } finally {
      wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
  }
  /**
   * Advance the instance one HTTP round. Pass `undefined`/`null` on the first
   * call, then the previous `needs_http` request's `fetch` result as JSON.
   * `now_unix_ms` is the host's clock (`Date.now()`), injected so the core
   * never reads wall time (DR-0033 Phase 6 — timers/deadlines resolve
   * against it, and `parked.next_due_unix_ms` names the next wake-up).
   * Returns the next `DurableStepOutcome` as JSON.
   * @param {string | null | undefined} response_json
   * @param {number} now_unix_ms
   * @returns {string}
   */
  step(response_json, now_unix_ms) {
    let deferred3_0;
    let deferred3_1;
    try {
      var ptr0 = isLikeNone(response_json) ? 0 : passStringToWasm0(response_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
      var len0 = WASM_VECTOR_LEN;
      const ret = wasm.wasmdurableinstance_step(this.__wbg_ptr, ptr0, len0, now_unix_ms);
      var ptr2 = ret[0];
      var len2 = ret[1];
      if (ret[3]) {
        ptr2 = 0;
        len2 = 0;
        throw takeFromExternrefTable0(ret[2]);
      }
      deferred3_0 = ptr2;
      deferred3_1 = len2;
      return getStringFromWasm0(ptr2, len2);
    } finally {
      wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
  }
};
if (Symbol.dispose) WasmDurableInstance.prototype[Symbol.dispose] = WasmDurableInstance.prototype.free;
function host_begin_turn(bridge, epoch, signed_envelope, expected_signer, public_key_hex, command_json, package_manifest, package_source, system_prompt, provider, model, base_url) {
  const ptr0 = passStringToWasm0(signed_envelope, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
  const len0 = WASM_VECTOR_LEN;
  const ptr1 = passStringToWasm0(expected_signer, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
  const len1 = WASM_VECTOR_LEN;
  const ptr2 = passStringToWasm0(public_key_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
  const len2 = WASM_VECTOR_LEN;
  const ptr3 = passStringToWasm0(command_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
  const len3 = WASM_VECTOR_LEN;
  const ptr4 = passStringToWasm0(package_manifest, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
  const len4 = WASM_VECTOR_LEN;
  const ptr5 = passStringToWasm0(package_source, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
  const len5 = WASM_VECTOR_LEN;
  const ptr6 = passStringToWasm0(system_prompt, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
  const len6 = WASM_VECTOR_LEN;
  const ptr7 = passStringToWasm0(provider, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
  const len7 = WASM_VECTOR_LEN;
  const ptr8 = passStringToWasm0(model, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
  const len8 = WASM_VECTOR_LEN;
  const ptr9 = passStringToWasm0(base_url, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
  const len9 = WASM_VECTOR_LEN;
  const ret = wasm.host_begin_turn(bridge, epoch, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5, ptr6, len6, ptr7, len7, ptr8, len8, ptr9, len9);
  if (ret[2]) {
    throw takeFromExternrefTable0(ret[1]);
  }
  return ret[0] !== 0;
}
__name(host_begin_turn, "host_begin_turn");
function host_cancel_turn(bridge, instance_id, command_id, requested_by) {
  let deferred5_0;
  let deferred5_1;
  try {
    const ptr0 = passStringToWasm0(instance_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(command_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(requested_by, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.host_cancel_turn(bridge, ptr0, len0, ptr1, len1, ptr2, len2);
    var ptr4 = ret[0];
    var len4 = ret[1];
    if (ret[3]) {
      ptr4 = 0;
      len4 = 0;
      throw takeFromExternrefTable0(ret[2]);
    }
    deferred5_0 = ptr4;
    deferred5_1 = len4;
    return getStringFromWasm0(ptr4, len4);
  } finally {
    wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
  }
}
__name(host_cancel_turn, "host_cancel_turn");
function host_current_position(bridge, instance_id) {
  let deferred3_0;
  let deferred3_1;
  try {
    const ptr0 = passStringToWasm0(instance_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.host_current_position(bridge, ptr0, len0);
    var ptr2 = ret[0];
    var len2 = ret[1];
    if (ret[3]) {
      ptr2 = 0;
      len2 = 0;
      throw takeFromExternrefTable0(ret[2]);
    }
    deferred3_0 = ptr2;
    deferred3_1 = len2;
    return getStringFromWasm0(ptr2, len2);
  } finally {
    wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
  }
}
__name(host_current_position, "host_current_position");
function host_export_thread(bridge, epoch, signed_envelope, expected_signer, public_key_hex, source_position_json, package_manifest, package_source, system_prompt) {
  let deferred9_0;
  let deferred9_1;
  try {
    const ptr0 = passStringToWasm0(signed_envelope, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(expected_signer, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(public_key_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(source_position_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(package_manifest, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ptr5 = passStringToWasm0(package_source, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len5 = WASM_VECTOR_LEN;
    const ptr6 = passStringToWasm0(system_prompt, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len6 = WASM_VECTOR_LEN;
    const ret = wasm.host_export_thread(bridge, epoch, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5, ptr6, len6);
    var ptr8 = ret[0];
    var len8 = ret[1];
    if (ret[3]) {
      ptr8 = 0;
      len8 = 0;
      throw takeFromExternrefTable0(ret[2]);
    }
    deferred9_0 = ptr8;
    deferred9_1 = len8;
    return getStringFromWasm0(ptr8, len8);
  } finally {
    wasm.__wbindgen_free(deferred9_0, deferred9_1, 1);
  }
}
__name(host_export_thread, "host_export_thread");
function host_import_fork(bridge, epoch, signed_envelope, expected_signer, public_key_hex, command_json, export_json, package_manifest, package_source, system_prompt) {
  let deferred10_0;
  let deferred10_1;
  try {
    const ptr0 = passStringToWasm0(signed_envelope, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(expected_signer, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(public_key_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(command_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(export_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ptr5 = passStringToWasm0(package_manifest, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len5 = WASM_VECTOR_LEN;
    const ptr6 = passStringToWasm0(package_source, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len6 = WASM_VECTOR_LEN;
    const ptr7 = passStringToWasm0(system_prompt, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len7 = WASM_VECTOR_LEN;
    const ret = wasm.host_import_fork(bridge, epoch, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5, ptr6, len6, ptr7, len7);
    var ptr9 = ret[0];
    var len9 = ret[1];
    if (ret[3]) {
      ptr9 = 0;
      len9 = 0;
      throw takeFromExternrefTable0(ret[2]);
    }
    deferred10_0 = ptr9;
    deferred10_1 = len9;
    return getStringFromWasm0(ptr9, len9);
  } finally {
    wasm.__wbindgen_free(deferred10_0, deferred10_1, 1);
  }
}
__name(host_import_fork, "host_import_fork");
function host_open_instance(bridge, epoch, signed_envelope, expected_signer, public_key_hex, command_json, package_manifest, package_source, system_prompt) {
  let deferred9_0;
  let deferred9_1;
  try {
    const ptr0 = passStringToWasm0(signed_envelope, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(expected_signer, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(public_key_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(command_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(package_manifest, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ptr5 = passStringToWasm0(package_source, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len5 = WASM_VECTOR_LEN;
    const ptr6 = passStringToWasm0(system_prompt, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len6 = WASM_VECTOR_LEN;
    const ret = wasm.host_open_instance(bridge, epoch, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5, ptr6, len6);
    var ptr8 = ret[0];
    var len8 = ret[1];
    if (ret[3]) {
      ptr8 = 0;
      len8 = 0;
      throw takeFromExternrefTable0(ret[2]);
    }
    deferred9_0 = ptr8;
    deferred9_1 = len8;
    return getStringFromWasm0(ptr8, len8);
  } finally {
    wasm.__wbindgen_free(deferred9_0, deferred9_1, 1);
  }
}
__name(host_open_instance, "host_open_instance");
function host_project_turn(bridge, instance_id, command_id) {
  let deferred4_0;
  let deferred4_1;
  try {
    const ptr0 = passStringToWasm0(instance_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(command_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.host_project_turn(bridge, ptr0, len0, ptr1, len1);
    var ptr3 = ret[0];
    var len3 = ret[1];
    if (ret[3]) {
      ptr3 = 0;
      len3 = 0;
      throw takeFromExternrefTable0(ret[2]);
    }
    deferred4_0 = ptr3;
    deferred4_1 = len3;
    return getStringFromWasm0(ptr3, len3);
  } finally {
    wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
  }
}
__name(host_project_turn, "host_project_turn");
function host_validate_turn(bridge, epoch, signed_envelope, expected_signer, public_key_hex, command_json, package_manifest, package_source, system_prompt) {
  let deferred9_0;
  let deferred9_1;
  try {
    const ptr0 = passStringToWasm0(signed_envelope, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(expected_signer, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(public_key_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(command_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(package_manifest, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ptr5 = passStringToWasm0(package_source, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len5 = WASM_VECTOR_LEN;
    const ptr6 = passStringToWasm0(system_prompt, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len6 = WASM_VECTOR_LEN;
    const ret = wasm.host_validate_turn(bridge, epoch, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5, ptr6, len6);
    var ptr8 = ret[0];
    var len8 = ret[1];
    if (ret[3]) {
      ptr8 = 0;
      len8 = 0;
      throw takeFromExternrefTable0(ret[2]);
    }
    deferred9_0 = ptr8;
    deferred9_1 = len8;
    return getStringFromWasm0(ptr8, len8);
  } finally {
    wasm.__wbindgen_free(deferred9_0, deferred9_1, 1);
  }
}
__name(host_validate_turn, "host_validate_turn");
function verify_host_policy(epoch, signed_envelope, expected_signer, public_key_hex) {
  let deferred5_0;
  let deferred5_1;
  try {
    const ptr0 = passStringToWasm0(signed_envelope, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(expected_signer, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(public_key_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.verify_host_policy(epoch, ptr0, len0, ptr1, len1, ptr2, len2);
    var ptr4 = ret[0];
    var len4 = ret[1];
    if (ret[3]) {
      ptr4 = 0;
      len4 = 0;
      throw takeFromExternrefTable0(ret[2]);
    }
    deferred5_0 = ptr4;
    deferred5_1 = len4;
    return getStringFromWasm0(ptr4, len4);
  } finally {
    wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
  }
}
__name(verify_host_policy, "verify_host_policy");
function __wbg___wbindgen_debug_string_c25d447a39f5578f(arg0, arg1) {
  const ret = debugString(arg1);
  const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
  const len1 = WASM_VECTOR_LEN;
  getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
  getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
}
__name(__wbg___wbindgen_debug_string_c25d447a39f5578f, "__wbg___wbindgen_debug_string_c25d447a39f5578f");
function __wbg___wbindgen_is_undefined_c05833b95a3cf397(arg0) {
  const ret = arg0 === void 0;
  return ret;
}
__name(__wbg___wbindgen_is_undefined_c05833b95a3cf397, "__wbg___wbindgen_is_undefined_c05833b95a3cf397");
function __wbg___wbindgen_throw_344f42d3211c4765(arg0, arg1) {
  throw new Error(getStringFromWasm0(arg0, arg1));
}
__name(__wbg___wbindgen_throw_344f42d3211c4765, "__wbg___wbindgen_throw_344f42d3211c4765");
function __wbg_exec_329a6101a5cf929b() {
  return handleError(function(arg0, arg1, arg2, arg3, arg4) {
    const ret = arg0.exec(getStringFromWasm0(arg1, arg2), getStringFromWasm0(arg3, arg4));
    return ret;
  }, arguments);
}
__name(__wbg_exec_329a6101a5cf929b, "__wbg_exec_329a6101a5cf929b");
function __wbg_getRandomValues_cc7f052a444bb2ce() {
  return handleError(function(arg0, arg1) {
    globalThis.crypto.getRandomValues(getArrayU8FromWasm0(arg0, arg1));
  }, arguments);
}
__name(__wbg_getRandomValues_cc7f052a444bb2ce, "__wbg_getRandomValues_cc7f052a444bb2ce");
function __wbg_getTime_d6f070c088c9b5ed(arg0) {
  const ret = arg0.getTime();
  return ret;
}
__name(__wbg_getTime_d6f070c088c9b5ed, "__wbg_getTime_d6f070c088c9b5ed");
function __wbg_getTimezoneOffset_dc9862c79e5a81a3(arg0) {
  const ret = arg0.getTimezoneOffset();
  return ret;
}
__name(__wbg_getTimezoneOffset_dc9862c79e5a81a3, "__wbg_getTimezoneOffset_dc9862c79e5a81a3");
function __wbg_new_0_3da9e97f24fc69be() {
  const ret = /* @__PURE__ */ new Date();
  return ret;
}
__name(__wbg_new_0_3da9e97f24fc69be, "__wbg_new_0_3da9e97f24fc69be");
function __wbg_new_cc984128914cfc6f(arg0) {
  const ret = new Date(arg0);
  return ret;
}
__name(__wbg_new_cc984128914cfc6f, "__wbg_new_cc984128914cfc6f");
function __wbg_new_with_year_month_day_hr_min_sec_c04713baa3b5e1a0(arg0, arg1, arg2, arg3, arg4, arg5) {
  const ret = new Date(arg0 >>> 0, arg1, arg2, arg3, arg4, arg5);
  return ret;
}
__name(__wbg_new_with_year_month_day_hr_min_sec_c04713baa3b5e1a0, "__wbg_new_with_year_month_day_hr_min_sec_c04713baa3b5e1a0");
function __wbg_now_86c0d4ba3fa605b8() {
  const ret = Date.now();
  return ret;
}
__name(__wbg_now_86c0d4ba3fa605b8, "__wbg_now_86c0d4ba3fa605b8");
function __wbg_now_e7c6795a7f81e10f(arg0) {
  const ret = arg0.now();
  return ret;
}
__name(__wbg_now_e7c6795a7f81e10f, "__wbg_now_e7c6795a7f81e10f");
function __wbg_performance_3fcf6e32a7e1ed0a(arg0) {
  const ret = arg0.performance;
  return ret;
}
__name(__wbg_performance_3fcf6e32a7e1ed0a, "__wbg_performance_3fcf6e32a7e1ed0a");
function __wbg_query_d38581f5f9f47264() {
  return handleError(function(arg0, arg1, arg2, arg3, arg4, arg5) {
    const ret = arg1.query(getStringFromWasm0(arg2, arg3), getStringFromWasm0(arg4, arg5));
    const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
    getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
  }, arguments);
}
__name(__wbg_query_d38581f5f9f47264, "__wbg_query_d38581f5f9f47264");
function __wbg_static_accessor_GLOBAL_4ef717fb391d88b7() {
  const ret = typeof global === "undefined" ? null : global;
  return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
}
__name(__wbg_static_accessor_GLOBAL_4ef717fb391d88b7, "__wbg_static_accessor_GLOBAL_4ef717fb391d88b7");
function __wbg_static_accessor_GLOBAL_THIS_8d1badc68b5a74f4() {
  const ret = typeof globalThis === "undefined" ? null : globalThis;
  return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
}
__name(__wbg_static_accessor_GLOBAL_THIS_8d1badc68b5a74f4, "__wbg_static_accessor_GLOBAL_THIS_8d1badc68b5a74f4");
function __wbg_static_accessor_SELF_146583524fe1469b() {
  const ret = typeof self === "undefined" ? null : self;
  return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
}
__name(__wbg_static_accessor_SELF_146583524fe1469b, "__wbg_static_accessor_SELF_146583524fe1469b");
function __wbg_static_accessor_WINDOW_f2829a2234d7819e() {
  const ret = typeof window === "undefined" ? null : window;
  return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
}
__name(__wbg_static_accessor_WINDOW_f2829a2234d7819e, "__wbg_static_accessor_WINDOW_f2829a2234d7819e");
function __wbindgen_cast_0000000000000001(arg0) {
  const ret = arg0;
  return ret;
}
__name(__wbindgen_cast_0000000000000001, "__wbindgen_cast_0000000000000001");
function __wbindgen_cast_0000000000000002(arg0, arg1) {
  const ret = getStringFromWasm0(arg0, arg1);
  return ret;
}
__name(__wbindgen_cast_0000000000000002, "__wbindgen_cast_0000000000000002");
function __wbindgen_init_externref_table() {
  const table = wasm.__wbindgen_externrefs;
  const offset = table.grow(4);
  table.set(0, void 0);
  table.set(offset + 0, void 0);
  table.set(offset + 1, null);
  table.set(offset + 2, true);
  table.set(offset + 3, false);
}
__name(__wbindgen_init_externref_table, "__wbindgen_init_externref_table");
var WasmDurableInstanceFinalization = typeof FinalizationRegistry === "undefined" ? { register: /* @__PURE__ */ __name(() => {
}, "register"), unregister: /* @__PURE__ */ __name(() => {
}, "unregister") } : new FinalizationRegistry((ptr) => wasm.__wbg_wasmdurableinstance_free(ptr, 1));
function addToExternrefTable0(obj) {
  const idx = wasm.__externref_table_alloc();
  wasm.__wbindgen_externrefs.set(idx, obj);
  return idx;
}
__name(addToExternrefTable0, "addToExternrefTable0");
function debugString(val) {
  const type = typeof val;
  if (type == "number" || type == "boolean" || val == null) {
    return `${val}`;
  }
  if (type == "string") {
    return `"${val}"`;
  }
  if (type == "symbol") {
    const description = val.description;
    if (description == null) {
      return "Symbol";
    } else {
      return `Symbol(${description})`;
    }
  }
  if (type == "function") {
    const name = val.name;
    if (typeof name == "string" && name.length > 0) {
      return `Function(${name})`;
    } else {
      return "Function";
    }
  }
  if (Array.isArray(val)) {
    const length = val.length;
    let debug = "[";
    if (length > 0) {
      debug += debugString(val[0]);
    }
    for (let i = 1; i < length; i++) {
      debug += ", " + debugString(val[i]);
    }
    debug += "]";
    return debug;
  }
  const builtInMatches = /\[object ([^\]]+)\]/.exec(toString.call(val));
  let className;
  if (builtInMatches && builtInMatches.length > 1) {
    className = builtInMatches[1];
  } else {
    return toString.call(val);
  }
  if (className == "Object") {
    try {
      return "Object(" + JSON.stringify(val) + ")";
    } catch (_) {
      return "Object";
    }
  }
  if (val instanceof Error) {
    return `${val.name}: ${val.message}
${val.stack}`;
  }
  return className;
}
__name(debugString, "debugString");
function getArrayU8FromWasm0(ptr, len) {
  ptr = ptr >>> 0;
  return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}
__name(getArrayU8FromWasm0, "getArrayU8FromWasm0");
var cachedDataViewMemory0 = null;
function getDataViewMemory0() {
  if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || cachedDataViewMemory0.buffer.detached === void 0 && cachedDataViewMemory0.buffer !== wasm.memory.buffer) {
    cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
  }
  return cachedDataViewMemory0;
}
__name(getDataViewMemory0, "getDataViewMemory0");
function getStringFromWasm0(ptr, len) {
  return decodeText(ptr >>> 0, len);
}
__name(getStringFromWasm0, "getStringFromWasm0");
var cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
  if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
    cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
  }
  return cachedUint8ArrayMemory0;
}
__name(getUint8ArrayMemory0, "getUint8ArrayMemory0");
function handleError(f, args) {
  try {
    return f.apply(this, args);
  } catch (e) {
    const idx = addToExternrefTable0(e);
    wasm.__wbindgen_exn_store(idx);
  }
}
__name(handleError, "handleError");
function isLikeNone(x) {
  return x === void 0 || x === null;
}
__name(isLikeNone, "isLikeNone");
function passStringToWasm0(arg, malloc, realloc) {
  if (realloc === void 0) {
    const buf = cachedTextEncoder.encode(arg);
    const ptr2 = malloc(buf.length, 1) >>> 0;
    getUint8ArrayMemory0().subarray(ptr2, ptr2 + buf.length).set(buf);
    WASM_VECTOR_LEN = buf.length;
    return ptr2;
  }
  let len = arg.length;
  let ptr = malloc(len, 1) >>> 0;
  const mem = getUint8ArrayMemory0();
  let offset = 0;
  for (; offset < len; offset++) {
    const code = arg.charCodeAt(offset);
    if (code > 127) break;
    mem[ptr + offset] = code;
  }
  if (offset !== len) {
    if (offset !== 0) {
      arg = arg.slice(offset);
    }
    ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
    const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
    const ret = cachedTextEncoder.encodeInto(arg, view);
    offset += ret.written;
    ptr = realloc(ptr, len, offset, 1) >>> 0;
  }
  WASM_VECTOR_LEN = offset;
  return ptr;
}
__name(passStringToWasm0, "passStringToWasm0");
function takeFromExternrefTable0(idx) {
  const value = wasm.__wbindgen_externrefs.get(idx);
  wasm.__externref_table_dealloc(idx);
  return value;
}
__name(takeFromExternrefTable0, "takeFromExternrefTable0");
var cachedTextDecoder = new TextDecoder("utf-8", { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
var MAX_SAFARI_DECODE_BYTES = 2146435072;
var numBytesDecoded = 0;
function decodeText(ptr, len) {
  numBytesDecoded += len;
  if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
    cachedTextDecoder = new TextDecoder("utf-8", { ignoreBOM: true, fatal: true });
    cachedTextDecoder.decode();
    numBytesDecoded = len;
  }
  return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}
__name(decodeText, "decodeText");
var cachedTextEncoder = new TextEncoder();
if (!("encodeInto" in cachedTextEncoder)) {
  cachedTextEncoder.encodeInto = function(arg, view) {
    const buf = cachedTextEncoder.encode(arg);
    view.set(buf);
    return {
      read: arg.length,
      written: buf.length
    };
  };
}
var WASM_VECTOR_LEN = 0;
var wasm;
function __wbg_set_wasm(val) {
  wasm = val;
}
__name(__wbg_set_wasm, "__wbg_set_wasm");

// node_modules/@cloudflare/containers/dist/lib/helpers.js
function generateId(length = 9) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  let result = "";
  for (let i = 0; i < length; i++) {
    result += alphabet[bytes[i] % alphabet.length];
  }
  return result;
}
__name(generateId, "generateId");
function parseTimeExpression(timeExpression) {
  if (typeof timeExpression === "number") {
    return timeExpression;
  }
  if (typeof timeExpression === "string") {
    const match = timeExpression.match(/^(\d+)([smh])$/);
    if (!match) {
      throw new Error(`invalid time expression ${timeExpression}`);
    }
    const value = parseInt(match[1]);
    const unit = match[2];
    switch (unit) {
      case "s":
        return value;
      case "m":
        return value * 60;
      case "h":
        return value * 60 * 60;
      default:
        throw new Error(`unknown time unit ${unit}`);
    }
  }
  throw new Error(`invalid type for a time expression: ${typeof timeExpression}`);
}
__name(parseTimeExpression, "parseTimeExpression");

// node_modules/@cloudflare/containers/dist/lib/container.js
import { DurableObject, WorkerEntrypoint } from "cloudflare:workers";
var NO_CONTAINER_INSTANCE_ERROR = "there is no container instance that can be provided to this durable object";
var RATE_LIMITED_ERROR = "you are requesting too many containers per second";
var RUNTIME_SIGNALLED_ERROR = "runtime signalled the container to exit:";
var UNEXPECTED_EXIT_ERROR = "container exited with unexpected exit code:";
var NOT_LISTENING_ERROR = "the container is not listening";
var CONTAINER_STATE_KEY = "__CF_CONTAINER_STATE";
var OUTBOUND_CONFIGURATION_KEY = "OUTBOUND_CONFIGURATION";
var MAX_ALARM_RETRIES = 3;
var PING_TIMEOUT_MS = 5e3;
var DEFAULT_SLEEP_AFTER = "10m";
var INSTANCE_POLL_INTERVAL_MS = 300;
var TIMEOUT_TO_GET_CONTAINER_MS = 8e3;
var TIMEOUT_TO_GET_PORTS_MS = 2e4;
var FALLBACK_PORT_TO_CHECK = 33;
var outboundHandlersRegistry = /* @__PURE__ */ new Map();
var defaultOutboundHandlerNameRegistry = /* @__PURE__ */ new Map();
var outboundByHostRegistry = /* @__PURE__ */ new Map();
var signalToNumbers = {
  SIGINT: 2,
  SIGTERM: 15,
  SIGKILL: 9
};
function isErrorOfType(e, matchingString) {
  const errorString = e instanceof Error ? e.message : String(e);
  return errorString.toLowerCase().includes(matchingString);
}
__name(isErrorOfType, "isErrorOfType");
var isNoInstanceError = /* @__PURE__ */ __name((error) => isErrorOfType(error, NO_CONTAINER_INSTANCE_ERROR), "isNoInstanceError");
var isRateLimitedError = /* @__PURE__ */ __name((error) => isErrorOfType(error, RATE_LIMITED_ERROR), "isRateLimitedError");
var isRuntimeSignalledError = /* @__PURE__ */ __name((error) => isErrorOfType(error, RUNTIME_SIGNALLED_ERROR), "isRuntimeSignalledError");
var isNotListeningError = /* @__PURE__ */ __name((error) => isErrorOfType(error, NOT_LISTENING_ERROR), "isNotListeningError");
var isContainerExitNonZeroError = /* @__PURE__ */ __name((error) => isErrorOfType(error, UNEXPECTED_EXIT_ERROR), "isContainerExitNonZeroError");
function getExitCodeFromError(error) {
  if (!(error instanceof Error)) {
    return null;
  }
  if (isRuntimeSignalledError(error)) {
    return +error.message.toLowerCase().slice(error.message.toLowerCase().indexOf(RUNTIME_SIGNALLED_ERROR) + RUNTIME_SIGNALLED_ERROR.length + 1);
  }
  if (isContainerExitNonZeroError(error)) {
    return +error.message.toLowerCase().slice(error.message.toLowerCase().indexOf(UNEXPECTED_EXIT_ERROR) + UNEXPECTED_EXIT_ERROR.length + 1);
  }
  return null;
}
__name(getExitCodeFromError, "getExitCodeFromError");
function addTimeoutSignal(existingSignal, timeoutMs) {
  const controller = new AbortController();
  if (existingSignal?.aborted) {
    controller.abort();
    return controller.signal;
  }
  existingSignal?.addEventListener("abort", () => controller.abort());
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  controller.signal.addEventListener("abort", () => clearTimeout(timeoutId));
  return controller.signal;
}
__name(addTimeoutSignal, "addTimeoutSignal");
var ContainerState = class {
  static {
    __name(this, "ContainerState");
  }
  storage;
  status;
  constructor(storage) {
    this.storage = storage;
  }
  async setRunning() {
    await this.setStatusAndupdate("running");
  }
  async setHealthy() {
    await this.setStatusAndupdate("healthy");
  }
  async setStopping() {
    await this.setStatusAndupdate("stopping");
  }
  async setStopped() {
    await this.setStatusAndupdate("stopped");
  }
  async setStoppedIfUnchanged(previousState) {
    if (this.status !== previousState) {
      return;
    }
    await this.setStopped();
  }
  async setStoppedWithCode(exitCode) {
    this.status = { status: "stopped_with_code", lastChange: Date.now(), exitCode };
    await this.update();
  }
  async getState() {
    if (!this.status) {
      const state = await this.storage.get(CONTAINER_STATE_KEY);
      if (!state) {
        this.status = {
          status: "stopped",
          lastChange: Date.now()
        };
        await this.update();
      } else {
        this.status = state;
      }
    }
    return this.status;
  }
  async setStatusAndupdate(status) {
    this.status = { status, lastChange: Date.now() };
    await this.update();
  }
  async update() {
    if (!this.status)
      throw new Error("status should be init");
    await this.storage.put(CONTAINER_STATE_KEY, this.status);
  }
};
var Container = class extends DurableObject {
  static {
    __name(this, "Container");
  }
  static get outboundByHost() {
    return outboundByHostRegistry.get(this.name);
  }
  static set outboundByHost(handlers) {
    outboundByHostRegistry.set(this.name, handlers);
  }
  static get outboundHandlers() {
    return outboundHandlersRegistry.get(this.name);
  }
  static set outboundHandlers(handlers) {
    const existing = outboundHandlersRegistry.get(this.name) ?? {};
    outboundHandlersRegistry.set(this.name, { ...existing, ...handlers });
  }
  static get outbound() {
    const handlerName = defaultOutboundHandlerNameRegistry.get(this.name);
    if (!handlerName)
      return void 0;
    return outboundHandlersRegistry.get(this.name)?.[handlerName];
  }
  static set outbound(handler) {
    const key = "__outbound__";
    const existing = outboundHandlersRegistry.get(this.name) ?? {};
    outboundHandlersRegistry.set(this.name, { ...existing, [key]: handler });
    defaultOutboundHandlerNameRegistry.set(this.name, key);
  }
  static get outboundProxies() {
    return this.outboundHandlers;
  }
  static set outboundProxies(handlers) {
    this.outboundHandlers = handlers;
  }
  static get outboundProxy() {
    return this.outbound;
  }
  static set outboundProxy(handler) {
    this.outbound = handler;
  }
  // =========================
  //     Public Attributes
  // =========================
  // Default port for the container (undefined means no default port)
  defaultPort;
  // Required ports that should be checked for availability during container startup
  // Override this in your subclass to specify ports that must be ready
  requiredPorts;
  // Timeout after which the container will sleep if no activity
  // The signal sent to the container by default is a SIGTERM.
  // The container won't get a SIGKILL if this threshold is triggered.
  sleepAfter = DEFAULT_SLEEP_AFTER;
  // Container configuration properties
  // Set these properties directly in your container instance
  envVars = {};
  entrypoint;
  enableInternet = true;
  labels = {};
  // When true, outbound HTTPS traffic from the container will be intercepted.
  // The container must trust /etc/cloudflare/certs/cloudflare-containers-ca.crt
  interceptHttps = false;
  // Hosts that are allowed to access the internet, even when enableInternet is false.
  // Useful for allowing specific domains on a per-host basis.
  allowedHosts;
  // Hosts that are denied internet access, even when enableInternet is true.
  // Also blocks hosts from being handled by the catch-all outbound handler.
  deniedHosts;
  // pingEndpoint is the host and path value that the class will use to send a request to the container and check if the
  // instance is ready.
  //
  // The user does not have to implement this route by any means,
  // but it's still useful if you want to control the path that
  // the Container class uses to send HTTP requests to.
  pingEndpoint = "ping";
  applyOutboundInterceptionPromise = Promise.resolve();
  usingInterception = false;
  // =========================
  //     PUBLIC INTERFACE
  // =========================
  constructor(ctx, env, options) {
    super(ctx, env);
    if (ctx.container === void 0) {
      throw new Error("Containers have not been enabled for this Durable Object class. Have you correctly setup your Wrangler config? More info: https://developers.cloudflare.com/containers/get-started/#configuration");
    }
    this.state = new ContainerState(this.ctx.storage);
    const persistedOutboundConfiguration = this.restoreOutboundConfiguration();
    this.ctx.blockConcurrencyWhile(async () => {
      await this.scheduleNextAlarm();
      this.renewActivityTimeout();
      const ctor = this.constructor;
      if (persistedOutboundConfiguration !== void 0 || ctor.outboundByHost !== void 0 || ctor.outbound !== void 0 || ctor.outboundHandlers !== void 0 || this.effectiveAllowedHosts !== void 0 || this.effectiveDeniedHosts !== void 0) {
        this.usingInterception = true;
      }
      if (this.container.running) {
        this.applyOutboundInterceptionPromise = this.applyOutboundInterception();
      }
    });
    this.container = ctx.container;
    if (options) {
      if (options.defaultPort !== void 0)
        this.defaultPort = options.defaultPort;
      if (options.sleepAfter !== void 0)
        this.sleepAfter = options.sleepAfter;
      if (options.envVars !== void 0)
        this.envVars = options.envVars;
      if (options.entrypoint !== void 0)
        this.entrypoint = options.entrypoint;
      if (options.enableInternet !== void 0)
        this.enableInternet = options.enableInternet;
    }
    this.sql`
      CREATE TABLE IF NOT EXISTS container_schedules (
        id TEXT PRIMARY KEY NOT NULL DEFAULT (randomblob(9)),
        callback TEXT NOT NULL,
        payload TEXT,
        type TEXT NOT NULL CHECK(type IN ('scheduled', 'delayed')),
        time INTEGER NOT NULL,
        delayInSeconds INTEGER,
        created_at INTEGER DEFAULT (unixepoch())
      )
    `;
    if (this.container.running) {
      this.monitor = this.container.monitor();
      this.setupMonitorCallbacks();
    }
  }
  /**
   * Gets the current state of the container
   * @returns Promise<State>
   */
  async getState() {
    return { ...await this.state.getState() };
  }
  // ====================================
  //     OUTBOUND INTERCEPTION CONFIG
  // ====================================
  /**
   * Set the catch-all outbound handler to a named method from `outboundHandlers`.
   * Overrides the default `outbound` at runtime via ContainerProxy props.
   *
   * @param methodName - Name of a method defined in `static outboundHandlers`
   * @param params - Optional params passed to the handler as `ctx.params`
   * @throws Error if the method name is not found in `outboundHandlers`
   */
  async setOutboundHandler(methodName, ...paramsArg) {
    this.validateOutboundHandlerMethodName(methodName);
    this.outboundHandlerOverride = paramsArg.length === 0 ? { method: methodName } : { method: methodName, params: paramsArg[0] };
    await this.refreshOutboundInterception();
  }
  /**
   * Add or override a hostname-specific outbound handler at runtime,
   * referencing a named method from `outboundHandlers`.
   * Overrides any matching entry in `static outboundByHost` for this hostname.
   *
   * @param hostname - The hostname or ip:port to intercept (e.g. `'google.com'`)
   * @param methodName - Name of a method defined in `static outboundHandlers`
   * @param params - Optional params passed to the handler as `ctx.params`
   * @throws Error if the method name is not found in `outboundHandlers`
   */
  async setOutboundByHost(hostname, methodName, ...paramsArg) {
    this.validateOutboundHandlerMethodName(methodName);
    this.outboundByHostOverrides[hostname] = paramsArg.length === 0 ? { method: methodName } : { method: methodName, params: paramsArg[0] };
    await this.refreshOutboundInterception();
  }
  /**
   * Remove a runtime hostname override added via `setOutboundByHost`.
   * The default handler from `static outboundByHost` (if any) will be used again.
   *
   * @param hostname - The hostname or ip:port to stop overriding
   */
  async removeOutboundByHost(hostname) {
    delete this.outboundByHostOverrides[hostname];
    await this.refreshOutboundInterception();
  }
  /**
   * Replace all runtime hostname overrides at once.
   * Each value may be either a method name or an object with `method` and `params`.
   *
   * @param handlers - Record mapping hostnames to handler configs in `outboundHandlers`
   * @throws Error if any method name is not found in `outboundHandlers`
   */
  async setOutboundByHosts(handlers) {
    for (const handler of Object.values(handlers)) {
      const methodName = typeof handler === "string" ? handler : handler.method;
      this.validateOutboundHandlerMethodName(methodName);
    }
    this.outboundByHostOverrides = Object.fromEntries(Object.entries(handlers).map(([hostname, handler]) => [
      hostname,
      typeof handler === "string" ? { method: handler } : handler
    ]));
    await this.refreshOutboundInterception();
  }
  // ====================================
  //     ALLOWED / DENIED HOSTS CONFIG
  // ====================================
  /**
   * Replace all allowed hosts at runtime.
   * Allowed hosts get internet access even when `enableInternet` is false.
   *
   * @param hosts - Array of hostnames to allow (e.g. `['api.stripe.com', 'example.com']`)
   */
  async setAllowedHosts(hosts) {
    this.allowedHostsOverride = [...hosts];
    this.usingInterception = true;
    await this.refreshOutboundInterception();
  }
  /**
   * Replace all denied hosts at runtime.
   * Denied hosts are blocked unconditionally, even when `enableInternet` is true
   * or a catch-all outbound handler is set.
   *
   * @param hosts - Array of hostnames to deny (e.g. `['evil.com', 'blocked.org']`)
   */
  async setDeniedHosts(hosts) {
    this.deniedHostsOverride = [...hosts];
    this.usingInterception = true;
    await this.refreshOutboundInterception();
  }
  /**
   * Add a single hostname to the allowed hosts list at runtime.
   *
   * @param hostname - The hostname to allow (e.g. `'api.stripe.com'`)
   */
  async allowHost(hostname) {
    const effective = this.effectiveAllowedHosts ?? [];
    if (!effective.includes(hostname)) {
      this.allowedHostsOverride = [...effective, hostname];
    }
    this.usingInterception = true;
    await this.refreshOutboundInterception();
  }
  /**
   * Add a single hostname to the denied hosts list at runtime.
   *
   * @param hostname - The hostname to deny (e.g. `'evil.com'`)
   */
  async denyHost(hostname) {
    const effective = this.effectiveDeniedHosts ?? [];
    if (!effective.includes(hostname)) {
      this.deniedHostsOverride = [...effective, hostname];
    }
    this.usingInterception = true;
    await this.refreshOutboundInterception();
  }
  /**
   * Remove a hostname from the allowed hosts list.
   *
   * @param hostname - The hostname to remove from the allow list
   */
  async removeAllowedHost(hostname) {
    this.allowedHostsOverride = (this.effectiveAllowedHosts ?? []).filter((h) => h !== hostname);
    await this.refreshOutboundInterception();
  }
  /**
   * Remove a hostname from the denied hosts list.
   *
   * @param hostname - The hostname to remove from the deny list
   */
  async removeDeniedHost(hostname) {
    this.deniedHostsOverride = (this.effectiveDeniedHosts ?? []).filter((h) => h !== hostname);
    await this.refreshOutboundInterception();
  }
  // ==========================
  //     CONTAINER STARTING
  // ==========================
  /**
   * Start the container if it's not running and set up monitoring and lifecycle hooks,
   * without waiting for ports to be ready.
   *
   * It will automatically retry if the container fails to start, using the specified waitOptions
   *
   *
   * @example
   * await this.start({
   *   envVars: { DEBUG: 'true', NODE_ENV: 'development' },
   *   entrypoint: ['npm', 'run', 'dev'],
   *   enableInternet: false,
   *   labels: { tenant: 'acme', env: 'prod' },
   * });
   *
   * @param startOptions - Override `envVars`, `entrypoint`, `enableInternet` and `labels` on a per-instance basis
   * @param waitOptions - Optional wait configuration with abort signal for cancellation. Default ~8s timeout.
   * @returns A promise that resolves when the container start command has been issued
   * @throws Error if no container context is available or if all start attempts fail
   */
  async start(startOptions, waitOptions) {
    const portToCheck = waitOptions?.portToCheck ?? this.defaultPort ?? (this.requiredPorts ? this.requiredPorts[0] : FALLBACK_PORT_TO_CHECK);
    const pollInterval = waitOptions?.waitInterval ?? INSTANCE_POLL_INTERVAL_MS;
    await this.startContainerIfNotRunning({
      signal: waitOptions?.signal,
      waitInterval: pollInterval,
      retries: waitOptions?.retries ?? Math.ceil(TIMEOUT_TO_GET_CONTAINER_MS / pollInterval),
      portToCheck
    }, startOptions);
    this.setupMonitorCallbacks();
    await this.ctx.blockConcurrencyWhile(async () => {
      await this.onStart();
    });
  }
  async startAndWaitForPorts(portsOrArgs, cancellationOptions, startOptions) {
    let ports;
    let resolvedCancellationOptions;
    let resolvedStartOptions;
    if (typeof portsOrArgs === "object" && portsOrArgs !== null && !Array.isArray(portsOrArgs)) {
      ports = portsOrArgs.ports;
      resolvedCancellationOptions = portsOrArgs.cancellationOptions;
      resolvedStartOptions = portsOrArgs.startOptions;
    } else {
      ports = portsOrArgs;
      resolvedCancellationOptions = cancellationOptions;
      resolvedStartOptions = startOptions;
    }
    const portsToCheck = await this.getPortsToCheck(ports);
    await this.syncPendingStoppedEvents();
    resolvedCancellationOptions ??= {};
    const containerGetTimeout = resolvedCancellationOptions.instanceGetTimeoutMS ?? TIMEOUT_TO_GET_CONTAINER_MS;
    const pollInterval = resolvedCancellationOptions.waitInterval ?? INSTANCE_POLL_INTERVAL_MS;
    const containerGetRetries = Math.ceil(containerGetTimeout / pollInterval);
    const waitOptions = {
      signal: resolvedCancellationOptions.abort,
      retries: containerGetRetries,
      waitInterval: pollInterval,
      portToCheck: portsToCheck[0]
    };
    const triesUsed = await this.startContainerIfNotRunning(waitOptions, resolvedStartOptions);
    const totalPortReadyTries = Math.ceil((resolvedCancellationOptions.portReadyTimeoutMS ?? TIMEOUT_TO_GET_PORTS_MS) / pollInterval);
    let triesLeft = totalPortReadyTries - triesUsed;
    for (const port of portsToCheck) {
      triesLeft = await this.waitForPort({
        signal: resolvedCancellationOptions.abort,
        waitInterval: pollInterval,
        retries: triesLeft,
        portToCheck: port
      });
    }
    this.setupMonitorCallbacks();
    await this.ctx.blockConcurrencyWhile(async () => {
      await this.state.setHealthy();
      await this.onStart();
    });
  }
  /**
   *
   * Waits for a specified port to be ready
   *
   * Returns the number of tries used to get the port, or throws if it couldn't get the port within the specified retry limits.
   *
   * @param waitOptions -
   * - `portToCheck`: The port number to check
   * - `abort`: Optional AbortSignal to cancel waiting
   * - `retries`: Number of retries before giving up (default: TRIES_TO_GET_PORTS)
   * - `waitInterval`: Interval between retries in milliseconds (default: INSTANCE_POLL_INTERVAL_MS)
   */
  async waitForPort(waitOptions) {
    const port = waitOptions.portToCheck;
    const tcpPort = this.container.getTcpPort(port);
    const abortedSignal = new Promise((res) => {
      waitOptions.signal?.addEventListener("abort", () => {
        res(true);
      });
    });
    const pollInterval = waitOptions.waitInterval ?? INSTANCE_POLL_INTERVAL_MS;
    const tries = waitOptions.retries ?? Math.ceil(TIMEOUT_TO_GET_PORTS_MS / pollInterval);
    for (let i = 0; i < tries; i++) {
      try {
        const combinedSignal = addTimeoutSignal(waitOptions.signal, PING_TIMEOUT_MS);
        await tcpPort.fetch(`http://${this.pingEndpoint}`, { signal: combinedSignal });
        break;
      } catch (e) {
        const errorMessage = e instanceof Error ? e.message : String(e);
        if (!this.container.running) {
          try {
            await this.onError(new Error(`Container crashed while checking for ports, did you start the container and setup the entrypoint correctly?`));
          } catch {
          }
          throw e;
        }
        if (i === tries - 1) {
          try {
            await this.onError(`Failed to verify port ${port} is available after ${(i + 1) * pollInterval}ms, last error: ${errorMessage}`);
          } catch {
          }
          throw e;
        }
        await Promise.any([
          new Promise((resolve) => setTimeout(resolve, pollInterval)),
          abortedSignal
        ]);
        if (waitOptions.signal?.aborted) {
          throw new Error("Container request aborted.", { cause: e });
        }
      }
    }
    return tries;
  }
  // =======================
  //     LIFECYCLE HOOKS
  // =======================
  /**
   * Send a signal to the container.
   * @param signal - The signal to send to the container (default: 15 for SIGTERM)
   */
  async stop(signal = "SIGTERM") {
    if (this.container.running) {
      this.container.signal(typeof signal === "string" ? signalToNumbers[signal] : signal);
    }
    await this.syncPendingStoppedEvents();
  }
  /**
   * Destroys the container with a SIGKILL. Triggers onStop.
   */
  async destroy() {
    await this.container.destroy();
  }
  /**
   * Lifecycle method called when container starts successfully
   * Override this method in subclasses to handle container start events
   */
  onStart() {
  }
  /**
   * Lifecycle method called when container shuts down
   * Override this method in subclasses to handle Container stopped events
   * @param params - Object containing exitCode and reason for the stop
   */
  onStop(params) {
    void params;
  }
  /**
   * Lifecycle method called when the container is running, and the activity timeout
   * expiration (set by `sleepAfter`) has been reached.
   *
   * If you want to shutdown the container, you should call this.stop() here
   *
   * By default, this method calls `this.stop()`
   */
  async onActivityExpired() {
    console.log("Activity expired, signalling container to stop");
    if (!this.container.running) {
      return;
    }
    await this.stop();
  }
  /**
   * Error handler for container errors
   * Override this method in subclasses to handle container errors
   * @param error - The error that occurred
   * @returns Can return any value or throw the error
   */
  onError(error) {
    console.error("Container error:", error);
    throw error;
  }
  /**
   * Renew the container's activity timeout
   *
   * Call this method whenever there is activity on the container
   */
  renewActivityTimeout() {
    const timeoutInMs = parseTimeExpression(this.sleepAfter) * 1e3;
    this.sleepAfterMs = Date.now() + timeoutInMs;
  }
  /**
   * Decrement the inflight request counter.
   * When the counter transitions to 0, renew the activity timeout so the
   * inactivity window starts fresh from the moment the last request completes.
   */
  decrementInflight() {
    this.inflightRequests = Math.max(0, this.inflightRequests - 1);
    if (this.inflightRequests === 0) {
      this.renewActivityTimeout();
    }
  }
  // ==================
  //     SCHEDULING
  // ==================
  /**
   * Schedule a task to be executed in the future.
   *
   * We strongly recommend using this instead of the `alarm` handler.
   *
   * @template T Type of the payload data
   * @param when When to execute the task (Date object or number of seconds delay)
   * @param callback Name of the method to call
   * @param payload Data to pass to the callback
   * @returns Schedule object representing the scheduled task
   */
  async schedule(when, callback, payload) {
    const id = generateId(9);
    if (typeof callback !== "string") {
      throw new Error("Callback must be a string (method name)");
    }
    if (typeof this[callback] !== "function") {
      throw new Error(`this.${callback} is not a function`);
    }
    if (when instanceof Date) {
      const timestamp = Math.floor(when.getTime() / 1e3);
      this.sql`
        INSERT OR REPLACE INTO container_schedules (id, callback, payload, type, time)
        VALUES (${id}, ${callback}, ${JSON.stringify(payload)}, 'scheduled', ${timestamp})
      `;
      await this.scheduleNextAlarm();
      return {
        taskId: id,
        callback,
        payload,
        time: timestamp,
        type: "scheduled"
      };
    }
    if (typeof when === "number") {
      const time = Math.floor(Date.now() / 1e3 + when);
      this.sql`
        INSERT OR REPLACE INTO container_schedules (id, callback, payload, type, delayInSeconds, time)
        VALUES (${id}, ${callback}, ${JSON.stringify(payload)}, 'delayed', ${when}, ${time})
      `;
      await this.scheduleNextAlarm();
      return {
        taskId: id,
        callback,
        payload,
        delayInSeconds: when,
        time,
        type: "delayed"
      };
    }
    throw new Error("Invalid schedule type. 'when' must be a Date or number of seconds");
  }
  // ============
  //     HTTP
  // ============
  /**
   * Send a request to the container (HTTP or WebSocket) using standard fetch API signature
   *
   * This method handles HTTP requests to the container.
   *
   * WebSocket requests done outside the DO won't work until https://github.com/cloudflare/workerd/issues/2319 is addressed.
   * Until then, please use `switchPort` + `fetch()`.
   *
   * Method supports multiple signatures to match standard fetch API:
   * - containerFetch(request: Request, port?: number)
   * - containerFetch(url: string | URL, init?: RequestInit, port?: number)
   *
   * Starts the container if not already running, and waits for the target port to be ready.
   *
   * @returns A Response from the container
   */
  async containerFetch(requestOrUrl, portOrInit, portParam) {
    const { request, port } = this.requestAndPortFromContainerFetchArgs(requestOrUrl, portOrInit, portParam);
    const state = await this.state.getState();
    if (!this.container.running || state.status !== "healthy") {
      try {
        await this.startAndWaitForPorts(port, { abort: request.signal });
      } catch (e) {
        if (isNoInstanceError(e)) {
          return new Response("There is no Container instance available at this time.\nThis is likely because you have reached your max concurrent instance count (set in wrangler config) or are you currently provisioning the Container.\nIf you are deploying your Container for the first time, check your dashboard to see provisioning status, this may take a few minutes.", { status: 503 });
        }
        if (isRateLimitedError(e)) {
          return new Response(e instanceof Error ? e.message : String(e), { status: 429 });
        }
        return new Response(`Failed to start container: ${e instanceof Error ? e.message : String(e)}`, {
          status: 500
        });
      }
    }
    const tcpPort = this.container.getTcpPort(port);
    const containerUrl = request.url.replace("https:", "http:");
    this.inflightRequests++;
    try {
      this.renewActivityTimeout();
      const res = await tcpPort.fetch(containerUrl, request);
      if (res.webSocket !== null) {
        const containerWs = res.webSocket;
        const [client, server] = Object.values(new WebSocketPair());
        let settled = false;
        const settleInflight = /* @__PURE__ */ __name(() => {
          if (!settled) {
            settled = true;
            this.decrementInflight();
          }
        }, "settleInflight");
        containerWs.accept();
        server.accept();
        server.addEventListener("message", async (event) => {
          this.renewActivityTimeout();
          try {
            const data = event.data instanceof Blob ? await event.data.arrayBuffer() : event.data;
            containerWs.send(data);
          } catch {
            server.close(1011, "Failed to forward message to container");
          }
        });
        containerWs.addEventListener("message", async (event) => {
          this.renewActivityTimeout();
          try {
            const data = event.data instanceof Blob ? await event.data.arrayBuffer() : event.data;
            server.send(data);
          } catch {
            containerWs.close(1011, "Failed to forward message to client");
          }
        });
        server.addEventListener("close", (event) => {
          settleInflight();
          const code = event.code === 1005 || event.code === 1006 ? 1e3 : event.code;
          containerWs.close(code, event.reason);
        });
        containerWs.addEventListener("close", (event) => {
          settleInflight();
          const code = event.code === 1005 || event.code === 1006 ? 1e3 : event.code;
          server.close(code, event.reason);
        });
        server.addEventListener("error", () => {
          settleInflight();
          containerWs.close(1011, "Client WebSocket error");
        });
        containerWs.addEventListener("error", () => {
          settleInflight();
          server.close(1011, "Container WebSocket error");
        });
        return new Response(null, { status: res.status, webSocket: client, headers: res.headers });
      }
      if (res.body !== null) {
        const { readable, writable } = new IdentityTransformStream();
        res.body?.pipeTo(writable).finally(() => {
          this.decrementInflight();
        });
        return new Response(readable, res);
      }
      this.decrementInflight();
      return res;
    } catch (e) {
      this.decrementInflight();
      if (!(e instanceof Error)) {
        throw e;
      }
      if (e.message.includes("Network connection lost.")) {
        return new Response("Container suddenly disconnected, try again", { status: 500 });
      }
      console.error(`Error proxying request to container ${this.ctx.id}:`, e);
      return new Response(`Error proxying request to container: ${e instanceof Error ? e.message : String(e)}`, { status: 500 });
    }
  }
  /**
   *
   * Fetch handler on the Container class.
   * By default this forwards all requests to the container by calling `containerFetch`.
   * Use `switchPort` to specify which port on the container to target, or this will use `defaultPort`.
   * @param request The request to handle
   */
  async fetch(request) {
    if (this.defaultPort === void 0 && !request.headers.has("cf-container-target-port")) {
      throw new Error("No port configured for this container. Set the `defaultPort` in your Container subclass, or specify a port with `container.fetch(switchPort(request, port))`.");
    }
    let portValue = this.defaultPort;
    if (request.headers.has("cf-container-target-port")) {
      const portFromHeaders = parseInt(request.headers.get("cf-container-target-port") ?? "");
      if (isNaN(portFromHeaders)) {
        throw new Error("port value from switchPort is not a number");
      } else {
        portValue = portFromHeaders;
      }
    }
    return await this.containerFetch(request, portValue);
  }
  // ===============================
  // ===============================
  //     PRIVATE METHODS & ATTRS
  // ===============================
  // ===============================
  // ==========================
  //     PRIVATE ATTRIBUTES
  // ==========================
  container;
  // onStopCalled will be true when we are in the middle of an onStop call
  onStopCalled = false;
  state;
  monitor;
  // Coalesces concurrent calls to startContainerIfNotRunning so we never
  // call `this.container.start()` twice. Without this guard, two requests
  // racing the readiness path can both pass the `if (this.container.running)`
  // early-return (each yielding the DO input gate at storage awaits) and
  // both reach the synchronous workerd `start()`, causing the second to
  // throw "start() cannot be called on a container that is already running."
  // See https://github.com/cloudflare/containers/issues/173.
  startInFlight;
  monitoredPromise;
  sleepAfterMs = 0;
  inflightRequests = 0;
  // Outbound interception runtime overrides (passed through ContainerProxy props)
  outboundByHostOverrides = {};
  outboundHandlerOverride;
  // Only set when the user calls setAllowedHosts/setDeniedHosts at runtime
  allowedHostsOverride;
  deniedHostsOverride;
  // The runtime does not expose a way to remove outbound interceptions yet, so
  // once we promote an instance to intercept-all we must keep using it.
  hasInterceptAllRegistration = false;
  // ==========================
  //     GENERAL HELPERS
  // ==========================
  /**
   * Validates that a method name exists in the outboundHandlers registry for this class.
   * @throws Error if the method name is not found
   */
  validateOutboundHandlerMethodName(methodName) {
    const handlers = outboundHandlersRegistry.get(this.constructor.name);
    if (!handlers || !(methodName in handlers)) {
      throw new Error(`Outbound handler method '${methodName}' not found in outboundHandlers for ${this.constructor.name}`);
    }
  }
  get effectiveAllowedHosts() {
    return this.allowedHostsOverride ?? this.allowedHosts;
  }
  get effectiveDeniedHosts() {
    return this.deniedHostsOverride ?? this.deniedHosts;
  }
  getOutboundConfiguration() {
    return {
      outboundByHostOverrides: Object.keys(this.outboundByHostOverrides).length > 0 ? this.outboundByHostOverrides : void 0,
      outboundHandlerOverride: this.outboundHandlerOverride,
      allowedHosts: this.effectiveAllowedHosts,
      deniedHosts: this.effectiveDeniedHosts,
      hasInterceptAllRegistration: this.hasInterceptAllRegistration || void 0
    };
  }
  persistOutboundConfiguration(configuration) {
    this.ctx.storage.kv.put(OUTBOUND_CONFIGURATION_KEY, {
      ...configuration,
      allowedHosts: this.allowedHostsOverride,
      deniedHosts: this.deniedHostsOverride
    });
  }
  restoreOutboundConfiguration() {
    const configuration = this.ctx.storage.kv.get(OUTBOUND_CONFIGURATION_KEY);
    if (!configuration) {
      return void 0;
    }
    this.outboundHandlerOverride = void 0;
    if (configuration.outboundHandlerOverride !== void 0) {
      try {
        this.validateOutboundHandlerMethodName(configuration.outboundHandlerOverride.method);
        this.outboundHandlerOverride = configuration.outboundHandlerOverride;
      } catch (error) {
        console.warn("Ignoring invalid persisted outbound handler override:", error);
      }
    }
    this.outboundByHostOverrides = {};
    for (const [hostname, override] of Object.entries(configuration.outboundByHostOverrides ?? {})) {
      try {
        this.validateOutboundHandlerMethodName(override.method);
        this.outboundByHostOverrides[hostname] = override;
      } catch (error) {
        console.warn(`Ignoring invalid persisted outbound override for ${hostname}:`, error);
      }
    }
    this.hasInterceptAllRegistration = configuration.hasInterceptAllRegistration === true;
    if (configuration.allowedHosts) {
      this.allowedHostsOverride = configuration.allowedHosts;
    }
    if (configuration.deniedHosts) {
      this.deniedHostsOverride = configuration.deniedHosts;
    }
    return this.getOutboundConfiguration();
  }
  /**
   * Returns true if a catch-all outbound HTTP interception is needed.
   * This is the case when a static `outbound` handler or a runtime
   * `outboundHandlerOverride` (catch-all) is configured.
   * When false, we only intercept specific hosts to avoid overhead.
   */
  needsCatchAllInterception() {
    const ctor = this.constructor;
    return ctor.outbound !== void 0 || this.outboundHandlerOverride !== void 0;
  }
  hasMutableOutboundConfiguration() {
    return Object.keys(this.outboundByHostOverrides).length > 0 || this.allowedHostsOverride !== void 0 || this.deniedHostsOverride !== void 0;
  }
  shouldInterceptAllOutbound() {
    return this.hasInterceptAllRegistration || this.needsCatchAllInterception() || this.effectiveAllowedHosts !== void 0 || this.effectiveDeniedHosts !== void 0 || this.hasMutableOutboundConfiguration();
  }
  getStaticOutboundByHostKeys() {
    const ctor = this.constructor;
    return ctor.outboundByHost ? Object.keys(ctor.outboundByHost) : [];
  }
  /**
   * Collects all hostnames that need per-host outbound interception.
   * This path is only used for the narrow optimized case where outbound
   * handling is static and host-specific.
   */
  getHostsToIntercept() {
    const hosts = /* @__PURE__ */ new Set();
    const ctor = this.constructor;
    if (ctor.outboundByHost) {
      for (const hostname of Object.keys(ctor.outboundByHost)) {
        hosts.add(hostname);
      }
    }
    for (const hostname of Object.keys(this.outboundByHostOverrides)) {
      hosts.add(hostname);
    }
    return [...hosts];
  }
  async refreshOutboundInterception() {
    if (!this.usingInterception) {
      return;
    }
    this.applyOutboundInterceptionPromise = this.applyOutboundInterception();
    await this.applyOutboundInterceptionPromise;
  }
  /**
   * Applies (or re-applies) outbound HTTP interception with the current
   * default registries + runtime overrides passed through ContainerProxy props.
   *
   * Uses per-host interception only for static host-specific outbound handlers.
   * As soon as the config needs to evaluate all hosts (catch-all outbound,
   * allow/deny lists, or runtime-mutated outbound config), we promote the
   * container to intercept-all and keep it there until the instance restarts.
   *
   * When `interceptHttps` is enabled, also applies HTTPS interception:
   * - Intercept-all mode: `interceptOutboundHttps('*', ...)` for all HTTPS traffic
   * - Per-host mode: `interceptOutboundHttps(host, ...)` for each known host
   */
  async applyOutboundInterception() {
    const ctx = this.ctx;
    if (ctx.exports === void 0) {
      throw new Error("ctx.exports is undefined, please try to update your compatibility date or export ContainerProxy from the containers package in your worker entrypoint");
    }
    if (ctx.exports.ContainerProxy === void 0) {
      throw new Error("ctx.exports.ContainerProxy is undefined, export ContainerProxy from the containers package in your worker entrypoint");
    }
    const interceptAll = this.shouldInterceptAllOutbound();
    if (interceptAll) {
      this.hasInterceptAllRegistration = interceptAll;
    }
    const outboundConfiguration = this.getOutboundConfiguration();
    this.persistOutboundConfiguration(outboundConfiguration);
    const hosts = this.getHostsToIntercept();
    const props = {
      enableInternet: this.enableInternet,
      containerId: this.ctx.id.toString(),
      className: this.constructor.name,
      outboundByHostOverrides: outboundConfiguration.outboundByHostOverrides,
      outboundHandlerOverride: outboundConfiguration.outboundHandlerOverride,
      allowedHosts: outboundConfiguration.allowedHosts,
      deniedHosts: outboundConfiguration.deniedHosts,
      interceptAll
    };
    const fetcher = ctx.exports.ContainerProxy({
      props
    });
    if (interceptAll) {
      for (const host of this.getStaticOutboundByHostKeys()) {
        await this.container.interceptOutboundHttp(host, fetcher);
        if (this.interceptHttps) {
          await this.container.interceptOutboundHttps(host, fetcher);
        }
      }
      if (this.interceptHttps) {
        await this.container.interceptOutboundHttps("*", fetcher);
      }
      await this.container.interceptAllOutboundHttp(fetcher);
    } else {
      for (const host of hosts) {
        await this.container.interceptOutboundHttp(host, fetcher);
        if (this.interceptHttps) {
          await this.container.interceptOutboundHttps(host, fetcher);
        }
      }
    }
  }
  /**
   * Execute SQL queries against the Container's database
   */
  sql(strings, ...values) {
    const query = strings.reduce((acc, str, i) => acc + str + (i < values.length ? "?" : ""), "");
    return [...this.ctx.storage.sql.exec(query, ...values)];
  }
  requestAndPortFromContainerFetchArgs(requestOrUrl, portOrInit, portParam) {
    let request;
    let port;
    if (requestOrUrl instanceof Request) {
      request = requestOrUrl;
      port = typeof portOrInit === "number" ? portOrInit : void 0;
    } else {
      const url = typeof requestOrUrl === "string" ? requestOrUrl : requestOrUrl.toString();
      const init = typeof portOrInit === "number" ? {} : portOrInit || {};
      port = typeof portOrInit === "number" ? portOrInit : typeof portParam === "number" ? portParam : void 0;
      request = new Request(url, init);
    }
    port ??= this.defaultPort;
    if (port === void 0) {
      throw new Error("No port specified for container fetch. Set defaultPort or specify a port parameter.");
    }
    return { request, port };
  }
  /**
   *
   * The method prioritizes port sources in this order:
   * 1. Ports specified directly in the method call
   * 2. `requiredPorts` class property (if set)
   * 3. `defaultPort` (if neither of the above is specified)
   * 4. Falls back to port 33 if none of the above are set
   */
  async getPortsToCheck(overridePorts) {
    if (overridePorts !== void 0) {
      return Array.isArray(overridePorts) ? overridePorts : [overridePorts];
    }
    if (this.requiredPorts && this.requiredPorts.length > 0) {
      return [...this.requiredPorts];
    }
    return [this.defaultPort ?? FALLBACK_PORT_TO_CHECK];
  }
  // ===========================================
  //     CONTAINER INTERACTION & MONITORING
  // ===========================================
  /**
   * Tries to start a container if it's not already running
   * Returns the number of tries used
   */
  async startContainerIfNotRunning(waitOptions, options) {
    if (this.startInFlight) {
      return this.startInFlight;
    }
    if (this.container.running) {
      if (!this.monitor) {
        this.monitor = this.container.monitor();
      }
      return 0;
    }
    const startPromise = this.doStartContainer(waitOptions, options);
    this.startInFlight = startPromise;
    try {
      return await startPromise;
    } finally {
      if (this.startInFlight === startPromise) {
        this.startInFlight = void 0;
      }
    }
  }
  async doStartContainer(waitOptions, options) {
    const abortedSignal = new Promise((res) => {
      waitOptions.signal?.addEventListener("abort", () => {
        res(true);
      });
    });
    const pollInterval = waitOptions.waitInterval ?? INSTANCE_POLL_INTERVAL_MS;
    const totalTries = waitOptions.retries ?? Math.ceil(TIMEOUT_TO_GET_CONTAINER_MS / pollInterval);
    for (let tries = 0; tries < totalTries; tries++) {
      const envVars = options?.envVars ?? this.envVars;
      const entrypoint = options?.entrypoint ?? this.entrypoint;
      const enableInternet = options?.enableInternet ?? this.enableInternet;
      const labels = options?.labels ?? this.labels;
      const startConfig = {
        enableInternet
      };
      if (envVars && Object.keys(envVars).length > 0)
        startConfig.env = envVars;
      if (entrypoint)
        startConfig.entrypoint = entrypoint;
      if (labels && Object.keys(labels).length > 0)
        startConfig.labels = labels;
      this.renewActivityTimeout();
      const handleError2 = /* @__PURE__ */ __name(async () => {
        const err = await this.monitor?.catch((err2) => err2);
        if (typeof err === "number") {
          const toThrow = new Error(`Container exited before we could determine the container health, exit code: ${err}`);
          await this.state.setStoppedWithCode(err);
          this.monitor = void 0;
          try {
            await this.onError(toThrow);
          } catch {
          }
          throw toThrow;
        } else if (!isNoInstanceError(err)) {
          await this.state.setStopped();
          this.monitor = void 0;
          try {
            await this.onError(err);
          } catch {
          }
          throw err;
        }
      }, "handleError");
      if (tries > 0 && !this.container.running) {
        await handleError2();
      }
      await this.scheduleNextAlarm();
      if (!this.container.running) {
        await this.refreshOutboundInterception();
        this.container.start(startConfig);
        this.monitor = this.container.monitor();
        await this.state.setRunning();
      } else {
        await this.scheduleNextAlarm();
      }
      this.renewActivityTimeout();
      const port = this.container.getTcpPort(waitOptions.portToCheck);
      try {
        const combinedSignal = addTimeoutSignal(waitOptions.signal, PING_TIMEOUT_MS);
        await port.fetch("http://containerstarthealthcheck", { signal: combinedSignal });
        return tries;
      } catch (error) {
        if (isNotListeningError(error) && this.container.running) {
          return tries;
        }
        if (!this.container.running && isNotListeningError(error)) {
          await handleError2();
        }
        await Promise.any([
          new Promise((res) => setTimeout(res, waitOptions.waitInterval)),
          abortedSignal
        ]);
        if (waitOptions.signal?.aborted) {
          throw new Error("Aborted waiting for container to start as we received a cancellation signal", { cause: error });
        }
        if (totalTries === tries + 1) {
          if (error instanceof Error && error.message.includes("Network connection lost")) {
            this.ctx.abort();
          }
          await handleError2();
          await this.state.setStopped();
          this.monitor = void 0;
          throw new Error(NO_CONTAINER_INSTANCE_ERROR, { cause: error });
        }
        continue;
      }
    }
    throw new Error(`Container did not start after ${totalTries * pollInterval}ms`);
  }
  setupMonitorCallbacks() {
    const monitor = this.monitor;
    if (!monitor || this.monitoredPromise === monitor) {
      return;
    }
    this.monitoredPromise = monitor;
    monitor.then(async () => {
      await this.ctx.blockConcurrencyWhile(async () => {
        if (this.monitor === monitor) {
          await this.state.setStoppedWithCode(0);
        }
      });
    }).catch(async (error) => {
      if (this.monitor !== monitor) {
        return;
      }
      if (isNoInstanceError(error)) {
        await this.ctx.blockConcurrencyWhile(async () => {
          if (this.monitor === monitor) {
            await this.state.setStopped();
          }
        });
        return;
      }
      const exitCode = getExitCodeFromError(error);
      if (exitCode !== null) {
        await this.ctx.blockConcurrencyWhile(async () => {
          if (this.monitor === monitor) {
            await this.state.setStoppedWithCode(exitCode);
          }
        });
        return;
      }
      await this.ctx.blockConcurrencyWhile(async () => {
        if (this.monitor === monitor) {
          await this.state.setStopped();
        }
      });
      if (this.monitor !== monitor) {
        return;
      }
      try {
        await this.onError(error);
      } catch {
      }
    }).finally(() => {
      if (this.monitor !== monitor) {
        return;
      }
      this.monitoredPromise = void 0;
      this.monitor = void 0;
      if (this.timeout) {
        if (this.resolve)
          this.resolve();
        clearTimeout(this.timeout);
      }
    });
  }
  deleteSchedules(name) {
    this.sql`DELETE FROM container_schedules WHERE callback = ${name}`;
  }
  // ============================
  //     ALARMS AND SCHEDULES
  // ============================
  /**
   * Method called when an alarm fires
   * Executes any scheduled tasks that are due
   */
  async alarm(alarmProps) {
    if (alarmProps !== void 0 && alarmProps.isRetry && alarmProps.retryCount > MAX_ALARM_RETRIES) {
      const scheduleCount = Number(this.sql`SELECT COUNT(*) as count FROM container_schedules`[0]?.count) || 0;
      const hasScheduledTasks = scheduleCount > 0;
      if (hasScheduledTasks || this.container.running) {
        await this.scheduleNextAlarm();
      }
      return;
    }
    const prevAlarm = Date.now();
    await this.ctx.storage.setAlarm(prevAlarm);
    await this.ctx.storage.sync();
    const result = this.sql`
         SELECT * FROM container_schedules;
       `;
    let minTime = Date.now() + 3 * 60 * 1e3;
    const now = Date.now() / 1e3;
    for (const row of result) {
      if (row.time > now) {
        continue;
      }
      const callback = this[row.callback];
      if (!callback || typeof callback !== "function") {
        console.error(`Callback ${row.callback} not found or is not a function`);
        continue;
      }
      const schedule = this.getSchedule(row.id);
      try {
        const payload = row.payload ? JSON.parse(row.payload) : void 0;
        await callback.call(this, payload, await schedule);
      } catch (e) {
        console.error(`Error executing scheduled callback "${row.callback}":`, e);
      }
      this.sql`DELETE FROM container_schedules WHERE id = ${row.id}`;
    }
    const resultForMinTime = this.sql`
         SELECT * FROM container_schedules;
       `;
    const minTimeFromSchedules = Math.min(...resultForMinTime.map((r) => r.time * 1e3));
    if (!this.container.running) {
      await this.syncPendingStoppedEvents();
      if (resultForMinTime.length == 0) {
        await this.ctx.storage.deleteAlarm();
      } else {
        await this.ctx.storage.setAlarm(minTimeFromSchedules);
      }
      return;
    }
    if (this.isActivityExpired()) {
      await this.onActivityExpired();
      this.renewActivityTimeout();
      return;
    }
    minTime = Math.min(minTimeFromSchedules, minTime, this.sleepAfterMs);
    const timeout = Math.max(0, minTime - Date.now());
    await new Promise((resolve) => {
      this.resolve = resolve;
      if (!this.container.running) {
        resolve();
        return;
      }
      this.timeout = setTimeout(() => {
        resolve();
      }, timeout);
    });
    await this.ctx.storage.setAlarm(Date.now());
  }
  timeout;
  resolve;
  // synchronises container state with the container source of truth to process events
  async syncPendingStoppedEvents() {
    const state = await this.state.getState();
    if (!this.container.running && (state.status === "healthy" || state.status === "running")) {
      await this.callOnStop({ exitCode: 0, reason: "exit" }, state);
      return;
    }
    if (!this.container.running && state.status === "stopped_with_code") {
      await this.callOnStop({ exitCode: state.exitCode ?? 0, reason: "exit" }, state);
      return;
    }
  }
  async callOnStop(onStopParams, stateBeforeOnStop) {
    if (this.onStopCalled) {
      return;
    }
    this.onStopCalled = true;
    const promise = this.onStop(onStopParams);
    if (promise instanceof Promise) {
      await promise.finally(() => {
        this.onStopCalled = false;
      });
    } else {
      this.onStopCalled = false;
    }
    await this.state.setStoppedIfUnchanged(stateBeforeOnStop);
  }
  /**
   * Schedule the next alarm based on upcoming tasks
   */
  async scheduleNextAlarm(ms = 1e3) {
    const nextTime = ms + Date.now();
    if (this.timeout) {
      if (this.resolve)
        this.resolve();
      clearTimeout(this.timeout);
    }
    await this.ctx.storage.setAlarm(nextTime);
    await this.ctx.storage.sync();
  }
  async listSchedules(name) {
    const result = this.sql`
      SELECT * FROM container_schedules WHERE callback = ${name} LIMIT 1
    `;
    if (!result || result.length === 0) {
      return [];
    }
    return result.map(this.toSchedule);
  }
  toSchedule(schedule) {
    let payload;
    try {
      payload = JSON.parse(schedule.payload);
    } catch (e) {
      console.error(`Error parsing payload for schedule ${schedule.id}:`, e);
      payload = void 0;
    }
    if (schedule.type === "delayed") {
      return {
        taskId: schedule.id,
        callback: schedule.callback,
        payload,
        type: "delayed",
        time: schedule.time,
        delayInSeconds: schedule.delayInSeconds
      };
    }
    return {
      taskId: schedule.id,
      callback: schedule.callback,
      payload,
      type: "scheduled",
      time: schedule.time
    };
  }
  /**
   * Get a scheduled task by ID
   * @template T Type of the payload data
   * @param id ID of the scheduled task
   * @returns The Schedule object or undefined if not found
   */
  async getSchedule(id) {
    const result = this.sql`
      SELECT * FROM container_schedules WHERE id = ${id} LIMIT 1
    `;
    if (!result || result.length === 0) {
      return void 0;
    }
    const schedule = result[0];
    return this.toSchedule(schedule);
  }
  isActivityExpired() {
    if (this.inflightRequests > 0) {
      this.renewActivityTimeout();
      return false;
    }
    return this.sleepAfterMs <= Date.now();
  }
};

// node_modules/@cloudflare/containers/dist/lib/utils.js
async function getRandom(binding, instances = 3) {
  const id = Math.floor(Math.random() * instances).toString();
  const objectId = binding.idFromName(`instance-${id}`);
  return binding.get(objectId);
}
__name(getRandom, "getRandom");

// src/session-collection.ts
var COLLECTION_KDF_DOMAIN = "gaugewright/collection/ecies/v1";
var NONCE_LEN = 12;
function toHex(bytes) {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
__name(toHex, "toHex");
function lengthPrefixed(value) {
  const body = new TextEncoder().encode(value);
  const out = new Uint8Array(8 + body.length);
  new DataView(out.buffer).setBigUint64(0, BigInt(body.length), false);
  out.set(body, 8);
  return out;
}
__name(lengthPrefixed, "lengthPrefixed");
function concatBytes(parts) {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
__name(concatBytes, "concatBytes");
async function deriveWrappingKey(shared, components) {
  const preimage = concatBytes([
    new TextEncoder().encode(COLLECTION_KDF_DOMAIN),
    ...components.map(lengthPrefixed),
    shared
  ]);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", preimage));
}
__name(deriveWrappingKey, "deriveWrappingKey");
async function aeadSeal(key, plaintext) {
  const aesKey = await crypto.subtle.importKey("raw", key, { name: "AES-GCM" }, false, [
    "encrypt"
  ]);
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aesKey, plaintext)
  );
  return concatBytes([nonce, sealed]);
}
__name(aeadSeal, "aeadSeal");
function selectorMatches(selector, path) {
  if (selector.endsWith("/*")) {
    const prefix = selector.slice(0, -1);
    if (!path.startsWith(prefix)) return false;
    return !path.slice(prefix.length).includes("/");
  }
  return selector === path;
}
__name(selectorMatches, "selectorMatches");
function selectWorkspace(files, policy) {
  const selected = {};
  for (const [path, content] of [...files.entries()].sort()) {
    if (policy.exportable_paths.some((selector) => selectorMatches(selector, path))) {
      selected[path] = content;
    }
  }
  return selected;
}
__name(selectWorkspace, "selectWorkspace");
function canonicalArtifact(envelope, workspace, transcript) {
  const body = { envelope, workspace };
  if (transcript) body.transcript = transcript;
  return new TextEncoder().encode(JSON.stringify(body));
}
__name(canonicalArtifact, "canonicalArtifact");
function fromHex(hex) {
  if (hex.length % 2 !== 0) throw new Error("recipient key is not hex");
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}
__name(fromHex, "fromHex");
async function sealArtifact(envelope, plaintext, recipientPublicKeysHex, admissionScope) {
  if (recipientPublicKeysHex.length === 0) {
    throw new Error("collection has no admitted recipient");
  }
  const subtle = crypto.subtle;
  const dataKey = crypto.getRandomValues(new Uint8Array(32));
  const ciphertext = await aeadSeal(dataKey, plaintext);
  const pointId = `${envelope.session_id}:${envelope.revision}`;
  const wraps = [];
  for (const recipientHex of recipientPublicKeysHex) {
    const recipient = await subtle.importKey(
      "raw",
      fromHex(recipientHex),
      { name: "ECDH", namedCurve: "P-256" },
      false,
      []
    );
    const ephemeral = await subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits"]
    );
    const shared = new Uint8Array(
      await subtle.deriveBits(
        { name: "ECDH", public: recipient },
        ephemeral.privateKey,
        256
      )
    );
    const wrappingKey = await deriveWrappingKey(shared, [
      admissionScope,
      pointId,
      recipientHex
    ]);
    wraps.push({
      recipient_public_key: recipientHex,
      ephemeral_public_key: toHex(
        new Uint8Array(
          await subtle.exportKey("raw", ephemeral.publicKey)
        )
      ),
      wrapped_key: toHex(await aeadSeal(wrappingKey, dataKey))
    });
    wrappingKey.fill(0);
    shared.fill(0);
  }
  dataKey.fill(0);
  return {
    envelope,
    ciphertext: toHex(ciphertext),
    wraps,
    byte_len: plaintext.byteLength
  };
}
__name(sealArtifact, "sealArtifact");

// src/session-lifecycle.ts
var UnknownLifecycleEventError = class extends Error {
  static {
    __name(this, "UnknownLifecycleEventError");
  }
  eventType;
  constructor(eventType) {
    super(
      `unrecognized session lifecycle event type "${eventType}"; this build refuses to fold past it (fail closed, DR-0054)`
    );
    this.name = "UnknownLifecycleEventError";
    this.eventType = eventType;
  }
};
var initialLifecycleState = {
  phase: "init",
  openedAtMs: 0,
  lastActivityMs: 0,
  collection: "none",
  transcriptRetained: false,
  sessionOccurred: false
};
function reject(reason) {
  return { rejected: reason };
}
__name(reject, "reject");
function deadlineAt(state, idleTtlMs, absoluteTtlMs) {
  return Math.min(
    state.openedAtMs + absoluteTtlMs,
    state.lastActivityMs + idleTtlMs
  );
}
__name(deadlineAt, "deadlineAt");
function decide(state, command) {
  switch (command.kind) {
    case "open":
      if (state.phase !== "init") return reject("open: session already opened");
      return [
        {
          type: "opened",
          atMs: command.atMs,
          collectionDeclared: command.collectionDeclared
        }
      ];
    case "activate":
      if (state.phase !== "opened") return reject("activate: only from opened");
      return [{ type: "activated" }];
    case "observeActivity":
      if (state.phase !== "active" && state.phase !== "expiring") {
        return reject("observeActivity: only from active or expiring");
      }
      return [{ type: "activityObserved", atMs: command.atMs }];
    // Time enters here and nowhere else. A firing before the deadline is an
    // ordinary no-op observation, not a rejection: the shell reschedules.
    case "observeDeadline": {
      if (state.phase !== "active" && state.phase !== "expiring") {
        return reject("observeDeadline: only from active or expiring");
      }
      if (state.phase === "expiring") return [];
      const due = deadlineAt(state, command.idleTtlMs, command.absoluteTtlMs);
      return command.atMs >= due ? [{ type: "deadlineReached", atMs: command.atMs }] : [];
    }
    case "settleCollection":
      if (state.collection !== "pending") {
        return reject("settleCollection: no pending collection");
      }
      return [{ type: "collectionSettled" }];
    case "failCollection":
      if (state.collection !== "pending") {
        return reject("failCollection: no pending collection");
      }
      return [{ type: "collectionFailed" }];
    // TERMINAL_REQUIRES_COLLECTION_SETTLED. A session whose declared collection
    // has not reached a terminal disposition cannot tear down, so the path that
    // failed to deliver an artifact can never be the path that erases it.
    case "tearDown":
      if (state.phase === "init" || state.phase === "tornDown") {
        return reject("tearDown: only from a live session");
      }
      if (state.collection === "pending") {
        return reject("tearDown: collection has not settled");
      }
      return [{ type: "tornDown" }];
  }
}
__name(decide, "decide");
function evolve(state, event) {
  switch (event.type) {
    case "opened":
      return {
        ...state,
        phase: "opened",
        openedAtMs: event.atMs,
        lastActivityMs: event.atMs,
        collection: event.collectionDeclared ? "pending" : "none"
      };
    case "activated":
      return { ...state, phase: "active" };
    case "activityObserved":
      return {
        ...state,
        phase: "active",
        lastActivityMs: Math.max(state.lastActivityMs, event.atMs)
      };
    case "deadlineReached":
      return { ...state, phase: "expiring" };
    case "collectionSettled":
      return { ...state, collection: "settled" };
    case "collectionFailed":
      return { ...state, collection: "failed" };
    case "tornDown":
      return {
        ...state,
        phase: "tornDown",
        transcriptRetained: true,
        sessionOccurred: true
      };
  }
  throw new UnknownLifecycleEventError(
    String(event.type)
  );
}
__name(evolve, "evolve");
function fold(events) {
  return events.reduce(evolve, initialLifecycleState);
}
__name(fold, "fold");
function isRejection(outcome) {
  return !Array.isArray(outcome);
}
__name(isRejection, "isRejection");

// src/model-broker.ts
var MODEL_EGRESS_PROTOCOL = "whipplescript.model-egress.v1";
var MODEL_EGRESS_STREAM_PROTOCOL = "whipplescript.model-egress.stream.v1";
var MODEL_AUTH_SENTINEL = "whipplescript-model-broker";
var MAX_BROKER_RESPONSE_BYTES = 16 * 1024 * 1024;
var STRIPPED_AUTH_HEADERS = /* @__PURE__ */ new Set([
  "authorization",
  "chatgpt-account-id",
  "x-api-key"
]);
var FORBIDDEN_AMBIENT_AUTH_HEADERS = /* @__PURE__ */ new Set([
  "cookie",
  "proxy-authorization"
]);
var MANAGED_BYOK_ALIAS = "primary";
var MANAGED_GATEWAY_RETRYABLE_STATUSES = /* @__PURE__ */ new Set([401, 403, 408, 425, 429]);
function managedGatewayTarget(baseUrl) {
  const admitted = new URL(baseUrl);
  const match = /^\/v1\/([0-9a-f]{32})\/([A-Za-z0-9][A-Za-z0-9_-]{0,63})\/compat\/?$/.exec(admitted.pathname);
  if (admitted.protocol !== "https:" || admitted.hostname !== "gateway.ai.cloudflare.com" || admitted.username || admitted.password || admitted.search || admitted.hash || !match) {
    throw new Error("managed funding requires an exact Cloudflare AI Gateway compat endpoint");
  }
  const [, accountId, gatewayId] = match;
  return {
    accountId,
    gatewayId,
    unifiedBillingBaseUrl: `https://api.cloudflare.com/client/v4/accounts/${accountId}/ai/v1`
  };
}
__name(managedGatewayTarget, "managedGatewayTarget");
function managedGatewayStatus(result) {
  const parsed = JSON.parse(result);
  return Number.isInteger(parsed.status) ? Number(parsed.status) : 0;
}
__name(managedGatewayStatus, "managedGatewayStatus");
function shouldFallbackToUnifiedBilling(status) {
  return MANAGED_GATEWAY_RETRYABLE_STATUSES.has(status) || status >= 500;
}
__name(shouldFallbackToUnifiedBilling, "shouldFallbackToUnifiedBilling");
async function directProviderCredential(binding, secrets) {
  const value = await secrets.resolve(binding.credential_id);
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`direct provider credential ${binding.credential_id} is unavailable`);
  }
  const entry = value;
  if (entry.provider !== binding.provider || !binding.credential_class || entry.credential_class !== binding.credential_class || typeof entry.api_key !== "string") {
    throw new Error(
      `direct provider credential ${binding.credential_id} does not match the admitted provider and class`
    );
  }
  const credential = entry.api_key.trim();
  if (!credential) {
    throw new Error(`direct provider credential ${binding.credential_id} is unavailable`);
  }
  return credential;
}
__name(directProviderCredential, "directProviderCredential");
function validatedBrokerUrl(raw) {
  if (!raw?.trim()) throw new Error("model broker URL is unavailable");
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new Error("model broker URL is invalid");
  }
  const loopback = url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]" || url.hostname === "::1";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
    throw new Error("model broker URL must use HTTPS (HTTP is loopback-only)");
  }
  if (url.username || url.password || url.hash) {
    throw new Error("model broker URL may not contain credentials or a fragment");
  }
  return url.toString();
}
__name(validatedBrokerUrl, "validatedBrokerUrl");
function sentinelValue(name) {
  return name === "authorization" ? `Bearer ${MODEL_AUTH_SENTINEL}` : MODEL_AUTH_SENTINEL;
}
__name(sentinelValue, "sentinelValue");
function stripSentinelAuthentication(headers) {
  const sanitized = [];
  let witnessedAuthentication = false;
  for (const [name, value] of headers) {
    const normalized = name.toLowerCase();
    if (FORBIDDEN_AMBIENT_AUTH_HEADERS.has(normalized)) {
      throw new Error(`model request contains forbidden ${normalized} header`);
    }
    if (STRIPPED_AUTH_HEADERS.has(normalized)) {
      if (value !== sentinelValue(normalized)) {
        throw new Error(`model request ${normalized} header is not the broker sentinel`);
      }
      witnessedAuthentication = true;
      continue;
    }
    sanitized.push([name, value]);
  }
  if (!witnessedAuthentication) {
    throw new Error("model request has no broker-sentinel authentication header");
  }
  return sanitized;
}
__name(stripSentinelAuthentication, "stripSentinelAuthentication");
async function readJsonCapped(response) {
  const declared = response.headers.get("content-length");
  if (declared && Number(declared) > MAX_BROKER_RESPONSE_BYTES) {
    throw new Error("model broker response exceeds the size cap");
  }
  if (!response.body) throw new Error("model broker response had no body");
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  for (; ; ) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    total += value.byteLength;
    if (total > MAX_BROKER_RESPONSE_BYTES) {
      await reader.cancel();
      throw new Error("model broker response exceeds the size cap");
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new Error("model broker response was not valid JSON");
  }
}
__name(readJsonCapped, "readJsonCapped");
function validatedBrokerResponse(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("model broker response must be an object");
  }
  const response = value;
  if (response.protocol !== MODEL_EGRESS_PROTOCOL) {
    throw new Error("model broker response has the wrong protocol");
  }
  if (!Number.isInteger(response.status) || Number(response.status) < 100 || Number(response.status) > 599) {
    throw new Error("model broker response has an invalid provider status");
  }
  if (!("body" in response)) {
    throw new Error("model broker response has no provider body");
  }
  if (response.reconciliation_ref !== void 0 && typeof response.reconciliation_ref !== "string") {
    throw new Error("model broker reconciliation ref must be a string");
  }
  return response;
}
__name(validatedBrokerResponse, "validatedBrokerResponse");
function directProviderBody(body, provider) {
  const providerLimit = provider === "openai" || provider === "openai-codex" ? "max_output_tokens" : provider === "cloudflare-ai-gateway" ? "max_completion_tokens" : null;
  if (!providerLimit) return body;
  if (!body || typeof body !== "object" || Array.isArray(body)) return body;
  const fields = body;
  if (!("max_tokens" in fields)) return body;
  if (providerLimit in fields) {
    throw new Error("provider request has conflicting output token limits");
  }
  const { max_tokens, ...rest } = fields;
  return { ...rest, [providerLimit]: max_tokens };
}
__name(directProviderBody, "directProviderBody");
async function performModelBrokerFetch(request, binding, config, fetcher = fetch, onTextDelta, traceId, onTiming) {
  const startedAt = performance.now();
  const mark = /* @__PURE__ */ __name((event) => onTiming?.(event, performance.now() - startedAt), "mark");
  const brokerUrl = validatedBrokerUrl(config.url);
  const token = config.token?.trim();
  const executionGrant = config.executionGrant?.trim();
  const executionSignature = config.executionSignature?.trim();
  if (!token && (!executionGrant || !executionSignature)) {
    throw new Error("model broker authorization is unavailable");
  }
  if (token && (executionGrant || executionSignature)) {
    throw new Error("model broker authorization is ambiguous");
  }
  if (!binding.credential_id.trim()) throw new Error("model broker credential ref is empty");
  const headers = stripSentinelAuthentication(request.headers);
  const idempotencyKey = headers.find(
    ([name]) => name.toLowerCase() === "idempotency-key"
  )?.[1];
  const envelope = {
    protocol: MODEL_EGRESS_PROTOCOL,
    credential_ref: binding.credential_id,
    provider: binding.provider,
    request: {
      url: request.url,
      headers,
      body: request.body
    }
  };
  const brokerHeaders = {
    accept: "application/vnd.whipplescript.model-egress-stream",
    "content-type": "application/json"
  };
  if (token) {
    brokerHeaders.authorization = `Bearer ${token}`;
  } else {
    brokerHeaders["x-gaugewright-execution-grant"] = executionGrant;
    brokerHeaders["x-gaugewright-execution-signature"] = executionSignature;
  }
  if (idempotencyKey) brokerHeaders["idempotency-key"] = idempotencyKey;
  if (traceId) brokerHeaders["x-gaugewright-trace-id"] = traceId;
  mark("broker_fetch_start");
  const response = await fetcher(brokerUrl, {
    method: "POST",
    headers: brokerHeaders,
    body: JSON.stringify(envelope)
  });
  mark("broker_headers");
  if (!response.ok) {
    throw new Error(`model broker returned HTTP ${response.status}`);
  }
  if (response.headers.get("x-whip-model-egress-protocol") === MODEL_EGRESS_STREAM_PROTOCOL) {
    const upstreamStatus = Number(response.headers.get("x-whip-provider-status"));
    if (!Number.isInteger(upstreamStatus) || upstreamStatus < 100 || upstreamStatus > 599) {
      throw new Error("model broker stream has an invalid provider status");
    }
    const contentType = response.headers.get("x-whip-provider-content-type") ?? "";
    if (!response.body) throw new Error("model broker stream had no body");
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    const chunks = [];
    let sawTextDelta = false;
    const deltas = new ResponsesSseDeltaDecoder((delta) => {
      if (!sawTextDelta) {
        sawTextDelta = true;
        mark("provider_first_text_delta");
      }
      onTextDelta?.(delta);
    });
    let total = 0;
    let sawByte = false;
    for (; ; ) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      if (!sawByte) {
        sawByte = true;
        mark("broker_first_body_byte");
      }
      total += value.byteLength;
      if (total > MAX_BROKER_RESPONSE_BYTES) {
        await reader.cancel();
        throw new Error("model broker response exceeds the size cap");
      }
      const text = decoder.decode(value, { stream: true });
      chunks.push(text);
      if (contentType.toLowerCase().includes("text/event-stream")) deltas.feed(text);
    }
    const tail = decoder.decode();
    if (tail) {
      chunks.push(tail);
      if (contentType.toLowerCase().includes("text/event-stream")) deltas.feed(tail);
    }
    deltas.finish();
    mark("broker_body_complete");
    const raw = chunks.join("");
    let body = raw;
    if (!contentType.toLowerCase().includes("text/event-stream")) {
      try {
        body = JSON.parse(raw);
      } catch {
        throw new Error("model broker response was not valid JSON");
      }
    }
    return JSON.stringify({ status: upstreamStatus, body });
  }
  const decoded = validatedBrokerResponse(await readJsonCapped(response));
  mark("broker_body_complete");
  return JSON.stringify({ status: decoded.status, body: decoded.body });
}
__name(performModelBrokerFetch, "performModelBrokerFetch");
async function performManagedGatewayFetch(request, binding, secret, fetcher = fetch, onTextDelta, onTiming, onUsage, onGatewayLog) {
  if (binding.provider !== "cloudflare-ai-gateway") {
    throw new Error(
      `managed funding requires the metered gateway, not ${binding.provider}`
    );
  }
  const token = secret.token()?.trim();
  if (!token) {
    throw new Error("managed funding has no gateway token on this runtime");
  }
  const target = managedGatewayTarget(binding.base_url);
  const gatewaySecret = {
    // The shim answers with the shape `directProviderCredential` proves, so
    // the checks there still run — the token simply is not a per-deployment
    // reference and never came from the credential registry.
    resolve: /* @__PURE__ */ __name(async () => ({
      provider: binding.provider,
      credential_class: binding.credential_class,
      api_key: token
    }), "resolve")
  };
  let primaryReachedEgress = false;
  let primaryEmittedText = false;
  let primaryResult;
  try {
    primaryResult = await performDirectProviderFetch(
      request,
      binding,
      gatewaySecret,
      async (url, init) => {
        primaryReachedEgress = true;
        const headers = new Headers(init.headers);
        headers.set("cf-aig-byok-alias", MANAGED_BYOK_ALIAS);
        return fetcher(url, { ...init, headers });
      },
      (delta) => {
        primaryEmittedText = true;
        onTextDelta?.(delta);
      },
      onTiming,
      onUsage,
      onGatewayLog
    );
  } catch (error) {
    if (!primaryReachedEgress || primaryEmittedText) throw error;
    primaryResult = JSON.stringify({ status: 599, body: null });
  }
  const primaryStatus = managedGatewayStatus(primaryResult);
  if (!shouldFallbackToUnifiedBilling(primaryStatus) || primaryEmittedText) {
    return primaryResult;
  }
  console.log(JSON.stringify({
    event: "gaugewright_managed_gateway_fallback",
    primary_status: primaryStatus,
    fallback: "cloudflare_unified_billing"
  }));
  const fallbackBinding = {
    ...binding,
    base_url: target.unifiedBillingBaseUrl
  };
  const fallbackRequest = {
    ...request,
    url: `${target.unifiedBillingBaseUrl}/chat/completions`
  };
  return performDirectProviderFetch(
    fallbackRequest,
    fallbackBinding,
    gatewaySecret,
    async (url, init) => {
      const headers = new Headers(init.headers);
      headers.set("cf-aig-gateway-id", target.gatewayId);
      headers.delete("cf-aig-byok-alias");
      return fetcher(url, { ...init, headers });
    },
    onTextDelta,
    onTiming,
    onUsage,
    onGatewayLog
  );
}
__name(performManagedGatewayFetch, "performManagedGatewayFetch");
async function performDirectProviderFetch(request, binding, secrets, fetcher = fetch, onTextDelta, onTiming, onUsage, onGatewayLog) {
  const startedAt = performance.now();
  const mark = /* @__PURE__ */ __name((event) => onTiming?.(event, performance.now() - startedAt), "mark");
  const requested = new URL(request.url);
  const admitted = new URL(binding.base_url);
  const admittedPath = admitted.pathname.replace(/\/$/, "");
  const expectedPath = binding.provider === "anthropic" ? `${admittedPath}/v1/messages` : binding.provider === "openai-generic" || binding.provider === "cloudflare-ai-gateway" ? `${admittedPath}/chat/completions` : `${admittedPath}/v1/responses`;
  if (requested.origin !== admitted.origin || requested.pathname !== expectedPath || requested.username || requested.password || requested.hash) {
    throw new Error("direct provider request escaped the signed provider endpoint");
  }
  const headers = new Headers(stripSentinelAuthentication(request.headers));
  const credential = await directProviderCredential(binding, secrets);
  if (binding.provider === "anthropic") {
    headers.set("x-api-key", credential);
  } else {
    headers.set("authorization", `Bearer ${credential}`);
  }
  mark("direct_provider_fetch_start");
  const response = await fetcher(request.url, {
    method: "POST",
    headers,
    body: JSON.stringify(directProviderBody(request.body, binding.provider))
  });
  mark("direct_provider_headers");
  if (!response.body) throw new Error("direct provider response had no body");
  const contentType = response.headers.get("content-type") ?? "";
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  const chunks = [];
  let total = 0;
  let sawByte = false;
  let sawText = false;
  const deltas = new ResponsesSseDeltaDecoder((delta) => {
    if (!sawText) {
      sawText = true;
      mark("direct_provider_first_text_delta");
    }
    onTextDelta?.(delta);
  });
  for (; ; ) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    if (!sawByte) {
      sawByte = true;
      mark("direct_provider_first_body_byte");
    }
    total += value.byteLength;
    if (total > MAX_BROKER_RESPONSE_BYTES) {
      await reader.cancel();
      throw new Error("direct provider response exceeds the size cap");
    }
    const text = decoder.decode(value, { stream: true });
    chunks.push(text);
    if (contentType.toLowerCase().includes("text/event-stream")) deltas.feed(text);
  }
  const tail = decoder.decode();
  if (tail) {
    chunks.push(tail);
    if (contentType.toLowerCase().includes("text/event-stream")) deltas.feed(tail);
  }
  deltas.finish();
  mark("direct_provider_body_complete");
  const raw = chunks.join("");
  const gatewayLogId = response.headers.get("cf-aig-log-id")?.trim();
  if (gatewayLogId) onGatewayLog?.(gatewayLogId);
  const usage = extractResponsesUsage(raw);
  if (usage) onUsage?.(usage);
  let body = raw;
  if (!contentType.toLowerCase().includes("text/event-stream")) {
    try {
      body = JSON.parse(raw);
    } catch {
      throw new Error("direct provider response was not valid JSON");
    }
    const completion = body && typeof body === "object" && !Array.isArray(body) ? body.choices?.[0]?.message?.content : void 0;
    if (typeof completion === "string" && completion) {
      if (!sawText) {
        sawText = true;
        mark("direct_provider_first_text_delta");
      }
      onTextDelta?.(completion);
    }
  }
  if (!response.ok) {
    const providerError = body && typeof body === "object" && !Array.isArray(body) ? body.error : void 0;
    const fields = providerError && typeof providerError === "object" && !Array.isArray(providerError) ? providerError : {};
    const safeField = /* @__PURE__ */ __name((name) => {
      const value = fields[name];
      return typeof value === "string" && /^[A-Za-z0-9._:-]{1,128}$/.test(value) ? value : null;
    }, "safeField");
    console.log(JSON.stringify({
      event: "gaugewright_direct_provider_rejected",
      status: response.status,
      type: safeField("type"),
      code: safeField("code"),
      param: safeField("param")
    }));
  }
  return JSON.stringify({ status: response.status, body });
}
__name(performDirectProviderFetch, "performDirectProviderFetch");
function extractResponsesUsage(raw) {
  let found = null;
  for (const line of raw.replaceAll("\r\n", "\n").split("\n")) {
    if (!line.startsWith("data:")) continue;
    const payload = line.slice("data:".length).trim();
    if (!payload || payload === "[DONE]") continue;
    try {
      const event = JSON.parse(payload);
      const usage = event.response?.usage ?? event.usage;
      if (usage && Number.isSafeInteger(usage.input_tokens) && Number(usage.input_tokens) >= 0 && Number.isSafeInteger(usage.output_tokens) && Number(usage.output_tokens) >= 0 && (usage.input_tokens_details?.cached_tokens === void 0 || Number.isSafeInteger(usage.input_tokens_details.cached_tokens) && Number(usage.input_tokens_details.cached_tokens) >= 0 && Number(usage.input_tokens_details.cached_tokens) <= Number(usage.input_tokens))) {
        found = {
          input_tokens: Number(usage.input_tokens),
          cached_input_tokens: Number.isSafeInteger(usage.input_tokens_details?.cached_tokens) && Number(usage.input_tokens_details?.cached_tokens) >= 0 ? Number(usage.input_tokens_details?.cached_tokens) : 0,
          output_tokens: Number(usage.output_tokens)
        };
      }
    } catch {
    }
  }
  return found;
}
__name(extractResponsesUsage, "extractResponsesUsage");
var ResponsesSseDeltaDecoder = class {
  static {
    __name(this, "ResponsesSseDeltaDecoder");
  }
  buffer = "";
  emit;
  constructor(emit) {
    this.emit = emit;
  }
  feed(chunk) {
    this.buffer = `${this.buffer}${chunk}`.replaceAll("\r\n", "\n");
    for (; ; ) {
      const boundary = this.buffer.indexOf("\n\n");
      if (boundary < 0) break;
      const event = this.buffer.slice(0, boundary);
      this.buffer = this.buffer.slice(boundary + 2);
      this.decodeEvent(event);
    }
  }
  finish() {
    if (this.buffer.trim()) this.decodeEvent(this.buffer);
    this.buffer = "";
  }
  decodeEvent(block) {
    for (const line of block.split("\n")) {
      const payload = line.trim().startsWith("data:") ? line.trim().slice("data:".length).trim() : "";
      if (!payload || payload === "[DONE]") continue;
      try {
        const event = JSON.parse(payload);
        if (event.type === "response.output_text.delta" && typeof event.delta === "string" && event.delta) {
          this.emit?.(event.delta);
          continue;
        }
        const chatDelta = event.choices?.[0]?.delta?.content;
        if (typeof chatDelta === "string" && chatDelta) {
          this.emit?.(chatDelta);
        }
      } catch {
      }
    }
  }
};

// src/provider-realization.ts
var supportedProviders = /* @__PURE__ */ new Set([
  "openai",
  "openai-generic",
  "anthropic",
  "openai-codex",
  "cloudflare-ai-gateway"
]);
function validateAdmission(admission) {
  if (!admission.provider_binding_id.trim() || !admission.credential_id.trim() || !admission.placement_ceiling_ref.trim() || !supportedProviders.has(admission.provider) || !admission.model.trim() || !admission.base_url.trim()) {
    throw new Error("admitted provider capability has no exact hosted realization");
  }
}
__name(validateAdmission, "validateAdmission");
function resolveAdmittedProvider(admission, env, execution = "model-broker") {
  validateAdmission(admission);
  if (execution === "managed") {
    if (admission.provider !== "cloudflare-ai-gateway") {
      throw new Error(
        `managed funding requires the metered gateway, not ${admission.provider}`
      );
    }
    if (!env.WHIP_GATEWAY_TOKEN?.trim()) {
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
      api_key: MODEL_AUTH_SENTINEL
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
      api_key: MODEL_AUTH_SENTINEL
    };
  }
  const hasToken = Boolean(env.WHIP_MODEL_BROKER_TOKEN?.trim());
  const hasGrant = Boolean(
    env.WHIP_MODEL_BROKER_EXECUTION_GRANT?.trim() && env.WHIP_MODEL_BROKER_EXECUTION_SIGNATURE?.trim()
  );
  if (!env.WHIP_MODEL_BROKER_URL?.trim() || !hasToken && !hasGrant) {
    throw new Error(`admitted provider credential ${admission.credential_id} has no model broker`);
  }
  return {
    credential_id: admission.credential_id,
    provider: admission.provider,
    model: admission.model,
    base_url: admission.base_url,
    execution: "model-broker",
    api_key: MODEL_AUTH_SENTINEL
  };
}
__name(resolveAdmittedProvider, "resolveAdmittedProvider");
function bindExactPublicCredential(binding, exactCredentialRef) {
  if (binding.execution !== "direct" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/.test(exactCredentialRef)) {
    throw new Error("public credential binding requires an exact deployment reference");
  }
  return {
    ...binding,
    credential_id: exactCredentialRef,
    credential_class: binding.credential_id
  };
}
__name(bindExactPublicCredential, "bindExactPublicCredential");

// src/index.ts
import DO_SCHEMA from "./87a27d1155c05cc650dfcce552b754c26265c58b-do_schema.sql";
var wasmInstance = new WebAssembly.Instance(wasmModule, {
  "./whipplescript_host_do_bg.js": whipplescript_host_do_bg_exports
});
__wbg_set_wasm(wasmInstance.exports);
wasmInstance.exports.__wbindgen_start?.();
var verifyHostPolicy = verify_host_policy;
var hostFunctions = whipplescript_host_do_bg_exports;
function publicCommandId(sessionId, requestId) {
  return `public:${sessionId}:${requestId}`;
}
__name(publicCommandId, "publicCommandId");
function publicRequestId(commandId) {
  return commandId.split(":").slice(2).join(":");
}
__name(publicRequestId, "publicRequestId");
var ExecutorContainer = class extends Container {
  static {
    __name(this, "ExecutorContainer");
  }
  defaultPort = 8080;
  sleepAfter = "10m";
};
var EXECUTOR_POOL_SIZE = 4;
var MAX_BOOTSTRAP_BYTES = 1024 * 1024;
var INSTANCE_DUE_KEY = "instance-next-due-unix-ms";
var BUILTIN_SEEDS = [
  `INSERT INTO capability_schemas (capability, description, schema_json) VALUES ('schema.coerce', 'Coerce unstructured data into a typed value.', '{}')`,
  `INSERT INTO effect_providers (provider_id, effect_kind, provider, capability, config_json) VALUES ('provider_coerce_builtin', 'schema.coerce', 'builtin-coerce', 'schema.coerce', '{}')`,
  `INSERT INTO capability_bindings (binding_id, program_id, capability, provider, config_json) VALUES ('binding_coerce_builtin', NULL, 'schema.coerce', 'builtin-coerce', '{}')`,
  `INSERT INTO capability_schemas (capability, description, schema_json) VALUES ('agent.tell', 'Run an agent turn.', '{}')`,
  `INSERT INTO effect_providers (provider_id, effect_kind, provider, capability, config_json) VALUES ('provider_agent_tell_builtin', 'agent.tell', 'builtin-agent-harness', 'agent.tell', '{}')`,
  `INSERT INTO capability_bindings (binding_id, program_id, capability, provider, config_json) VALUES ('binding_agent_tell_builtin', NULL, 'agent.tell', 'builtin-agent-harness', '{}')`,
  `INSERT INTO profiles (profile_id, name, description, enforcement_mode, allowed_capabilities, config_json) VALUES ('profile_repo_reader', 'repo-reader', 'Allow repository reads and agent turns without writes.', 'enforce', '["agent.tell","repo.read","schema.coerce","event.emit","workflow.invoke"]', '{}')`
];
var SUPPORTED_DO_SCHEMA_VERSION = 1;
var UnsupportedSchemaVersionError = class extends Error {
  static {
    __name(this, "UnsupportedSchemaVersionError");
  }
  constructor(found) {
    super(
      `durable object schema is at version ${found}, but this deploy supports up to version ${SUPPORTED_DO_SCHEMA_VERSION}; it was written by a newer deploy. Serve it with a deploy that supports version ${found} \u2014 the state is intact, do not delete it`
    );
    this.name = "UnsupportedSchemaVersionError";
  }
};
function ensureSchema(sql) {
  const marker = sql.exec(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'`).toArray();
  if (marker.length === 0) {
    sql.exec(DO_SCHEMA);
    for (const seed of BUILTIN_SEEDS) {
      sql.exec(seed);
    }
  }
  const stamped = sql.exec(`SELECT COALESCE(MAX(version), 0) AS version FROM schema_migrations`).toArray();
  const found = stamped[0]?.version ?? 0;
  if (found > SUPPORTED_DO_SCHEMA_VERSION) {
    throw new UnsupportedSchemaVersionError(found);
  }
  sql.exec(`INSERT OR IGNORE INTO profiles
    (profile_id, name, description, enforcement_mode, allowed_capabilities, config_json)
    VALUES (
      'profile_repo_writer',
      'repo-writer',
      'Allow governed workspace reads, writes, Bashkit commands, and agent turns.',
      'enforce',
      '["agent.tell","workspace.read","workspace.write","command.run"]',
      '{}'
    )`);
  const hasAssignedTo = sql.exec(`SELECT name FROM pragma_table_info('tracker_issues') WHERE name = 'assigned_to'`).toArray();
  if (hasAssignedTo.length === 0) {
    sql.exec(`ALTER TABLE tracker_issues ADD COLUMN assigned_to TEXT`);
  }
  sql.exec(`CREATE TABLE IF NOT EXISTS tracker_aliases (
    content_id TEXT PRIMARY KEY, alias TEXT NOT NULL UNIQUE
  )`);
  sql.exec(`CREATE TABLE IF NOT EXISTS tracker_comments (
    comment_id TEXT PRIMARY KEY, issue_id TEXT NOT NULL, author TEXT,
    body TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  sql.exec(`CREATE TABLE IF NOT EXISTS tracker_evidence (
    evidence_id TEXT PRIMARY KEY, issue_id TEXT NOT NULL, kind TEXT, reference TEXT,
    note TEXT, added_by TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  for (const [column, definition] of [
    ["event_id", "event_id TEXT"],
    ["parents_json", "parents_json TEXT NOT NULL DEFAULT '[]'"]
  ]) {
    const present = sql.exec(
      `SELECT name FROM pragma_table_info('tracker_events') WHERE name = ?`,
      column
    ).toArray();
    if (present.length === 0) {
      sql.exec(`ALTER TABLE tracker_events ADD COLUMN ${definition}`);
    }
  }
  sql.exec(
    `CREATE UNIQUE INDEX IF NOT EXISTS idx_tracker_events_id ON tracker_events(event_id)`
  );
  const hasFormatVersion = sql.exec(`SELECT name FROM pragma_table_info('events') WHERE name = 'format_version'`).toArray();
  if (hasFormatVersion.length === 0) {
    sql.exec(`ALTER TABLE events ADD COLUMN format_version INTEGER`);
  }
  sql.exec(`CREATE TABLE IF NOT EXISTS host_turn_images (
    instance_id TEXT NOT NULL,
    command_id TEXT NOT NULL,
    selector TEXT NOT NULL,
    media_type TEXT NOT NULL,
    data_base64 TEXT NOT NULL,
    PRIMARY KEY (instance_id, command_id, selector)
  )`);
  sql.exec(`CREATE TABLE IF NOT EXISTS host_turn_deltas (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    instance_id TEXT NOT NULL,
    command_id TEXT NOT NULL,
    delta TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  sql.exec(`CREATE INDEX IF NOT EXISTS idx_host_turn_deltas
    ON host_turn_deltas(instance_id, command_id, sequence)`);
  sql.exec(`CREATE TABLE IF NOT EXISTS public_turn_commands (
    command_id TEXT PRIMARY KEY,
    turn_command_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('steer', 'follow_up')),
    text TEXT NOT NULL,
    images_json TEXT NOT NULL DEFAULT '[]',
    position INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
      CHECK (status IN ('pending', 'applied', 'removed')),
    announced INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    applied_at TEXT
  )`);
  sql.exec(`CREATE INDEX IF NOT EXISTS idx_public_turn_commands_pending
    ON public_turn_commands(turn_command_id, kind, status, position)`);
  sql.exec(`CREATE TABLE IF NOT EXISTS public_turn_binding (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    request_id TEXT NOT NULL,
    command_id TEXT NOT NULL
  )`);
  sql.exec(`CREATE TABLE IF NOT EXISTS public_session_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    release_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    instance_ref TEXT NOT NULL,
    governance_signer TEXT NOT NULL,
    governance_key TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  sql.exec(`CREATE TABLE IF NOT EXISTS session_lifecycle_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_json TEXT NOT NULL,
    recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
}
__name(ensureSchema, "ensureSchema");
function rowsToPositionalJson(cursor) {
  const rows = [];
  for (const row of cursor) {
    rows.push(Object.values(row));
  }
  return JSON.stringify(rows);
}
__name(rowsToPositionalJson, "rowsToPositionalJson");
function makeBridge(sql) {
  return {
    exec(query, paramsJson) {
      const params = JSON.parse(paramsJson);
      const cursor = sql.exec(query, ...params);
      return cursor.rowsWritten;
    },
    query(query, paramsJson) {
      const params = JSON.parse(paramsJson);
      const cursor = sql.exec(query, ...params);
      return rowsToPositionalJson(cursor);
    }
  };
}
__name(makeBridge, "makeBridge");
function constantTimeEqual(left, right) {
  let diff = left.length ^ right.length;
  const max = Math.max(left.length, right.length);
  for (let i = 0; i < max; i += 1) {
    diff |= (left.charCodeAt(i) || 0) ^ (right.charCodeAt(i) || 0);
  }
  return diff === 0;
}
__name(constantTimeEqual, "constantTimeEqual");
function requestBearerToken(request) {
  const authorization = request.headers.get("authorization") ?? "";
  if (authorization.toLowerCase().startsWith("bearer ")) {
    return authorization.slice("bearer ".length).trim();
  }
  return request.headers.get("x-whip-control-token") ?? void 0;
}
__name(requestBearerToken, "requestBearerToken");
function controlAuthError(request, env) {
  const expected = new URL(request.url).pathname.startsWith("/public/session/") ? env.WHIP_SESSION_TOKEN?.trim() : env.WHIP_CONTROL_TOKEN?.trim();
  if (!expected) {
    return Response.json({ error: "required control credential is unavailable" }, { status: 503 });
  }
  const actual = requestBearerToken(request) ?? "";
  if (!constantTimeEqual(actual, expected)) {
    return Response.json({ error: "unauthorized" }, { status: 401 });
  }
  return void 0;
}
__name(controlAuthError, "controlAuthError");
function requestBodyTooLarge(request) {
  const declared = request.headers.get("content-length");
  if (declared && Number(declared) > MAX_BOOTSTRAP_BYTES) {
    return Response.json({ error: "request body too large" }, { status: 413 });
  }
  return void 0;
}
__name(requestBodyTooLarge, "requestBodyTooLarge");
async function readJsonBody(request) {
  const early = requestBodyTooLarge(request);
  if (early) {
    return early;
  }
  const text = await request.text();
  if (new TextEncoder().encode(text).length > MAX_BOOTSTRAP_BYTES) {
    return Response.json({ error: "request body too large" }, { status: 413 });
  }
  try {
    const parsed = JSON.parse(text || "{}");
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed;
    }
    return Response.json({ error: "JSON body must be an object" }, { status: 400 });
  } catch (error) {
    return Response.json({ error: `invalid JSON body: ${error instanceof Error ? error.message : String(error)}` }, { status: 400 });
  }
}
__name(readJsonBody, "readJsonBody");
function isSentinelRoute(requestUrl, sentinelBase, suffix) {
  const request = new URL(requestUrl);
  const sentinel = new URL(sentinelBase);
  const basePath = sentinel.pathname.replace(/\/$/, "");
  const expectedPath = `${basePath}${suffix}`;
  return request.origin === sentinel.origin && request.pathname === expectedPath;
}
__name(isSentinelRoute, "isSentinelRoute");
function redactedUrlForLog(url) {
  try {
    const parsed = new URL(url);
    return `${parsed.origin}${parsed.pathname}`;
  } catch {
    return "<invalid-url>";
  }
}
__name(redactedUrlForLog, "redactedUrlForLog");
var MAX_FETCH_RESPONSE_BYTES = 16 * 1024 * 1024;
async function readJsonCapped2(resp, maxBytes) {
  const declared = resp.headers.get("content-length");
  if (declared && Number(declared) > maxBytes) {
    throw new Error(`response body (${declared} bytes) exceeds the ${maxBytes}-byte cap`);
  }
  if (!resp.body) {
    throw new Error("response had no body");
  }
  const reader = resp.body.getReader();
  const chunks = [];
  let total = 0;
  for (; ; ) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new Error(`response body exceeds the ${maxBytes}-byte cap`);
      }
      chunks.push(value);
    }
  }
  const buffer = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    buffer.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return JSON.parse(new TextDecoder().decode(buffer));
}
__name(readJsonCapped2, "readJsonCapped");
async function performFetch(req, env) {
  try {
    const init = {
      method: "POST",
      headers: Object.fromEntries(req.headers),
      body: JSON.stringify(req.body)
    };
    const executorHost = env?.WHIP_EXECUTOR_URL;
    const turnHost = env?.WHIP_TURN_URL;
    let resp;
    if (turnHost && isSentinelRoute(req.url, turnHost, "/turn")) {
      const turnId = String(req.body?.turn_id ?? "turn");
      const container = env.EXECUTOR.get(env.EXECUTOR.idFromName(`turn-${turnId}`));
      resp = await container.fetch(req.url, init);
    } else if (executorHost && isSentinelRoute(req.url, executorHost, "/exec")) {
      resp = await (await getRandom(env.EXECUTOR, EXECUTOR_POOL_SIZE)).fetch(req.url, init);
    } else {
      resp = await fetch(req.url, init);
    }
    return JSON.stringify({
      status: resp.status,
      body: await readJsonCapped2(resp, MAX_FETCH_RESPONSE_BYTES)
    });
  } catch (error) {
    console.log(`performFetch failed for ${redactedUrlForLog(req.url)}: ${error instanceof Error ? error.stack ?? error.message : String(error)}`);
    return JSON.stringify({ error: error instanceof Error ? error.message : String(error) });
  }
}
__name(performFetch, "performFetch");
var UnreadableSessionStateError = class extends Error {
  static {
    __name(this, "UnreadableSessionStateError");
  }
  constructor(detail) {
    super(
      `stored public session state is unreadable by this build (${detail}); refusing to guess (fail closed, DR-0054)`
    );
    this.name = "UnreadableSessionStateError";
  }
};
var LEGACY_RETENTION_FALLBACK = {
  idle_ttl_seconds: 3600,
  absolute_ttl_seconds: 86400
};
function normalizeStoredSessionState(raw) {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new UnreadableSessionStateError("record is not an object");
  }
  const candidate = raw;
  const missing = ["session_id", "release_id", "admission_scope", "instance_ref"].filter((field) => typeof candidate[field] !== "string" || !candidate[field]);
  if (missing.length) {
    throw new UnreadableSessionStateError(
      `missing identity fields: ${missing.join(", ")}`
    );
  }
  const repairs = [];
  const session = { ...candidate };
  const retention = candidate.retention;
  if (!retention || typeof retention !== "object" || !Number.isSafeInteger(retention.idle_ttl_seconds) || retention.idle_ttl_seconds < 0 || !Number.isSafeInteger(retention.absolute_ttl_seconds) || retention.absolute_ttl_seconds < retention.idle_ttl_seconds) {
    session.retention = { ...LEGACY_RETENTION_FALLBACK };
    repairs.push("retention");
  }
  const principal = candidate.principal;
  if (!principal || typeof principal !== "object" || typeof principal.label !== "string" || !principal.label) {
    session.principal = { label: "legacy-unlabeled" };
    repairs.push("principal");
  }
  const now = Date.now();
  if (!Number.isFinite(candidate.created_at_unix_ms)) {
    session.created_at_unix_ms = now;
    repairs.push("created_at_unix_ms");
  }
  if (!Number.isFinite(candidate.last_activity_unix_ms)) {
    session.last_activity_unix_ms = session.created_at_unix_ms;
    repairs.push("last_activity_unix_ms");
  }
  return { session, repairs };
}
__name(normalizeStoredSessionState, "normalizeStoredSessionState");
function validatePublicMessage(parsed) {
  const requestId = typeof parsed.request_id === "string" ? parsed.request_id.trim() : "";
  const text = typeof parsed.text === "string" ? parsed.text.trim() : "";
  if (parsed.images !== void 0 && !Array.isArray(parsed.images)) {
    return { ok: false, response: Response.json({ error: "turn images must be an array" }, { status: 422 }) };
  }
  const images = Array.isArray(parsed.images) ? parsed.images : [];
  if (images.length > 16) {
    return { ok: false, response: Response.json({ error: "turn accepts at most 16 images" }, { status: 413 }) };
  }
  let imageBytes = 0;
  for (const body of images) {
    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return { ok: false, response: Response.json({ error: "turn image has an invalid shape" }, { status: 422 }) };
    }
    const image = body;
    if (typeof image.media_type !== "string" || !["image/png", "image/jpeg", "image/webp", "image/gif"].includes(image.media_type) || typeof image.data_base64 !== "string" || !image.data_base64 || image.data_base64.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(image.data_base64)) {
      return { ok: false, response: Response.json({ error: "turn image is not supported base64 image input" }, { status: 422 }) };
    }
    const padding = image.data_base64.endsWith("==") ? 2 : image.data_base64.endsWith("=") ? 1 : 0;
    const bytes = image.data_base64.length / 4 * 3 - padding;
    imageBytes += bytes;
    if (bytes > 16 * 1024 * 1024 || imageBytes > 32 * 1024 * 1024) {
      return { ok: false, response: Response.json({ error: "turn image body limit exceeded" }, { status: 413 }) };
    }
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(requestId) || !text || new TextEncoder().encode(text).length > 256 * 1024) {
    return { ok: false, response: Response.json({ error: "turn requires a valid request_id and non-empty text" }, { status: 422 }) };
  }
  return { ok: true, requestId, text, images };
}
__name(validatePublicMessage, "validatePublicMessage");
var WorkflowInstance = class {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;
  }
  ctx;
  env;
  static {
    __name(this, "WorkflowInstance");
  }
  turnStreams = /* @__PURE__ */ new Map();
  // Same-isolate command coalescing only. Durable command identity and recovery
  // remain in WhippleScript effects/runs/receipts; this map disappears freely
  // on hibernation and is never a second turn lifecycle.
  publicTurns = /* @__PURE__ */ new Map();
  publicTraceStarts = /* @__PURE__ */ new Map();
  publicFirstWebSocketDeltas = /* @__PURE__ */ new Set();
  textEncoder = new TextEncoder();
  /**
   * DR-0054 Phase A: unrecognized durable state (an unknown lifecycle event
   * row, an unreadable session record) fails closed as a structured 500 with
   * the diagnosis logged, instead of an anonymous exception page. Nothing is
   * deleted; a build that recognizes the state serves it again.
   */
  failClosedResponse(error) {
    if (!(error instanceof UnknownLifecycleEventError) && !(error instanceof UnreadableSessionStateError) && !(error instanceof UnsupportedSchemaVersionError)) {
      return null;
    }
    console.log(
      JSON.stringify({
        event: "durable_state_fail_closed",
        error: String(error)
      })
    );
    return Response.json(
      { error: `durable state is unreadable by this build: ${error.message}` },
      { status: 500 }
    );
  }
  async fetch(request) {
    try {
      return await this.routeFetch(request);
    } catch (error) {
      const failClosed = this.failClosedResponse(error);
      if (failClosed) return failClosed;
      throw error;
    }
  }
  // POST /start { program, input, principal } -- create + drive to the first
  // suspension or terminal. Subsequent external events / alarms re-enter and drive
  // further; the durable state is entirely in DO SQLite.
  async routeFetch(request) {
    const authError = controlAuthError(request, this.env);
    if (authError) {
      return authError;
    }
    const privateRootError = this.pinPrivateGovernanceRoot(request);
    if (privateRootError) {
      return privateRootError;
    }
    const url = new URL(request.url);
    if (request.method === "GET") {
      if (url.pathname === "/public/session/state") {
        return this.publicSessionState();
      }
      if (url.pathname === "/public/session/files") {
        return this.publicSessionFiles(url);
      }
      if (url.pathname === "/public/session/socket") {
        const session = await this.readPublicSessionState();
        if (!session) {
          return Response.json(
            { error: "public session is not bootstrapped" },
            { status: 409 }
          );
        }
        if (await this.publicSessionRequestExpired(session)) {
          return Response.json({ error: "public session has expired" }, { status: 410 });
        }
        return this.openPublicSessionSocket(request, session, url);
      }
      const eventStream = url.pathname.match(/^\/host\/instances\/([^/]+)\/events\/stream$/);
      if (eventStream) {
        return this.hostEventStream(decodeURIComponent(eventStream[1]), url);
      }
      const eventSocket = url.pathname.match(/^\/host\/instances\/([^/]+)\/events\/live$/);
      if (eventSocket) {
        return this.openHostEventSocket(
          request,
          decodeURIComponent(eventSocket[1]),
          url
        );
      }
      const turnStream = url.pathname.match(
        /^\/host\/instances\/([^/]+)\/turns\/([^/]+)\/stream$/
      );
      if (turnStream) {
        return this.openHostTurnStream(
          decodeURIComponent(turnStream[1]),
          decodeURIComponent(turnStream[2]),
          url
        );
      }
      const forkExport = url.pathname.match(/^\/host\/instances\/([^/]+)\/fork-export$/);
      if (forkExport) {
        return this.exportHostFork(decodeURIComponent(forkExport[1]), url);
      }
      return this.hostProjection(url);
    }
    if (request.method !== "POST") {
      return Response.json({ error: "method not allowed" }, { status: 405 });
    }
    const parsed = await readJsonBody(request);
    if (parsed instanceof Response) {
      return parsed;
    }
    if (url.pathname === "/public/session/bootstrap") {
      return this.bootstrapPublicSession(parsed);
    }
    if (url.pathname === "/public/session/claim") {
      return this.claimPublicSession(parsed);
    }
    if (url.pathname === "/public/session/erase") {
      return this.erasePublicSession();
    }
    const cancel = url.pathname.match(/^\/host\/instances\/([^/]+)\/turns\/([^/]+)\/cancel$/);
    if (cancel) {
      try {
        const receipt = JSON.parse(
          hostFunctions.host_cancel_turn(
            makeBridge(this.ctx.storage.sql),
            decodeURIComponent(cancel[1]),
            decodeURIComponent(cancel[2]),
            "gaugedesk-control-plane"
          )
        );
        return Response.json(receipt, { status: 202 });
      } catch (error) {
        return Response.json({ error: `cancellation rejected: ${String(error)}` }, { status: 400 });
      }
    }
    const fileSync = url.pathname.match(/^\/host\/instances\/([^/]+)\/files\/sync$/);
    if (fileSync) {
      return this.syncHostFiles(decodeURIComponent(fileSync[1]), parsed);
    }
    const checkpoint = url.pathname.match(
      /^\/host\/instances\/([^/]+)\/(checkpoint|restore)$/
    );
    if (checkpoint) {
      return this.hostCheckpoint(
        decodeURIComponent(checkpoint[1]),
        checkpoint[2],
        parsed
      );
    }
    if (url.pathname === "/host/policy") {
      return this.bootstrapHostPolicy(parsed);
    }
    if (url.pathname === "/host/instances/open") {
      return this.openHostInstance(parsed);
    }
    if (url.pathname === "/host/turns") {
      return this.beginHostTurn(parsed);
    }
    if (url.pathname === "/host/forks/import") {
      return this.importHostFork(parsed);
    }
    const body = parsed;
    if (body.command === "checkpoint" || body.command === "restore") {
      const existing = await this.ctx.storage.get("bootstrap");
      if (!existing) {
        return Response.json({ error: "no instance to command" }, { status: 400 });
      }
      if (!body.cut_id) {
        return Response.json({ error: `${body.command} requires cut_id` }, { status: 400 });
      }
      const instance = this.makeInstance(existing);
      try {
        const report = body.command === "checkpoint" ? instance.checkpoint(body.cut_id) : instance.restore(body.cut_id);
        return new Response(report, { headers: { "content-type": "application/json" } });
      } catch (error) {
        return Response.json({ error: String(error) }, { status: 400 });
      }
    }
    const program = typeof body.program === "string" ? body.program : void 0;
    const input = typeof body.input === "string" ? body.input : void 0;
    const principal = typeof body.principal === "string" ? body.principal : void 0;
    let bootstrap;
    if (program) {
      const existing = await this.ctx.storage.get("bootstrap");
      if (existing) {
        return Response.json({ error: "instance already bootstrapped; use a new id" }, { status: 409 });
      }
      bootstrap = {
        program,
        input: input ?? "{}",
        principal: principal ?? "local/Workflow"
      };
      await this.ctx.storage.put("bootstrap", bootstrap);
    } else {
      bootstrap = await this.ctx.storage.get("bootstrap");
    }
    if (!bootstrap) {
      return Response.json({ error: "no program: POST { program, input, principal } first" }, { status: 400 });
    }
    const result = await this.drive(bootstrap);
    return Response.json(result);
  }
  async publicSessionState() {
    const session = await this.readPublicSessionState();
    if (!session) {
      return Response.json(
        { error: "public session is not bootstrapped" },
        { status: 409 }
      );
    }
    if (await this.publicSessionRequestExpired(session)) {
      return Response.json({ error: "public session has expired" }, { status: 410 });
    }
    ensureSchema(this.ctx.storage.sql);
    const snapshot = await this.publicSessionSnapshot(session);
    return Response.json(snapshot);
  }
  async claimPublicSession(parsed) {
    const session = await this.readPublicSessionState();
    const subjectHash = typeof parsed.subject_hash === "string" ? parsed.subject_hash : "";
    if (!session) {
      return Response.json({ error: "public session is not bootstrapped" }, { status: 409 });
    }
    if (!/^[0-9a-f]{64}$/.test(subjectHash)) {
      return Response.json({ error: "principal subject is invalid" }, { status: 422 });
    }
    if (typeof session.principal.subject_hash === "string" && session.principal.subject_hash !== subjectHash) {
      return Response.json({ error: "session belongs to another subject" }, { status: 409 });
    }
    session.principal = { label: session.principal.label, subject_hash: subjectHash };
    await this.ctx.storage.put("public-session-state", session);
    this.appendPublicEvent({ type: "session_claimed" });
    return Response.json({ claimed: true });
  }
  async erasePublicSession() {
    for (const socket of this.ctx.getWebSockets()) {
      socket.close(1008, "session erased");
    }
    await this.ctx.storage.deleteAll();
    return Response.json({ erased: true });
  }
  ensurePublicEventSchema() {
    this.ctx.storage.sql.exec(
      `CREATE TABLE IF NOT EXISTS public_session_events (
         sequence INTEGER PRIMARY KEY AUTOINCREMENT,
         event_key TEXT,
         event_json TEXT NOT NULL
       )`
    );
    const columns = this.ctx.storage.sql.exec("PRAGMA table_info(public_session_events)").toArray();
    if (!columns.some((column) => column.name === "event_key")) {
      this.ctx.storage.sql.exec(
        "ALTER TABLE public_session_events ADD COLUMN event_key TEXT"
      );
    }
    this.ctx.storage.sql.exec(
      `CREATE UNIQUE INDEX IF NOT EXISTS public_session_events_event_key
         ON public_session_events(event_key) WHERE event_key IS NOT NULL`
    );
  }
  publicEventCursor() {
    this.ensurePublicEventSchema();
    const rows = this.ctx.storage.sql.exec(
      "SELECT COALESCE(MAX(sequence), 0) AS sequence FROM public_session_events"
    ).toArray();
    return Number(rows[0]?.sequence ?? 0);
  }
  publicEvents(after) {
    this.ensurePublicEventSchema();
    return this.ctx.storage.sql.exec(
      `SELECT sequence, event_json FROM public_session_events
            WHERE sequence > ?1 ORDER BY sequence LIMIT 2000`,
      after
    ).toArray().map((row) => ({
      ...JSON.parse(row.event_json),
      sequence: row.sequence
    }));
  }
  appendPublicEvent(event, eventKey) {
    this.ensurePublicEventSchema();
    if (eventKey) {
      const existing = this.ctx.storage.sql.exec(
        `SELECT sequence, event_json FROM public_session_events
            WHERE event_key = ?1 LIMIT 1`,
        eventKey
      ).toArray();
      if (existing.length) {
        return {
          ...JSON.parse(existing[0].event_json),
          sequence: Number(existing[0].sequence)
        };
      }
    }
    const rows = this.ctx.storage.sql.exec(
      `INSERT INTO public_session_events (event_key, event_json)
         VALUES (?1, ?2) RETURNING sequence`,
      eventKey ?? null,
      JSON.stringify(event)
    ).toArray();
    const persisted = {
      ...event,
      sequence: Number(rows[0]?.sequence ?? 0)
    };
    for (const socket of this.ctx.getWebSockets()) {
      const attachment = socket.deserializeAttachment();
      if (attachment?.publicSession) socket.send(JSON.stringify(persisted));
    }
    return persisted;
  }
  sendPublicLatency(traceId, span, phase, elapsedMs) {
    if (!traceId.startsWith("public:")) return;
    const requestId = traceId.split(":").at(-1);
    if (!requestId) return;
    const frame = JSON.stringify({
      type: "latency",
      source: "session",
      span,
      phase,
      request_id: requestId,
      elapsed_ms: Math.round(elapsedMs * 10) / 10
    });
    for (const socket of this.ctx.getWebSockets()) {
      const attachment = socket.deserializeAttachment();
      if (attachment?.publicSession) socket.send(frame);
    }
  }
  async publicSessionSnapshot(session) {
    await this.publishAppliedTurnCommands();
    const transcript = await this.ctx.storage.get(
      "public-transcript"
    ) ?? [];
    const prefix = `${session.instance_ref}/`;
    const files = this.ctx.storage.sql.exec(
      `SELECT substr(key, length(?1) + 1) AS path
           FROM files WHERE key LIKE ?1 || '%' ORDER BY key LIMIT 5000`,
      prefix
    ).toArray();
    return {
      session_id: session.session_id,
      release_id: session.release_id,
      cursor: this.publicEventCursor(),
      transcript,
      files,
      queue: this.publicTurnQueue()
    };
  }
  async publicSessionFiles(url) {
    const session = await this.readPublicSessionState();
    if (!session) {
      return Response.json(
        { error: "public session is not bootstrapped" },
        { status: 409 }
      );
    }
    if (await this.publicSessionRequestExpired(session)) {
      return Response.json({ error: "public session has expired" }, { status: 410 });
    }
    const path = url.searchParams.get("path");
    if (!path) return this.publicSessionState();
    if (path.startsWith("/") || path.includes("\\") || path.split("/").some((part) => !part || part === "." || part === "..")) {
      return Response.json({ error: "invalid file path" }, { status: 400 });
    }
    ensureSchema(this.ctx.storage.sql);
    const rows = this.ctx.storage.sql.exec(
      "SELECT content FROM files WHERE key = ?1",
      `${session.instance_ref}/${path}`
    ).toArray();
    return rows.length ? new Response(rows[0].content, {
      headers: { "content-type": "text/plain; charset=utf-8" }
    }) : Response.json({ error: "file not found" }, { status: 404 });
  }
  instanceExists(instanceId) {
    ensureSchema(this.ctx.storage.sql);
    return this.ctx.storage.sql.exec("SELECT 1 AS present FROM instances WHERE instance_id = ?1", instanceId).toArray().length > 0;
  }
  hostProjection(url) {
    ensureSchema(this.ctx.storage.sql);
    if (url.pathname.match(/^\/host\/instances\/([^/]+)\/pending$/)) {
      return Response.json({ pending: null });
    }
    const result = url.pathname.match(
      /^\/host\/instances\/([^/]+)\/turns\/([^/]+)\/result$/
    );
    if (result) {
      const instanceId = decodeURIComponent(result[1]);
      const commandId = decodeURIComponent(result[2]);
      const turns = this.ctx.storage.sql.exec(
        `SELECT e.status, e.policy_block_reason, r.status AS run_status, r.summary
             FROM effects e LEFT JOIN runs r ON r.effect_id = e.effect_id
            WHERE e.instance_id = ?1 AND e.effect_id = ?2
            ORDER BY r.started_at DESC LIMIT 1`,
        instanceId,
        commandId
      ).toArray();
      if (!turns.length) return Response.json({ error: "turn not found" }, { status: 404 });
      const transcripts = this.ctx.storage.sql.exec(
        `SELECT sequence, payload_json FROM events
            WHERE instance_id = ?1 AND event_type = 'agent.turn.brokered.transcript'
              AND (correlation_id = ?2 OR causation_id = ?2)
            ORDER BY sequence DESC LIMIT 1`,
        instanceId,
        commandId
      ).toArray();
      const transcript2 = transcripts.length ? JSON.parse(transcripts[0].payload_json) : { messages: [] };
      const evidence2 = this.ctx.storage.sql.exec(
        `SELECT evidence_id AS evidence_ref, kind, subject_type, subject_id,
                  correlation_id AS command_id, created_at
             FROM evidence WHERE instance_id = ?1 AND correlation_id = ?2
            ORDER BY created_at, evidence_id`,
        instanceId,
        commandId
      ).toArray();
      let runtimeProjection;
      try {
        runtimeProjection = JSON.parse(
          hostFunctions.host_project_turn(
            makeBridge(this.ctx.storage.sql),
            instanceId,
            commandId
          )
        );
      } catch (error) {
        return Response.json(
          { error: `turn projection failed: ${String(error)}` },
          { status: 409 }
        );
      }
      return Response.json({
        ...turns[0],
        ...runtimeProjection,
        transcript_sequence: transcripts[0]?.sequence ?? 0,
        messages: transcript2.messages ?? [],
        evidence: evidence2
      });
    }
    const position = url.pathname.match(/^\/host\/instances\/([^/]+)\/position$/);
    if (position) {
      const instanceId = decodeURIComponent(position[1]);
      if (!this.instanceExists(instanceId)) {
        return Response.json({ error: "instance not found" }, { status: 404 });
      }
      try {
        return Response.json(JSON.parse(hostFunctions.host_current_position(
          makeBridge(this.ctx.storage.sql),
          instanceId
        )));
      } catch (error) {
        return Response.json({ error: `position projection failed: ${String(error)}` }, { status: 409 });
      }
    }
    const turn = url.pathname.match(/^\/host\/instances\/([^/]+)\/turns\/([^/]+)$/);
    if (turn) {
      const instanceId = decodeURIComponent(turn[1]);
      const commandId = decodeURIComponent(turn[2]);
      const rows = this.ctx.storage.sql.exec(
        `SELECT e.effect_id AS command_id, e.instance_id AS instance_ref,
                  e.status, e.policy_block_reason, e.updated_at,
                  r.run_id, r.status AS run_status, r.summary
             FROM effects e LEFT JOIN runs r ON r.effect_id = e.effect_id
            WHERE e.instance_id = ?1 AND e.effect_id = ?2
            ORDER BY r.started_at DESC LIMIT 1`,
        instanceId,
        commandId
      ).toArray();
      return rows.length ? Response.json(rows[0]) : Response.json({ error: "turn not found" }, { status: 404 });
    }
    const transcript = url.pathname.match(
      /^\/host\/instances\/([^/]+)\/turns\/([^/]+)\/transcript$/
    );
    if (transcript) {
      const instanceId = decodeURIComponent(transcript[1]);
      const commandId = decodeURIComponent(transcript[2]);
      const rows = this.ctx.storage.sql.exec(
        `SELECT sequence, payload_json FROM events
            WHERE instance_id = ?1
              AND event_type = 'agent.turn.brokered.transcript'
              AND (correlation_id = ?2 OR causation_id = ?2)
            ORDER BY sequence DESC LIMIT 1`,
        instanceId,
        commandId
      ).toArray();
      if (!rows.length) return Response.json({ sequence: 0, messages: [] });
      const payload = JSON.parse(rows[0].payload_json);
      return Response.json({ sequence: rows[0].sequence, messages: payload.messages ?? [] });
    }
    const events = url.pathname.match(/^\/host\/instances\/([^/]+)\/events$/);
    if (events) {
      const instanceId = decodeURIComponent(events[1]);
      const after = Math.max(0, Number(url.searchParams.get("after") ?? "0") || 0);
      const rows = this.ctx.storage.sql.exec(
        `SELECT event_id AS evidence_ref, sequence, event_type AS kind,
                  occurred_at, correlation_id AS command_id
             FROM events WHERE instance_id = ?1 AND sequence > ?2
            ORDER BY sequence LIMIT 500`,
        instanceId,
        after
      ).toArray();
      return Response.json({ events: rows });
    }
    const evidence = url.pathname.match(/^\/host\/instances\/([^/]+)\/evidence$/);
    if (evidence) {
      const instanceId = decodeURIComponent(evidence[1]);
      const commandId = url.searchParams.get("command_id");
      const rows = this.ctx.storage.sql.exec(
        `SELECT evidence_id AS evidence_ref, kind, subject_type, subject_id,
                  correlation_id AS command_id, summary, created_at
             FROM evidence WHERE instance_id = ?1
              AND (?2 IS NULL OR correlation_id = ?2)
            ORDER BY created_at, evidence_id LIMIT 500`,
        instanceId,
        commandId
      ).toArray();
      return Response.json({ evidence: rows });
    }
    const files = url.pathname.match(/^\/host\/instances\/([^/]+)\/files$/);
    if (files) {
      const instanceId = decodeURIComponent(files[1]);
      if (!this.instanceExists(instanceId)) {
        return Response.json({ error: "instance not found" }, { status: 404 });
      }
      const prefix = `${instanceId}/`;
      const path = url.searchParams.get("path");
      if (path != null) {
        const rows2 = this.ctx.storage.sql.exec("SELECT content FROM files WHERE key = ?1", `${prefix}${path}`).toArray();
        return rows2.length ? new Response(rows2[0].content, { headers: { "content-type": "text/plain; charset=utf-8" } }) : Response.json({ error: "file not found" }, { status: 404 });
      }
      const rows = this.ctx.storage.sql.exec(
        "SELECT substr(key, length(?1) + 1) AS path FROM files WHERE key LIKE ?1 || '%' ORDER BY key LIMIT 5000",
        prefix
      ).toArray();
      return Response.json({ files: rows });
    }
    return Response.json({ error: "not found" }, { status: 404 });
  }
  hostEvents(instanceId, after) {
    ensureSchema(this.ctx.storage.sql);
    return this.ctx.storage.sql.exec(
      `SELECT event_id AS evidence_ref, sequence, event_type AS kind,
                occurred_at, correlation_id AS command_id
           FROM events WHERE instance_id = ?1 AND sequence > ?2
          ORDER BY sequence LIMIT 500`,
      instanceId,
      after
    ).toArray();
  }
  hostEventStream(instanceId, url) {
    if (!this.instanceExists(instanceId)) {
      return Response.json({ error: "instance not found" }, { status: 404 });
    }
    const after = Math.max(0, Number(url.searchParams.get("after") ?? "0") || 0);
    const events = this.hostEvents(instanceId, after);
    const body = events.map((event) => `id: ${String(event.sequence)}
event: runtime
data: ${JSON.stringify(event)}

`).join("") + ": caught-up\n\n";
    return new Response(body, {
      headers: {
        "content-type": "text/event-stream; charset=utf-8",
        "cache-control": "no-cache, no-transform",
        "x-accel-buffering": "no"
      }
    });
  }
  openHostEventSocket(request, instanceId, url) {
    if (request.headers.get("upgrade")?.toLowerCase() !== "websocket") {
      return Response.json({ error: "websocket upgrade required" }, { status: 426 });
    }
    if (!this.instanceExists(instanceId)) {
      return Response.json({ error: "instance not found" }, { status: 404 });
    }
    const after = Math.max(0, Number(url.searchParams.get("after") ?? "0") || 0);
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    this.ctx.acceptWebSocket(server, [instanceId]);
    server.serializeAttachment({ instanceId, after });
    this.sendHostProgress(server, instanceId, after);
    return new Response(null, { status: 101, webSocket: client });
  }
  async openPublicSessionSocket(request, session, url) {
    if (request.headers.get("upgrade")?.toLowerCase() !== "websocket") {
      return Response.json({ error: "websocket upgrade required" }, { status: 426 });
    }
    if (!this.instanceExists(session.instance_ref)) {
      return Response.json(
        { error: "public session runtime is not recoverable" },
        { status: 503 }
      );
    }
    const after = Math.max(0, Number(url.searchParams.get("after") ?? "0") || 0);
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    this.ctx.acceptWebSocket(server, [session.instance_ref]);
    server.serializeAttachment({
      instanceId: session.instance_ref,
      after,
      publicSession: true
    });
    const snapshot = await this.publicSessionSnapshot(session);
    if (after > 0) {
      for (const event of this.publicEvents(after)) {
        server.send(JSON.stringify(event));
      }
    }
    server.send(
      JSON.stringify({
        type: "session_ready",
        sequence: snapshot.cursor,
        snapshot
      })
    );
    return new Response(null, { status: 101, webSocket: client });
  }
  sendHostProgress(socket, instanceId, after) {
    const events = this.hostEvents(instanceId, after);
    if (!events.length) return;
    socket.send(JSON.stringify({ type: "runtime_events", events }));
    const next = Number(events.at(-1)?.sequence ?? after);
    socket.serializeAttachment({ instanceId, after: next });
  }
  broadcastHostProgress(instanceId) {
    for (const socket of this.ctx.getWebSockets(instanceId)) {
      const attachment = socket.deserializeAttachment();
      if (attachment?.publicSession) continue;
      this.sendHostProgress(
        socket,
        attachment?.instanceId ?? instanceId,
        attachment?.after ?? 0
      );
    }
  }
  turnStreamKey(instanceId, commandId) {
    return `${instanceId}\0${commandId}`;
  }
  hostTurnDeltas(instanceId, commandId, after) {
    ensureSchema(this.ctx.storage.sql);
    return this.ctx.storage.sql.exec(
      `SELECT sequence, delta FROM host_turn_deltas
          WHERE instance_id = ?1 AND command_id = ?2 AND sequence > ?3
          ORDER BY sequence LIMIT 1000`,
      instanceId,
      commandId,
      after
    ).toArray();
  }
  /** Reconcile a retried provider stream against chunks already published for
   * this exact stable model-round idempotency key. Matching replay is
   * suppressed; segmentation/content drift fails closed instead of duplicating
   * or rewriting browser output. */
  publicProviderRoundReplay(instanceId, commandId, request) {
    if (!instanceId || !commandId) {
      throw new Error("public provider round has no durable command identity");
    }
    const roundKey = request.headers.find(
      ([name]) => name.toLowerCase() === "idempotency-key"
    )?.[1];
    if (!roundKey) {
      throw new Error("public provider round has no stable idempotency key");
    }
    this.ctx.storage.sql.exec(
      `CREATE TABLE IF NOT EXISTS public_provider_chunks (
         instance_id TEXT NOT NULL,
         command_id TEXT NOT NULL,
         round_key TEXT NOT NULL,
         chunk_index INTEGER NOT NULL,
         delta TEXT NOT NULL,
         PRIMARY KEY (instance_id, command_id, round_key, chunk_index)
       )`
    );
    const existing = this.ctx.storage.sql.exec(
      `SELECT chunk_index, delta FROM public_provider_chunks
          WHERE instance_id = ?1 AND command_id = ?2 AND round_key = ?3
          ORDER BY chunk_index`,
      instanceId,
      commandId,
      roundKey
    ).toArray();
    const priorCount = existing.length;
    let index = 0;
    return {
      accept: /* @__PURE__ */ __name((delta) => {
        const prior = existing[index];
        if (prior) {
          if (prior.chunk_index !== index || prior.delta !== delta) {
            throw new Error("retried public provider stream diverged from durable output");
          }
          index += 1;
          return false;
        }
        this.ctx.storage.sql.exec(
          `INSERT INTO public_provider_chunks
             (instance_id, command_id, round_key, chunk_index, delta)
           VALUES (?1, ?2, ?3, ?4, ?5)`,
          instanceId,
          commandId,
          roundKey,
          index,
          delta
        );
        existing.push({ chunk_index: index, delta });
        index += 1;
        return true;
      }, "accept"),
      complete: /* @__PURE__ */ __name(() => {
        if (index < priorCount) {
          throw new Error("retried public provider stream ended before durable output");
        }
      }, "complete")
    };
  }
  encodeTurnDelta(sequence, delta) {
    return this.textEncoder.encode(
      `id: ${sequence}
event: text_delta
data: ${JSON.stringify({
        type: "text_delta",
        sequence,
        delta
      })}

`
    );
  }
  turnIsTerminal(instanceId, commandId) {
    const rows = this.ctx.storage.sql.exec(
      `SELECT status FROM effects
          WHERE instance_id = ?1 AND effect_id = ?2 LIMIT 1`,
      instanceId,
      commandId
    ).toArray();
    return rows.length > 0 && ["completed", "failed", "timed_out", "cancelled", "blocked"].includes(rows[0].status);
  }
  openHostTurnStream(instanceId, commandId, url) {
    if (!this.instanceExists(instanceId)) {
      return Response.json({ error: "instance not found" }, { status: 404 });
    }
    const after = Math.max(0, Number(url.searchParams.get("after") ?? "0") || 0);
    const key = this.turnStreamKey(instanceId, commandId);
    const owner = this;
    let controllerRef;
    const body = new ReadableStream({
      start(controller) {
        controllerRef = controller;
        controller.enqueue(owner.textEncoder.encode(": connected\n\n"));
        for (const event of owner.hostTurnDeltas(instanceId, commandId, after)) {
          controller.enqueue(owner.encodeTurnDelta(event.sequence, event.delta));
        }
        if (owner.turnIsTerminal(instanceId, commandId)) {
          controller.enqueue(owner.textEncoder.encode("event: terminal\ndata: {}\n\n"));
          controller.close();
          return;
        }
        const streams = owner.turnStreams.get(key) ?? /* @__PURE__ */ new Set();
        streams.add(controller);
        owner.turnStreams.set(key, streams);
      },
      cancel() {
        if (!controllerRef) return;
        const streams = owner.turnStreams.get(key);
        streams?.delete(controllerRef);
        if (streams?.size === 0) owner.turnStreams.delete(key);
      }
    });
    return new Response(body, {
      headers: {
        "content-type": "text/event-stream; charset=utf-8",
        "cache-control": "no-cache, no-transform",
        "x-accel-buffering": "no"
      }
    });
  }
  publishHostTurnDelta(instanceId, commandId, delta) {
    if (!delta) return;
    const rows = this.ctx.storage.sql.exec(
      `INSERT INTO host_turn_deltas (instance_id, command_id, delta)
         VALUES (?1, ?2, ?3) RETURNING sequence`,
      instanceId,
      commandId,
      delta
    ).toArray();
    const sequence = rows[0]?.sequence;
    if (!Number.isSafeInteger(sequence)) return;
    if (commandId.startsWith("public:")) {
      const requestId = publicRequestId(commandId);
      this.appendPublicEvent({
        type: "text_delta",
        command_id: commandId,
        ...requestId ? { request_id: requestId } : {},
        delta
      });
      if (!this.publicFirstWebSocketDeltas.has(commandId)) {
        this.publicFirstWebSocketDeltas.add(commandId);
        const startedAt = this.publicTraceStarts.get(commandId);
        if (startedAt !== void 0) {
          this.sendPublicLatency(
            commandId,
            "public_turn",
            "websocket_first_delta_sent",
            performance.now() - startedAt
          );
        }
      }
    }
    const encoded = this.encodeTurnDelta(sequence, delta);
    for (const controller of this.turnStreams.get(
      this.turnStreamKey(instanceId, commandId)
    ) ?? []) {
      controller.enqueue(encoded);
    }
    for (const socket of this.ctx.getWebSockets(instanceId)) {
      const attachment = socket.deserializeAttachment();
      if (attachment?.publicSession) continue;
      socket.send(
        JSON.stringify({
          type: "text_delta",
          command_id: commandId,
          sequence,
          delta
        })
      );
    }
  }
  finishHostTurnStream(instanceId, commandId) {
    const key = this.turnStreamKey(instanceId, commandId);
    for (const controller of this.turnStreams.get(key) ?? []) {
      controller.enqueue(this.textEncoder.encode("event: terminal\ndata: {}\n\n"));
      controller.close();
    }
    this.turnStreams.delete(key);
    if (commandId.startsWith("public:")) return;
    for (const socket of this.ctx.getWebSockets(instanceId)) {
      socket.send(
        JSON.stringify({ type: "turn_terminal", command_id: commandId })
      );
    }
  }
  async webSocketMessage(socket, message) {
    let operationId;
    try {
      const parsed = JSON.parse(
        typeof message === "string" ? message : new TextDecoder().decode(message)
      );
      operationId = parsed.operation_id;
      const attachment = socket.deserializeAttachment();
      const instanceId = attachment?.instanceId;
      if (!instanceId) throw new Error("socket has no instance attachment");
      if (attachment?.publicSession && parsed.type === "send_message") {
        const requestId = typeof parsed.request_id === "string" ? parsed.request_id.trim() : "";
        const completed = requestId ? await this.ctx.storage.get(
          `public-turn-result:${requestId}`
        ) : void 0;
        if (completed) {
          socket.send(JSON.stringify(completed));
          return;
        }
        const inProcess = requestId ? this.publicTurns.get(requestId) : void 0;
        if (inProcess) {
          const event = await inProcess;
          if (event) socket.send(JSON.stringify(event));
          return;
        }
        const run = (async () => {
          const result = await this.beginPublicTurn(parsed);
          return this.publishPublicTurnResult(instanceId, requestId, result);
        })();
        if (requestId) this.publicTurns.set(requestId, run);
        try {
          await run;
        } finally {
          if (requestId && this.publicTurns.get(requestId) === run) {
            this.publicTurns.delete(requestId);
          }
          if (requestId) {
            for (const traceId of this.publicTraceStarts.keys()) {
              if (!traceId.endsWith(`:${requestId}`)) continue;
              this.publicTraceStarts.delete(traceId);
              this.publicFirstWebSocketDeltas.delete(traceId);
            }
          }
        }
        return;
      }
      if (attachment?.publicSession && parsed.type === "resume") {
        const after2 = Number.isSafeInteger(parsed.after) ? Math.max(0, Number(parsed.after)) : 0;
        for (const event of this.publicEvents(after2)) {
          socket.send(JSON.stringify(event));
        }
        return;
      }
      if (attachment?.publicSession && (parsed.type === "steer" || parsed.type === "follow_up")) {
        const response = await this.enqueuePublicTurnCommand(
          parsed.type,
          parsed
        );
        if (!response.ok) {
          const body = await response.json();
          throw new Error(body.error ?? `turn command rejected (${response.status})`);
        }
        return;
      }
      if (attachment?.publicSession && ["queue_edit", "queue_remove", "queue_reorder", "queue_promote"].includes(
        String(parsed.type)
      )) {
        const response = this.mutatePublicTurnQueue(parsed);
        if (!response.ok) {
          const body = await response.json();
          throw new Error(body.error ?? `queue command rejected (${response.status})`);
        }
        return;
      }
      if (attachment?.publicSession && parsed.type === "stop") {
        const requestId = typeof parsed.request_id === "string" ? parsed.request_id.trim() : "";
        const publicSession = await this.readPublicSessionState();
        if (!publicSession || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(requestId)) {
          throw new Error("stop requires a valid public request_id");
        }
        const commandId = publicCommandId(publicSession.session_id, requestId);
        const receipt = JSON.parse(
          hostFunctions.host_cancel_turn(
            makeBridge(this.ctx.storage.sql),
            instanceId,
            commandId,
            "public-audience"
          )
        );
        this.appendPublicEvent({
          type: "turn_stop_requested",
          request_id: requestId,
          command_id: commandId,
          receipt
        }, `turn-stop-requested:${commandId}`);
        this.appendPublicEvent({
          type: "turn_stopped",
          request_id: requestId,
          command_id: commandId,
          receipt,
          compatibility_alias: true
        }, `turn-stopped-compat:${commandId}`);
        return;
      }
      if (attachment?.publicSession) {
        throw new Error("unsupported public session command");
      }
      const after = Number.isSafeInteger(parsed.after) ? Number(parsed.after) : attachment?.after ?? 0;
      this.sendHostProgress(socket, instanceId, Math.max(0, after));
    } catch (error) {
      socket.send(JSON.stringify({
        type: "error",
        error: String(error),
        ...typeof operationId === "string" ? { operation_id: operationId } : {}
      }));
    }
  }
  async publishPublicTurnResult(instanceId, requestId, result) {
    this.ctx.storage.sql.exec(
      "DELETE FROM public_turn_binding WHERE singleton = 1 AND request_id = ?1",
      requestId
    );
    const body = await result.json();
    const publicSession = await this.readPublicSessionState();
    if (!publicSession) {
      throw new Error("public turn lost its durable session");
    }
    const commandId = publicCommandId(publicSession.session_id, requestId);
    const terminal = this.appendPublicEvent({
      type: result.ok ? "turn_terminal" : "error",
      request_id: requestId,
      command_id: commandId,
      status: result.status,
      body
    });
    await this.ctx.storage.put(`public-turn-result:${requestId}`, terminal);
    return terminal;
  }
  publicTurnQueue() {
    ensureSchema(this.ctx.storage.sql);
    return this.ctx.storage.sql.exec(
      `SELECT command_id, text, position
           FROM public_turn_commands
          WHERE status = 'pending'
          ORDER BY CASE kind WHEN 'steer' THEN 0 ELSE 1 END,
                   position, created_at, command_id`
    ).toArray().map((row) => ({
      command_id: row.command_id,
      text: row.text,
      position: Number(row.position)
    }));
  }
  publishPublicTurnQueue(eventKey, operationId) {
    this.appendPublicEvent(
      {
        type: "turn_queue_changed",
        queue: this.publicTurnQueue(),
        ...operationId ? { operation_id: operationId } : {}
      },
      eventKey
    );
  }
  async enqueuePublicTurnCommand(kind, parsed) {
    const session = await this.readPublicSessionState();
    if (!session) {
      return Response.json({ error: "public session is not bootstrapped" }, { status: 409 });
    }
    const message = validatePublicMessage(parsed);
    if (!message.ok) return message.response;
    ensureSchema(this.ctx.storage.sql);
    const active = this.ctx.storage.sql.exec(
      `SELECT request_id, command_id FROM public_turn_binding
          WHERE singleton = 1`
    ).toArray();
    if (active.length === 0) {
      return Response.json({ error: "session has no running turn" }, { status: 409 });
    }
    const positionRows = this.ctx.storage.sql.exec(
      `SELECT COALESCE(MAX(position), 0) + 1024 AS position
           FROM public_turn_commands
          WHERE turn_command_id = ?1 AND kind = ?2 AND status = 'pending'`,
      active[0].command_id,
      kind
    ).toArray();
    const position = Number(positionRows[0]?.position ?? 1024);
    this.ctx.storage.sql.exec(
      `INSERT INTO public_turn_commands
         (command_id, turn_command_id, kind, text, images_json, position)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6)
       ON CONFLICT(command_id) DO NOTHING`,
      message.requestId,
      active[0].command_id,
      kind,
      message.text,
      JSON.stringify(message.images),
      position
    );
    this.publishPublicTurnQueue(
      `turn-command-queue:${message.requestId}`,
      typeof parsed.operation_id === "string" ? parsed.operation_id : message.requestId
    );
    return Response.json({ admitted: true, command_id: message.requestId }, { status: 202 });
  }
  mutatePublicTurnQueue(parsed) {
    ensureSchema(this.ctx.storage.sql);
    const commandId = typeof parsed.command_id === "string" ? parsed.command_id.trim() : "";
    if (parsed.type !== "queue_reorder" && !commandId) {
      return Response.json({ error: "queue command requires command_id" }, { status: 422 });
    }
    if (parsed.type === "queue_edit") {
      const text = typeof parsed.text === "string" ? parsed.text.trim() : "";
      if (!text || new TextEncoder().encode(text).length > 256 * 1024) {
        return Response.json({ error: "queue edit requires non-empty text" }, { status: 422 });
      }
      const changed = this.ctx.storage.sql.exec(
        "UPDATE public_turn_commands SET text = ?1 WHERE command_id = ?2 AND status = 'pending'",
        text,
        commandId
      ).rowsWritten;
      if (!changed) return Response.json({ error: "queued command is no longer pending" }, { status: 409 });
    } else if (parsed.type === "queue_remove") {
      const changed = this.ctx.storage.sql.exec(
        "UPDATE public_turn_commands SET status = 'removed' WHERE command_id = ?1 AND status = 'pending'",
        commandId
      ).rowsWritten;
      if (!changed) {
        const removed = this.ctx.storage.sql.exec(
          "SELECT 1 AS present FROM public_turn_commands WHERE command_id = ?1 AND status = 'removed'",
          commandId
        ).toArray();
        if (removed.length === 0) {
          return Response.json({ error: "queued command is no longer pending" }, { status: 409 });
        }
      }
    } else if (parsed.type === "queue_promote") {
      const changed = this.ctx.storage.sql.exec(
        `UPDATE public_turn_commands SET kind = 'steer', position = 0
          WHERE command_id = ?1 AND status = 'pending'`,
        commandId
      ).rowsWritten;
      if (!changed) return Response.json({ error: "queued command is no longer pending" }, { status: 409 });
    } else if (parsed.type === "queue_reorder") {
      const ids = Array.isArray(parsed.command_ids) ? parsed.command_ids.filter((id) => typeof id === "string") : [];
      if (ids.length === 0 || new Set(ids).size !== ids.length) {
        return Response.json({ error: "queue reorder requires unique command_ids" }, { status: 422 });
      }
      ids.forEach((id, index) => {
        this.ctx.storage.sql.exec(
          "UPDATE public_turn_commands SET position = ?1 WHERE command_id = ?2 AND status = 'pending' AND kind = 'follow_up'",
          (index + 1) * 1024,
          id
        );
      });
    } else {
      return Response.json({ error: "unsupported queue command" }, { status: 422 });
    }
    const operationId = typeof parsed.operation_id === "string" ? parsed.operation_id : void 0;
    this.publishPublicTurnQueue(
      operationId ? `turn-queue-operation:${operationId}` : void 0,
      operationId
    );
    return Response.json({ updated: true });
  }
  async projectPublicAssistantSegment(instanceId, commandId) {
    const cursorKey = `public-transcript-delta-cursor:${commandId}`;
    const after = await this.ctx.storage.get(cursorKey) ?? 0;
    const deltas = this.hostTurnDeltas(instanceId, commandId, after);
    if (deltas.length === 0) return;
    const text = deltas.map((event) => event.delta).join("");
    const transcript = await this.ctx.storage.get(
      "public-transcript"
    ) ?? [];
    if (text) transcript.push({ type: "assistant", text });
    await this.ctx.storage.put({
      "public-transcript": transcript,
      [cursorKey]: deltas.at(-1).sequence
    });
  }
  async publishAppliedTurnCommands() {
    const rows = this.ctx.storage.sql.exec(
      `SELECT command_id, turn_command_id, kind, text FROM public_turn_commands
          WHERE status = 'applied' AND announced = 0 ORDER BY applied_at, command_id`
    ).toArray();
    if (rows.length === 0) return;
    for (const row of rows) {
      const active = this.ctx.storage.sql.exec(
        "SELECT request_id FROM public_turn_binding WHERE singleton = 1 AND command_id = ?1",
        row.turn_command_id
      ).toArray();
      const session = await this.readPublicSessionState();
      if (session) {
        await this.projectPublicAssistantSegment(
          session.instance_ref,
          row.turn_command_id
        );
      }
      const transcript = await this.ctx.storage.get(
        "public-transcript"
      ) ?? [];
      const projectionKey = `public-transcript-user:${row.command_id}`;
      if (!await this.ctx.storage.get(projectionKey)) {
        transcript.push({ type: "user", text: row.text });
        await this.ctx.storage.put({
          "public-transcript": transcript,
          [projectionKey]: true
        });
        this.appendPublicEvent({
          type: "message_accepted",
          request_id: row.command_id,
          command_id: row.turn_command_id,
          ...active[0]?.request_id ? { parent_request_id: active[0].request_id } : {},
          role: "user",
          text: row.text
        }, `turn-command-message:${row.command_id}`);
      }
      this.appendPublicEvent({
        type: "turn_command_applied",
        request_id: row.command_id,
        command_id: row.turn_command_id,
        kind: row.kind
      }, `turn-command-applied:${row.command_id}`);
      this.ctx.storage.sql.exec(
        "UPDATE public_turn_commands SET announced = 1 WHERE command_id = ?1",
        row.command_id
      );
    }
    this.publishPublicTurnQueue();
  }
  async beginPublicTurn(parsed) {
    const session = await this.readPublicSessionState();
    if (!session) {
      return Response.json(
        { error: "public session is not bootstrapped" },
        { status: 409 }
      );
    }
    if (await this.publicSessionRequestExpired(session)) {
      return Response.json({ error: "public session has expired" }, { status: 410 });
    }
    const message = validatePublicMessage(parsed);
    if (!message.ok) return message.response;
    const { requestId, text, images: imageBodies } = message;
    ensureSchema(this.ctx.storage.sql);
    const commandId = publicCommandId(session.session_id, requestId);
    const active = this.ctx.storage.sql.exec(
      "SELECT request_id, command_id FROM public_turn_binding WHERE singleton = 1"
    ).toArray();
    if (active.length > 0 && active[0].request_id !== requestId) {
      return Response.json({ error: "a public turn is already running" }, { status: 409 });
    }
    this.ctx.storage.sql.exec(
      `INSERT INTO public_turn_binding (singleton, request_id, command_id)
       VALUES (1, ?1, ?2)
       ON CONFLICT(singleton) DO UPDATE SET request_id = excluded.request_id,
         command_id = excluded.command_id`,
      requestId,
      commandId
    );
    const imageRefs = imageBodies.map((_image, index) => ({
      handle: "turn_images",
      kind: "image",
      selector: String(index)
    }));
    const activityAt = Date.now();
    this.admitLifecycle({ kind: "observeActivity", atMs: activityAt });
    session.last_activity_unix_ms = activityAt;
    await this.ctx.storage.put("public-session-state", session);
    await this.schedulePublicSessionExpiry(session);
    const capabilities = new Set(session.capabilities ?? []);
    const resources = [];
    if (capabilities.has("workspace.read") || capabilities.has("workspace.write")) {
      resources.push({ handle: "project", kind: "file_store", selector: null });
    }
    if (capabilities.has("command.run")) {
      resources.push({ handle: "command", kind: "command", selector: null });
    }
    const turnStartedAt = performance.now();
    this.publicTraceStarts.set(commandId, turnStartedAt);
    const traceBoundary = /* @__PURE__ */ __name((boundary) => {
      const elapsedMs = performance.now() - turnStartedAt;
      console.log(JSON.stringify({
        event: "gaugewright_public_turn_boundary",
        trace_id: commandId,
        boundary,
        elapsed_ms: Math.round(elapsedMs * 10) / 10
      }));
      this.sendPublicLatency(commandId, "public_turn", boundary, elapsedMs);
    }, "traceBoundary");
    traceBoundary("command_received");
    traceBoundary("reservation_start");
    const reservation = await this.sessionAdmissionCommand(
      session,
      "admit",
      { request_id: requestId }
    );
    if (reservation instanceof Response) return reservation;
    traceBoundary("reservation_complete");
    const transcript = await this.ctx.storage.get(
      "public-transcript"
    ) ?? [];
    const userProjectionKey = `public-transcript-user:${requestId}`;
    if (!await this.ctx.storage.get(userProjectionKey)) {
      transcript.push({ type: "user", text });
      await this.ctx.storage.put({
        "public-transcript": transcript,
        [userProjectionKey]: true
      });
      this.appendPublicEvent({
        type: "message_accepted",
        request_id: requestId,
        command_id: commandId,
        role: "user",
        text
      });
    }
    const reservationRef = typeof reservation.reservation_ref === "string" ? reservation.reservation_ref : "";
    traceBoundary("runtime_turn_start");
    const turn = await this.beginHostTurn({
      command: {
        protocol: "whipplescript.host.v1",
        command_id: commandId,
        run_ref: `public:run:${session.session_id}:${requestId}`,
        instance_ref: session.instance_ref,
        package_version_ref: session.package_version_ref,
        policy: {
          epoch: session.host_policy.epoch,
          envelope_hash: session.envelope_hash,
          signer: session.host_policy.expected_signer,
          ...session.policy_key_id ? { key_id: session.policy_key_id } : {}
        },
        // The signed public host policy maps this stable runtime principal to
        // the `audience` IFC role. Per-visitor identity remains attributable in
        // the session-owned principal record and command/session correlation;
        // putting a session-specific string here would be unmapped by the
        // immutable policy and silently demote the agent to `public`.
        actor_ref: "audience",
        input: { text, images: imageRefs },
        resources,
        provider_binding: {
          binding_id: session.host_policy.provider_binding_ref,
          credential: {
            credential_id: session.host_policy.credential_class
          }
        },
        placement_ceiling_ref: session.host_policy.placement_ref
      },
      package: session.package,
      image_bodies: imageBodies
    }, session.credential_ref);
    await this.projectPublicAssistantSegment(session.instance_ref, commandId);
    traceBoundary("runtime_turn_complete");
    const turnBody = await turn.clone().json();
    const receiptStatus = typeof turnBody.receipt?.status === "string" ? turnBody.receipt.status : "";
    const turnSucceeded = turn.ok && receiptStatus === "completed";
    const turnCancelled = turn.ok && receiptStatus === "cancelled";
    if (turn.ok && turnBody.outcome === "parked" && !receiptStatus) {
      return turn;
    }
    const usage = turnBody.usage;
    const hasExactUsage = typeof usage?.usage_ref === "string" && Number.isSafeInteger(usage.input_tokens) && Number(usage.input_tokens) >= 0 && Number.isSafeInteger(usage.cached_input_tokens) && Number(usage.cached_input_tokens) >= 0 && Number(usage.cached_input_tokens) <= Number(usage.input_tokens) && Number.isSafeInteger(usage.output_tokens) && Number(usage.output_tokens) >= 0;
    if (turnSucceeded && !hasExactUsage) {
      traceBoundary("settlement_start");
      await this.sessionAdmissionCommand(
        session,
        "release",
        { reservation_ref: reservationRef }
      );
      traceBoundary("settlement_complete");
      return Response.json(
        { error: "provider completed without exact usage evidence" },
        { status: 502 }
      );
    }
    traceBoundary("settlement_start");
    const settlement = await this.sessionAdmissionCommand(
      session,
      turnSucceeded ? "settle" : "release",
      {
        reservation_ref: reservationRef,
        ...turnSucceeded && hasExactUsage ? { usage } : {}
      }
    );
    if (settlement instanceof Response) return settlement;
    traceBoundary("settlement_complete");
    if (turnSucceeded) {
      for (const tool of turnBody.output?.tool_calls ?? []) {
        if (typeof tool.call_id !== "string" || typeof tool.name !== "string") {
          continue;
        }
        this.appendPublicEvent(
          {
            type: "tool_call",
            request_id: requestId,
            command_id: commandId,
            call_id: tool.call_id,
            tool: tool.name,
            arguments: tool.arguments ?? null,
            label_ref: turnBody.output?.label_ref ?? null
          },
          `turn:${requestId}:tool:${tool.call_id}:call`
        );
        if (typeof tool.ok === "boolean") {
          this.appendPublicEvent(
            {
              type: "tool_result",
              request_id: requestId,
              command_id: commandId,
              call_id: tool.call_id,
              ok: tool.ok,
              ...typeof tool.result === "string" ? { result: tool.result } : {}
            },
            `turn:${requestId}:tool:${tool.call_id}:result`
          );
        }
      }
      const snapshot = await this.publicSessionSnapshot(session);
      this.appendPublicEvent(
        {
          type: "workspace_snapshot",
          request_id: requestId,
          command_id: commandId,
          files: snapshot.files
        },
        `turn:${requestId}:workspace`
      );
      this.appendPublicEvent(
        {
          type: "usage",
          request_id: requestId,
          command_id: commandId,
          usage,
          settlement
        },
        `turn:${requestId}:usage`
      );
    }
    return Response.json(
      {
        ...turnBody,
        runtime_outcome: turnBody.outcome,
        outcome: turnSucceeded ? "terminal" : turnCancelled ? "interrupted" : "failed"
      },
      { status: turnSucceeded || turnCancelled ? 200 : 502 }
    );
  }
  async settlePublicContinuation(commandId, body, succeeded) {
    const session = await this.readPublicSessionState();
    if (!session) throw new Error("public session is not bootstrapped");
    const requestId = publicRequestId(commandId);
    const reservation = await this.sessionAdmissionCommand(
      session,
      "admit",
      { request_id: requestId }
    );
    if (reservation instanceof Response) {
      throw new Error(`cannot recover public reservation (${reservation.status})`);
    }
    const reservationRef = typeof reservation.reservation_ref === "string" ? reservation.reservation_ref : "";
    const usage = body.usage;
    const exactUsage = typeof usage?.usage_ref === "string" && Number.isSafeInteger(usage.input_tokens) && Number.isSafeInteger(usage.cached_input_tokens) && Number.isSafeInteger(usage.output_tokens);
    const settlement = await this.sessionAdmissionCommand(
      session,
      succeeded && exactUsage ? "settle" : "release",
      {
        reservation_ref: reservationRef,
        ...succeeded && exactUsage ? { usage } : {}
      }
    );
    if (settlement instanceof Response) {
      throw new Error(`public continuation settlement failed (${settlement.status})`);
    }
    if (succeeded && exactUsage) {
      await this.projectPublicAssistantSegment(session.instance_ref, commandId);
      const output = body.output;
      for (const tool of output?.tool_calls ?? []) {
        if (typeof tool.call_id !== "string" || typeof tool.name !== "string") continue;
        this.appendPublicEvent({
          type: "tool_call",
          request_id: requestId,
          command_id: commandId,
          call_id: tool.call_id,
          tool: tool.name,
          arguments: tool.arguments ?? null,
          label_ref: output?.label_ref ?? null
        }, `turn:${requestId}:tool:${tool.call_id}:call`);
        if (typeof tool.ok === "boolean") {
          this.appendPublicEvent({
            type: "tool_result",
            request_id: requestId,
            command_id: commandId,
            call_id: tool.call_id,
            ok: tool.ok,
            ...typeof tool.result === "string" ? { result: tool.result } : {}
          }, `turn:${requestId}:tool:${tool.call_id}:result`);
        }
      }
      const snapshot = await this.publicSessionSnapshot(session);
      this.appendPublicEvent({
        type: "workspace_snapshot",
        request_id: requestId,
        command_id: commandId,
        files: snapshot.files
      }, `turn:${requestId}:workspace`);
      this.appendPublicEvent({
        type: "usage",
        request_id: requestId,
        command_id: commandId,
        usage,
        settlement
      }, `turn:${requestId}:usage`);
    }
    const terminal = this.appendPublicEvent({
      type: succeeded && exactUsage ? "turn_terminal" : "error",
      request_id: requestId,
      command_id: commandId,
      status: succeeded && exactUsage ? 200 : 502,
      body
    }, `turn:${requestId}:terminal`);
    await this.ctx.storage.put(`public-turn-result:${requestId}`, terminal);
  }
  /**
   * The generic admission and settlement port (DR-0049 §1). The runtime calls
   * it before a metered operation and after a terminal one; it does not know
   * what is being metered, who funds it, or what the embedder scope denotes.
   */
  async sessionAdmissionCommand(session, command, body) {
    const namespace = this.env.SESSION_ADMISSION;
    const token = this.env.WHIP_PUBLIC_CONTROL_TOKEN?.trim();
    if (!namespace || !token) {
      return Response.json(
        { error: "session admission channel is unavailable" },
        { status: 503 }
      );
    }
    const stub = namespace.get(namespace.idFromName(session.admission_scope));
    const response = await stub.fetch(
      new Request(
        `https://admission.internal/internal/sessions/${session.session_id}/${command}`,
        {
          method: "POST",
          headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json"
          },
          body: JSON.stringify(body)
        }
      )
    );
    const value = await response.json();
    return response.ok ? value : Response.json(value, { status: response.status });
  }
  // ---- Session lifecycle (DR-0049 §3/§4) -----------------------------------
  // Phase is the fold of these events. Nothing stores a phase, and no predicate
  // inside the fold reads a clock: every time is stamped here, at the host
  // boundary, and presented to the reducer as an observation.
  lifecycleEvents() {
    ensureSchema(this.ctx.storage.sql);
    return this.ctx.storage.sql.exec("SELECT event_json FROM session_lifecycle_events ORDER BY sequence").toArray().map((row) => JSON.parse(row.event_json));
  }
  lifecycleState() {
    return fold(this.lifecycleEvents());
  }
  /**
   * Read and validate the durable session record (DR-0054 Phase A). Absent
   * record -> null. A legacy-but-recognizable record is normalized with logged
   * compatibility repairs and has its lifecycle log backfilled so the session
   * is expirable. An unrecognizable record throws
   * `UnreadableSessionStateError` — fail closed, never a raw TypeError, and
   * never a deletion.
   */
  async readPublicSessionState() {
    const raw = await this.ctx.storage.get("public-session-state");
    if (raw === void 0 || raw === null) return null;
    const { session, repairs } = normalizeStoredSessionState(raw);
    if (repairs.length) {
      console.log(
        JSON.stringify({
          event: "session_state_compat_normalized",
          session_id: session.session_id,
          repaired: repairs
        })
      );
    }
    this.backfillLegacyLifecycle(session);
    return session;
  }
  /**
   * A session record that predates the lifecycle log folds to `init`, and
   * `init` refuses `observeDeadline` — such a session never expired and never
   * tore down. Backfill the log (append-only) with the open/activate/activity
   * observations the record itself attests, so the ordinary retention deadline
   * exists from the next fold (DR-0054 Phase A). A session opened through the
   * reducer has a non-empty log and is untouched.
   */
  backfillLegacyLifecycle(session) {
    if (this.lifecycleEvents().length > 0) return;
    console.log(
      JSON.stringify({
        event: "legacy_session_lifecycle_backfilled",
        session_id: session.session_id,
        opened_at_unix_ms: session.created_at_unix_ms
      })
    );
    this.admitLifecycle({
      kind: "open",
      atMs: session.created_at_unix_ms,
      collectionDeclared: Boolean(session.collection)
    });
    this.admitLifecycle({ kind: "activate" });
    if (session.last_activity_unix_ms > session.created_at_unix_ms) {
      this.admitLifecycle({
        kind: "observeActivity",
        atMs: session.last_activity_unix_ms
      });
    }
  }
  /** Admit one command. Returns the folded state, or null when refused. */
  admitLifecycle(command) {
    const state = this.lifecycleState();
    const outcome = decide(state, command);
    if (isRejection(outcome)) return null;
    for (const event of outcome) {
      this.ctx.storage.sql.exec(
        "INSERT INTO session_lifecycle_events (event_json) VALUES (?1)",
        JSON.stringify(event)
      );
    }
    return outcome.reduce(evolve, state);
  }
  leaseBounds(session) {
    return {
      idleTtlMs: session.retention.idle_ttl_seconds * 1e3,
      absoluteTtlMs: session.retention.absolute_ttl_seconds * 1e3
    };
  }
  publicSessionExpiryAt(session) {
    const bounds = this.leaseBounds(session);
    return deadlineAt(
      this.lifecycleState(),
      bounds.idleTtlMs,
      bounds.absoluteTtlMs
    );
  }
  /**
   * Present the current time as a deadline observation and report whether the
   * folded phase now refuses traffic. A refused command (for example a session
   * that has not activated) leaves the fold untouched.
   */
  publicSessionExpired(session) {
    const bounds = this.leaseBounds(session);
    const admitted = this.admitLifecycle({
      kind: "observeDeadline",
      atMs: Date.now(),
      ...bounds
    });
    const state = admitted ?? this.lifecycleState();
    return state.phase === "expiring" || state.phase === "tornDown";
  }
  async publicSessionRequestExpired(session) {
    if (!this.publicSessionExpired(session)) return false;
    await this.schedulePublicSessionExpiry(session);
    return true;
  }
  async schedulePublicSessionExpiry(session) {
    await this.armAlarm(session);
  }
  /**
   * One object has one alarm, and two independent things need to wake it: the
   * session's retention deadline and the instance's next due timer. Whichever
   * comes first must win, and **neither may erase the other**.
   *
   * That second half was missing. The drive loop called `deleteAlarm()`
   * unconditionally whenever an instance parked with nothing due, and driving
   * is the last thing every turn does — so every turn silently disarmed
   * retention. A session that ran even one turn then never expired, its
   * declared collection stayed `pending` forever (the alarm is the only path
   * that emits it), and the drain it should have fed was permanently empty.
   * Only a session that never ran a turn kept its alarm and expired correctly,
   * which is exactly the shape the symptom took in production.
   *
   * So the two deadlines are now folded here, and the drive loop records its
   * due time as a fact rather than by writing the shared alarm directly.
   */
  async armAlarm(session) {
    const deadlines = [];
    const live = session ?? await this.readPublicSessionState();
    if (live && this.lifecycleState().phase !== "tornDown") {
      deadlines.push(
        Math.max(this.publicSessionExpiryAt(live), Date.now() + 1e3)
      );
    }
    const due = await this.ctx.storage.get(INSTANCE_DUE_KEY);
    if (due != null) deadlines.push(due);
    if (deadlines.length === 0) {
      console.log(
        JSON.stringify({ event: "arm_alarm", armed: null, session: Boolean(live) })
      );
      await this.ctx.storage.deleteAlarm();
      return;
    }
    const at = Math.min(...deadlines);
    console.log(
      JSON.stringify({
        event: "arm_alarm",
        armed: at,
        in_ms: at - Date.now(),
        phase: this.lifecycleState().phase,
        instance_due: due ?? null
      })
    );
    await this.ctx.storage.setAlarm(at);
  }
  /**
   * Terminal teardown: remove payload resolution, preserve the lifecycle event
   * log and session metadata (DR-0049 §7). Storage-wide deletion is retired
   * from this path — it destroyed audit metadata alongside payload.
   */
  /**
   * The terminal artifact effect (DR-0049 §5). Driven by host and release
   * structure, never by an agent tool call, and settled through the reducer so
   * retry and exactly-once come from the machine rather than a catch block.
   *
   * A transient refusal leaves the collection pending, which keeps the session
   * out of a terminal phase; only a definitive refusal marks it failed.
   */
  async emitCollection(session) {
    const policy = session.collection;
    if (!policy) {
      console.log(
        JSON.stringify({ event: "emit_collection", skipped: "no policy on session" })
      );
      return;
    }
    if (this.lifecycleState().collection !== "pending") {
      console.log(
        JSON.stringify({
          event: "emit_collection",
          skipped: "not pending",
          collection: this.lifecycleState().collection
        })
      );
      return;
    }
    ensureSchema(this.ctx.storage.sql);
    const prefix = `${session.instance_ref}/`;
    const rows = this.ctx.storage.sql.exec("SELECT key, content FROM files WHERE key LIKE ?1 || '%'", prefix).toArray();
    const files = new Map(
      rows.map(({ key, content }) => [key.slice(prefix.length), content])
    );
    const workspace = selectWorkspace(files, policy);
    this.ensurePublicEventSchema();
    const transcript = policy.transcript_eligible ? this.ctx.storage.sql.exec("SELECT event_json FROM public_session_events ORDER BY sequence").toArray().map((row) => JSON.parse(row.event_json)) : null;
    const revision = await this.ctx.storage.get("collection-revision") ?? 1;
    const envelope = {
      schema_ref: policy.schema_ref,
      session_id: session.session_id,
      release_id: session.release_id,
      revision,
      produced_at_unix_ms: Date.now()
    };
    const plaintext = canonicalArtifact(envelope, workspace, transcript);
    if (plaintext.byteLength > policy.max_artifact_bytes) {
      console.log(
        JSON.stringify({
          event: "emit_collection",
          failed: "artifact exceeds the declared bound",
          byte_len: plaintext.byteLength,
          max_artifact_bytes: policy.max_artifact_bytes
        })
      );
      this.admitLifecycle({ kind: "failCollection" });
      this.appendPublicEvent({
        type: "collection_failed",
        reason: "artifact exceeds the declared bound"
      });
      return;
    }
    let sealed;
    try {
      sealed = await sealArtifact(
        envelope,
        plaintext,
        policy.recipient_public_keys,
        session.admission_scope
      );
    } catch (error) {
      console.log(
        JSON.stringify({
          event: "emit_collection",
          failed: "artifact sealing failed",
          error: String(error).slice(0, 300)
        })
      );
      this.admitLifecycle({ kind: "failCollection" });
      this.appendPublicEvent({
        type: "collection_failed",
        reason: String(error)
      });
      return;
    }
    const deposited = await this.sessionAdmissionCommand(session, "deposit", {
      idempotency_key: `${session.session_id}:${revision}`,
      artifact: sealed
    });
    if (deposited instanceof Response) {
      console.log(
        JSON.stringify({
          event: "emit_collection",
          deposit_refused: deposited.status,
          body: (await deposited.clone().text()).slice(0, 200)
        })
      );
      if (deposited.status >= 400 && deposited.status < 500) {
        this.admitLifecycle({ kind: "failCollection" });
        this.appendPublicEvent({
          type: "collection_failed",
          reason: `admission refused the deposit: ${deposited.status}`
        });
      }
      return;
    }
    this.admitLifecycle({ kind: "settleCollection" });
    this.appendPublicEvent({ type: "collection_settled", revision });
    console.log(
      JSON.stringify({
        event: "emit_collection",
        deposited: true,
        session_id: session.session_id,
        revision
      })
    );
  }
  async tombstonePublicSession() {
    ensureSchema(this.ctx.storage.sql);
    for (const table of [
      "files",
      "host_turn_images",
      "host_turn_deltas",
      "public_provider_chunks",
      "public_session_events",
      "events",
      "facts",
      "artifacts",
      "workspaces",
      "content_blobs"
    ]) {
      try {
        this.ctx.storage.sql.exec(`DELETE FROM ${table}`);
      } catch {
      }
    }
    for (const statement of [
      `UPDATE instances SET
          last_error = 'retention tombstone (DR-0054): payload removed; prior status ' || status,
          status = 'tombstoned',
          completed_at = COALESCE(completed_at, CURRENT_TIMESTAMP),
          updated_at = CURRENT_TIMESTAMP
        WHERE status NOT IN ('completed', 'failed', 'timed_out', 'cancelled', 'tombstoned')`,
      `UPDATE effects SET status = 'tombstoned', updated_at = CURRENT_TIMESTAMP
        WHERE status NOT IN ('completed', 'failed', 'timed_out', 'cancelled', 'tombstoned')`,
      `UPDATE runs SET status = 'tombstoned', completed_at = COALESCE(completed_at, CURRENT_TIMESTAMP)
        WHERE status = 'running'`,
      `UPDATE leases SET status = 'tombstoned', released_at = COALESCE(released_at, CURRENT_TIMESTAMP)
        WHERE released_at IS NULL`
    ]) {
      try {
        this.ctx.storage.sql.exec(statement);
      } catch {
      }
    }
    try {
      this.ctx.storage.sql.exec(
        `INSERT INTO diagnostics (diagnostic_id, severity, code, message)
         VALUES (?1, 'info', 'session.tombstoned',
                 'retention tombstone (DR-0054): payload removed; handles, lifecycle events, and audit metadata retained')`,
        `tombstone:${crypto.randomUUID()}`
      );
    } catch {
    }
    const keys = [...(await this.ctx.storage.list()).keys()].filter(
      (key) => key === "public-session-state" || key.startsWith("host-package:") || key.startsWith("host-policy:") || key.startsWith("public-turn-result:")
    );
    if (keys.length) await this.ctx.storage.delete(keys);
  }
  webSocketClose(_socket, _code, _reason) {
  }
  syncHostFiles(instanceId, parsed) {
    ensureSchema(this.ctx.storage.sql);
    if (!this.instanceExists(instanceId)) {
      return Response.json({ error: "instance not found" }, { status: 404 });
    }
    const files = parsed.files;
    if (!Array.isArray(files) || files.length > 5e3) {
      return Response.json({ error: "files must be an array of at most 5000 entries" }, { status: 400 });
    }
    const normalized = /* @__PURE__ */ new Map();
    for (const value of files) {
      if (!value || typeof value !== "object" || Array.isArray(value)) {
        return Response.json({ error: "each file must be an object" }, { status: 400 });
      }
      const candidate = value;
      if (typeof candidate.path !== "string" || typeof candidate.content !== "string") {
        return Response.json({ error: "each file requires path and content strings" }, { status: 400 });
      }
      const path = candidate.path.replaceAll("\\", "/");
      if (!path || path.startsWith("/") || path.includes("\0") || path.split("/").some((part) => !part || part === "." || part === "..")) {
        return Response.json({ error: `invalid workspace path: ${candidate.path}` }, { status: 400 });
      }
      if (new TextEncoder().encode(candidate.content).length > 8 * 1024 * 1024) {
        return Response.json({ error: `workspace file is too large: ${path}` }, { status: 413 });
      }
      normalized.set(path, candidate.content);
    }
    const prefix = `${instanceId}/`;
    const retainPaths = parsed.retain_paths;
    if (retainPaths !== void 0) {
      if (!Array.isArray(retainPaths) || retainPaths.some((path) => typeof path !== "string")) {
        return Response.json({ error: "retain_paths must be an array of strings" }, { status: 400 });
      }
      const retained = new Set(retainPaths);
      const current = this.ctx.storage.sql.exec("SELECT key FROM files WHERE key LIKE ?1 || '%'", prefix).toArray();
      for (const row of current) {
        if (!retained.has(row.key.slice(prefix.length))) {
          this.ctx.storage.sql.exec("DELETE FROM files WHERE key = ?1", row.key);
        }
      }
    }
    if (parsed.delete_missing === true) {
      const current = this.ctx.storage.sql.exec("SELECT key FROM files WHERE key LIKE ?1 || '%'", prefix).toArray();
      for (const row of current) {
        const path = row.key.slice(prefix.length);
        if (!normalized.has(path)) this.ctx.storage.sql.exec("DELETE FROM files WHERE key = ?1", row.key);
      }
    }
    for (const [path, content] of normalized) {
      this.ctx.storage.sql.exec(
        `INSERT INTO files (key, content) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET content = excluded.content`,
        `${prefix}${path}`,
        content
      );
    }
    return Response.json({ synced: normalized.size });
  }
  async hostCheckpoint(instanceId, command, parsed) {
    const cutId = typeof parsed.cut_id === "string" ? parsed.cut_id.trim() : "";
    if (!cutId) return Response.json({ error: `${command} requires cut_id` }, { status: 400 });
    const packageDocs = await this.ctx.storage.get(
      `host-package:${instanceId}`
    );
    if (!packageDocs) return Response.json({ error: "host package not found" }, { status: 404 });
    try {
      const instance = WasmDurableInstance.attach_host(
        makeBridge(this.ctx.storage.sql),
        instanceId,
        packageDocs.manifest,
        packageDocs.source,
        packageDocs.system_prompt,
        void 0
      );
      const report = command === "checkpoint" ? instance.checkpoint(cutId) : instance.restore(cutId);
      return new Response(report, { headers: { "content-type": "application/json" } });
    } catch (error) {
      return Response.json({ error: `${command} rejected: ${String(error)}` }, { status: 400 });
    }
  }
  pinPrivateGovernanceRoot(request) {
    const signer = request.headers.get("x-gaugewright-private-governance-signer")?.trim();
    const key = request.headers.get("x-gaugewright-private-governance-key")?.trim().toLowerCase();
    const callback = request.headers.get("x-gaugewright-private-callback")?.trim();
    const executionGrant = request.headers.get("x-gaugewright-private-execution-grant")?.trim();
    const executionSignature = request.headers.get("x-gaugewright-private-execution-signature")?.trim();
    if (!signer && !key) return void 0;
    if (!signer || !/^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/.test(signer)) {
      return Response.json(
        { error: "private Home governance signer is invalid" },
        { status: 403 }
      );
    }
    if (!key || !/^04[0-9a-f]{128}$/.test(key)) {
      return Response.json(
        { error: "private Home governance key is invalid" },
        { status: 403 }
      );
    }
    let callbackUrl;
    try {
      callbackUrl = new URL(callback ?? "");
    } catch {
      return Response.json(
        { error: "private Home callback is invalid" },
        { status: 403 }
      );
    }
    if (callbackUrl.protocol !== "https:" || callbackUrl.username || callbackUrl.password || callbackUrl.search || callbackUrl.hash || !executionGrant || executionGrant.length > 16384 || !executionSignature || executionSignature.length > 1024) {
      return Response.json(
        { error: "private Home callback authorization is invalid" },
        { status: 403 }
      );
    }
    ensureSchema(this.ctx.storage.sql);
    this.ctx.storage.sql.exec(
      `CREATE TABLE IF NOT EXISTS private_governance_root (
         singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
         signer TEXT NOT NULL,
         key TEXT NOT NULL
       )`
    );
    const existing = this.ctx.storage.sql.exec(
      "SELECT signer, key FROM private_governance_root WHERE singleton = 1"
    ).toArray();
    if (existing.length === 0) {
      this.ctx.storage.sql.exec(
        `INSERT INTO private_governance_root (singleton, signer, key)
         VALUES (1, ?1, ?2)`,
        signer,
        key
      );
    } else if (existing[0].signer !== signer || existing[0].key !== key) {
      return Response.json(
        { error: "private Home governance root changed for this command" },
        { status: 403 }
      );
    }
    this.ctx.storage.sql.exec(
      `CREATE TABLE IF NOT EXISTS private_execution_context (
         singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
         callback TEXT NOT NULL,
         execution_grant TEXT NOT NULL,
         execution_signature TEXT NOT NULL
       )`
    );
    const execution = this.ctx.storage.sql.exec(
      `SELECT callback FROM private_execution_context WHERE singleton = 1`
    ).toArray();
    if (execution.length === 1 && execution[0].callback !== callbackUrl.toString()) {
      return Response.json(
        { error: "private Home callback changed for this command" },
        { status: 403 }
      );
    }
    this.ctx.storage.sql.exec(
      `INSERT INTO private_execution_context
         (singleton, callback, execution_grant, execution_signature)
       VALUES (1, ?1, ?2, ?3)
       ON CONFLICT(singleton) DO UPDATE SET
         execution_grant = excluded.execution_grant,
         execution_signature = excluded.execution_signature`,
      callbackUrl.toString(),
      executionGrant,
      executionSignature
    );
    return void 0;
  }
  privateModelBrokerConfig() {
    ensureSchema(this.ctx.storage.sql);
    this.ctx.storage.sql.exec(
      `CREATE TABLE IF NOT EXISTS private_execution_context (
         singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
         callback TEXT NOT NULL,
         execution_grant TEXT NOT NULL,
         execution_signature TEXT NOT NULL
       )`
    );
    const rows = this.ctx.storage.sql.exec(
      `SELECT callback, execution_grant, execution_signature
           FROM private_execution_context WHERE singleton = 1`
    ).toArray();
    if (rows.length !== 1) return void 0;
    return {
      url: rows[0].callback,
      executionGrant: rows[0].execution_grant,
      executionSignature: rows[0].execution_signature
    };
  }
  pinnedGovernanceRoot() {
    ensureSchema(this.ctx.storage.sql);
    const publicRoot = this.ctx.storage.sql.exec(
      `SELECT governance_signer AS signer, governance_key AS key
           FROM public_session_metadata WHERE singleton = 1`
    ).toArray();
    if (publicRoot.length === 1) {
      return publicRoot[0];
    }
    this.ctx.storage.sql.exec(
      `CREATE TABLE IF NOT EXISTS private_governance_root (
         singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
         signer TEXT NOT NULL,
         key TEXT NOT NULL
       )`
    );
    const privateRoot = this.ctx.storage.sql.exec(
      `SELECT signer, key FROM private_governance_root
          WHERE singleton = 1`
    ).toArray();
    if (privateRoot.length === 1) {
      return privateRoot[0];
    }
    const signer = this.env.GAUGEDESK_GOVERNANCE_SIGNER?.trim();
    const key = this.env.GAUGEDESK_GOVERNANCE_KEY?.trim();
    if (!signer || !key) {
      return Response.json(
        { error: "hosted placement has no pinned GaugeDesk governance root" },
        { status: 503 }
      );
    }
    return { signer, key };
  }
  async bootstrapPublicSession(parsed) {
    const candidate = parsed;
    const releaseId = typeof candidate.release_id === "string" ? candidate.release_id : "";
    const admissionScope = typeof candidate.admission_scope === "string" ? candidate.admission_scope : "";
    const sessionId = typeof candidate.session_id === "string" ? candidate.session_id : "";
    const packageVersionRef = typeof candidate.package_version_ref === "string" ? candidate.package_version_ref : "";
    const packageDocs = candidate.package;
    const policy = candidate.host_policy;
    const retention = candidate.retention;
    if (!/^sha256:[0-9a-f]{64}$/.test(releaseId) || !/^[A-Za-z0-9_-]{1,128}$/.test(admissionScope) || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(sessionId) || !packageVersionRef || !packageDocs || typeof packageDocs.manifest !== "string" || typeof packageDocs.source !== "string" || typeof packageDocs.system_prompt !== "string" || !policy || !Number.isSafeInteger(policy.epoch) || Number(policy.epoch) <= 0 || typeof policy.signed_envelope !== "string" || typeof policy.expected_signer !== "string" || typeof policy.signer_public_key_hex !== "string" || typeof policy.provider_binding_ref !== "string" || typeof policy.credential_class !== "string" || typeof policy.placement_ref !== "string" || // Absent under managed funding, and that absence is the signal the turn
    // runs on the metered gateway rather than a customer credential — see
    // `resolveAdmittedProvider`. Present means BYOK and must still be an exact
    // reference; a malformed one is refused rather than silently treated as
    // absent, which would turn a typo into a bill charged to the wrong party.
    candidate.credential_ref !== void 0 && (typeof candidate.credential_ref !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/.test(candidate.credential_ref)) || !Array.isArray(candidate.capabilities) || !candidate.principal || typeof candidate.principal.label !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/.test(candidate.principal.label) || candidate.principal.subject_hash !== void 0 && (typeof candidate.principal.subject_hash !== "string" || !/^[0-9a-f]{64}$/.test(candidate.principal.subject_hash)) || !retention || !Number.isSafeInteger(retention.idle_ttl_seconds) || retention.idle_ttl_seconds <= 0 || !Number.isSafeInteger(retention.absolute_ttl_seconds) || retention.absolute_ttl_seconds < retention.idle_ttl_seconds) {
      return Response.json(
        { error: "public session bootstrap is incomplete" },
        { status: 400 }
      );
    }
    const initialWorkspace = candidate.initial_workspace;
    if (!Array.isArray(initialWorkspace) || initialWorkspace.length > 5e3) {
      return Response.json(
        { error: "public initial workspace is invalid" },
        { status: 400 }
      );
    }
    const workspaceFiles = [];
    try {
      for (const file of initialWorkspace) {
        if (!file || typeof file.path !== "string" || typeof file.base64 !== "string" || typeof file.sha256 !== "string") {
          throw new Error("initial workspace file is incomplete");
        }
        const binary = atob(file.base64);
        const bytes = Uint8Array.from(
          binary,
          (character) => character.charCodeAt(0)
        );
        workspaceFiles.push({
          path: file.path.replace(/^workspace\//, ""),
          content: new TextDecoder("utf-8", {
            fatal: true,
            ignoreBOM: false
          }).decode(bytes)
        });
      }
    } catch (error) {
      return Response.json(
        { error: `initial workspace rejected: ${String(error)}` },
        { status: 400 }
      );
    }
    ensureSchema(this.ctx.storage.sql);
    const existing = this.ctx.storage.sql.exec(
      `SELECT release_id, session_id, instance_ref
           FROM public_session_metadata WHERE singleton = 1`
    ).toArray();
    if (existing.length === 1) {
      if (existing[0].release_id === releaseId && existing[0].session_id === sessionId) {
        return Response.json({
          release_id: releaseId,
          session_id: sessionId,
          created: false
        });
      }
      return Response.json(
        { error: "session object is already pinned to another engagement" },
        { status: 409 }
      );
    }
    let verifiedPolicy;
    try {
      verifiedPolicy = JSON.parse(
        verifyHostPolicy(
          BigInt(policy.epoch),
          policy.signed_envelope,
          policy.expected_signer,
          policy.signer_public_key_hex
        )
      );
    } catch (error) {
      return Response.json(
        { error: `public host policy rejected: ${String(error)}` },
        { status: 403 }
      );
    }
    const openCommand = {
      protocol: "whipplescript.host.v1",
      request_id: `public:${sessionId}:open`,
      package_version_ref: packageVersionRef,
      policy: {
        epoch: policy.epoch,
        envelope_hash: verifiedPolicy.envelope_hash,
        signer: verifiedPolicy.signer,
        ...verifiedPolicy.key_id ? { key_id: verifiedPolicy.key_id } : {}
      }
    };
    let opened;
    try {
      opened = JSON.parse(
        hostFunctions.host_open_instance(
          makeBridge(this.ctx.storage.sql),
          BigInt(policy.epoch),
          policy.signed_envelope,
          policy.expected_signer,
          policy.signer_public_key_hex,
          JSON.stringify(openCommand),
          packageDocs.manifest,
          packageDocs.source,
          packageDocs.system_prompt
        )
      );
    } catch (error) {
      return Response.json(
        { error: `public instance rejected: ${String(error)}` },
        { status: 400 }
      );
    }
    const instanceRef = typeof opened.instance_ref === "string" ? opened.instance_ref : "";
    if (!instanceRef) {
      return Response.json(
        { error: "public runtime returned no instance reference" },
        { status: 500 }
      );
    }
    const synced = this.syncHostFiles(instanceRef, {
      files: workspaceFiles,
      delete_missing: true
    });
    if (!synced.ok) return synced;
    await this.ctx.storage.put(
      `host-policy:${policy.epoch}:${verifiedPolicy.envelope_hash}`,
      {
        epoch: policy.epoch,
        signed_envelope: policy.signed_envelope,
        policy: verifiedPolicy
      }
    );
    await this.ctx.storage.put(`host-package:${instanceRef}`, packageDocs);
    const now = Date.now();
    const sessionState = {
      ...candidate,
      instance_ref: instanceRef,
      envelope_hash: verifiedPolicy.envelope_hash,
      policy_key_id: verifiedPolicy.key_id,
      created_at_unix_ms: now,
      last_activity_unix_ms: now
    };
    await this.ctx.storage.put("public-session-state", sessionState);
    this.admitLifecycle({
      kind: "open",
      atMs: now,
      collectionDeclared: Boolean(candidate.collection)
    });
    this.admitLifecycle({ kind: "activate" });
    await this.schedulePublicSessionExpiry(sessionState);
    this.ctx.storage.sql.exec(
      `INSERT INTO public_session_metadata
        (singleton, release_id, session_id, instance_ref, governance_signer, governance_key)
       VALUES (1, ?1, ?2, ?3, ?4, ?5)`,
      releaseId,
      sessionId,
      instanceRef,
      policy.expected_signer,
      policy.signer_public_key_hex
    );
    return Response.json(
      {
        release_id: releaseId,
        session_id: sessionId,
        created: true
      },
      { status: 201 }
    );
  }
  async hostPolicy(command) {
    const cited = command.policy;
    if (!cited || typeof cited !== "object" || Array.isArray(cited)) {
      return Response.json({ error: "host command does not cite a policy epoch" }, { status: 400 });
    }
    const policyRef = cited;
    if (!Number.isSafeInteger(policyRef.epoch) || typeof policyRef.envelope_hash !== "string") {
      return Response.json({ error: "host command has an invalid policy reference" }, { status: 400 });
    }
    const key = `host-policy:${String(policyRef.epoch)}:${policyRef.envelope_hash}`;
    const policy = await this.ctx.storage.get(key);
    return policy ?? Response.json(
      { error: "placement policy has not been bootstrapped" },
      { status: 409 }
    );
  }
  hostCommandRequest(parsed) {
    const command = parsed.command;
    const packageValue = parsed.package;
    if (!command || typeof command !== "object" || Array.isArray(command)) {
      return Response.json({ error: "host request requires command" }, { status: 400 });
    }
    if (!packageValue || typeof packageValue !== "object" || Array.isArray(packageValue)) {
      return Response.json({ error: "host request requires package documents" }, { status: 400 });
    }
    const candidate = packageValue;
    if (typeof candidate.manifest !== "string" || typeof candidate.source !== "string" || typeof candidate.system_prompt !== "string") {
      return Response.json(
        { error: "package requires manifest, source, and system_prompt strings" },
        { status: 400 }
      );
    }
    return {
      command,
      package: candidate,
      image_bodies: Array.isArray(parsed.image_bodies) ? parsed.image_bodies : []
    };
  }
  storeAdmittedImages(request) {
    const command = request.command;
    const instanceId = typeof command.instance_ref === "string" ? command.instance_ref : "";
    const commandId = typeof command.command_id === "string" ? command.command_id : "";
    const input = command.input;
    const refs = input && typeof input === "object" && !Array.isArray(input) ? input.images : void 0;
    const imageRefs = Array.isArray(refs) ? refs : [];
    if (imageRefs.length !== request.image_bodies.length || imageRefs.length > 16) {
      return Response.json(
        { error: "image bodies must exactly match at most 16 admitted image refs" },
        { status: 400 }
      );
    }
    let totalBytes = 0;
    const normalized = [];
    for (let index = 0; index < imageRefs.length; index += 1) {
      const ref = imageRefs[index];
      const body = request.image_bodies[index];
      if (!ref || typeof ref !== "object" || Array.isArray(ref) || !body || typeof body !== "object" || Array.isArray(body)) {
        return Response.json({ error: "invalid admitted image broker entry" }, { status: 400 });
      }
      const admitted = ref;
      const candidate = body;
      if (admitted.handle !== "turn_images" || admitted.kind !== "image" || admitted.selector !== String(index) || typeof candidate.media_type !== "string" || !["image/png", "image/jpeg", "image/webp", "image/gif"].includes(candidate.media_type) || typeof candidate.data_base64 !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(candidate.data_base64)) {
        return Response.json(
          { error: "image body does not match its admitted ref or supported media type" },
          { status: 400 }
        );
      }
      let bytes;
      try {
        bytes = atob(candidate.data_base64).length;
      } catch {
        return Response.json({ error: "image body is not valid base64" }, { status: 400 });
      }
      totalBytes += bytes;
      if (bytes > 16 * 1024 * 1024 || totalBytes > 32 * 1024 * 1024) {
        return Response.json({ error: "admitted image body limit exceeded" }, { status: 413 });
      }
      normalized.push({
        selector: String(index),
        mediaType: candidate.media_type,
        data: candidate.data_base64
      });
    }
    this.ctx.storage.sql.exec(
      "DELETE FROM host_turn_images WHERE instance_id = ?1 AND command_id = ?2",
      instanceId,
      commandId
    );
    for (const image of normalized) {
      this.ctx.storage.sql.exec(
        `INSERT INTO host_turn_images
          (instance_id, command_id, selector, media_type, data_base64)
         VALUES (?1, ?2, ?3, ?4, ?5)`,
        instanceId,
        commandId,
        image.selector,
        image.mediaType,
        image.data
      );
    }
    return void 0;
  }
  async openHostInstance(parsed) {
    const request = this.hostCommandRequest(parsed);
    if (request instanceof Response) return request;
    const policy = await this.hostPolicy(request.command);
    if (policy instanceof Response) return policy;
    const root = this.pinnedGovernanceRoot();
    if (root instanceof Response) return root;
    ensureSchema(this.ctx.storage.sql);
    try {
      const opened = JSON.parse(
        hostFunctions.host_open_instance(
          makeBridge(this.ctx.storage.sql),
          BigInt(policy.epoch),
          policy.signed_envelope,
          root.signer,
          root.key,
          JSON.stringify(request.command),
          request.package.manifest,
          request.package.source,
          request.package.system_prompt
        )
      );
      await this.ctx.storage.put(
        `host-package:${String(opened.instance_ref)}`,
        request.package
      );
      return Response.json(opened, { status: 201 });
    } catch (error) {
      return Response.json(
        { error: `instance rejected: ${error instanceof Error ? error.message : String(error)}` },
        { status: 400 }
      );
    }
  }
  /**
   * Which broker realization funds this turn (ADR 0085 §3).
   *
   * For a public session the choice is *whether an exact deployment credential
   * was admitted*: one means BYOK, so the turn runs `direct` against the
   * customer's own key; none means managed funding, so it runs `managed` on the
   * service's metered gateway and the owner is billed from usage.
   *
   * Reading the absence of a credential as the managed signal is deliberate.
   * The alternative — a separate "funding mode" flag — could disagree with the
   * credential actually present, and the failure would be silent and expensive:
   * a turn billed to the wrong party. Here the two cannot disagree, because
   * there is only one fact.
   */
  resolveAdmittedProvider(admission, exactPublicCredentialRef) {
    try {
      const privateBroker = this.privateModelBrokerConfig();
      return resolveAdmittedProvider(
        admission,
        privateBroker ? {
          ...this.env,
          WHIP_MODEL_BROKER_URL: privateBroker.url,
          WHIP_MODEL_BROKER_TOKEN: void 0,
          WHIP_MODEL_BROKER_EXECUTION_GRANT: privateBroker.executionGrant,
          WHIP_MODEL_BROKER_EXECUTION_SIGNATURE: privateBroker.executionSignature
        } : this.env,
        this.isPublicSession() ? exactPublicCredentialRef ? "direct" : "managed" : "model-broker"
      );
    } catch (error) {
      return Response.json(
        { error: error instanceof Error ? error.message : String(error) },
        { status: 503 }
      );
    }
  }
  isPublicSession() {
    ensureSchema(this.ctx.storage.sql);
    return this.ctx.storage.sql.exec(
      "SELECT 1 AS present FROM public_session_metadata WHERE singleton = 1"
    ).toArray().length === 1;
  }
  async beginHostTurn(parsed, exactPublicCredentialRef) {
    const request = this.hostCommandRequest(parsed);
    if (request instanceof Response) return request;
    const policy = await this.hostPolicy(request.command);
    if (policy instanceof Response) return policy;
    const root = this.pinnedGovernanceRoot();
    if (root instanceof Response) return root;
    ensureSchema(this.ctx.storage.sql);
    const common = [
      BigInt(policy.epoch),
      policy.signed_envelope,
      root.signer,
      root.key,
      JSON.stringify(request.command),
      request.package.manifest,
      request.package.source,
      request.package.system_prompt
    ];
    try {
      const admission = JSON.parse(
        hostFunctions.host_validate_turn(makeBridge(this.ctx.storage.sql), ...common)
      );
      const admittedBinding = this.resolveAdmittedProvider(
        admission,
        exactPublicCredentialRef
      );
      if (admittedBinding instanceof Response) return admittedBinding;
      const binding = exactPublicCredentialRef ? bindExactPublicCredential(admittedBinding, exactPublicCredentialRef) : admittedBinding;
      const imageError = this.storeAdmittedImages(request);
      if (imageError) return imageError;
      const created = hostFunctions.host_begin_turn(
        makeBridge(this.ctx.storage.sql),
        ...common,
        binding.provider,
        binding.model,
        binding.base_url
      );
      const instanceId = String(request.command.instance_ref ?? "");
      if (!instanceId) {
        return Response.json({ error: "admitted host turn is missing its runtime binding" }, { status: 503 });
      }
      const instance = WasmDurableInstance.attach_host(
        makeBridge(this.ctx.storage.sql),
        instanceId,
        request.package.manifest,
        request.package.source,
        request.package.system_prompt,
        JSON.stringify({
          provider: binding.provider,
          base_url: binding.base_url,
          api_key: binding.api_key,
          model: binding.model,
          session_id: instanceId,
          cache_key: String(request.command.command_id ?? "")
        })
      );
      const commandId = String(request.command.command_id ?? "");
      const driven = await this.driveInstance(
        instance,
        instanceId,
        binding,
        (delta) => this.publishHostTurnDelta(instanceId, commandId, delta),
        commandId
      );
      const runtimeProjection = JSON.parse(
        hostFunctions.host_project_turn(
          makeBridge(this.ctx.storage.sql),
          instanceId,
          commandId
        )
      );
      const durableUsage = runtimeProjection.usage_observation;
      const durableOutput = runtimeProjection.output_observation;
      this.ctx.storage.sql.exec(
        "DELETE FROM host_turn_images WHERE instance_id = ?1 AND command_id = ?2",
        instanceId,
        commandId
      );
      if (driven.outcome !== "parked") {
        this.finishHostTurnStream(instanceId, commandId);
      }
      console.log(JSON.stringify({
        event: "gaugewright_turn_timing",
        trace_id: commandId,
        component: "durable_object",
        timing_ms: driven.timing
      }));
      return Response.json(
        {
          admitted: true,
          created,
          command_id: request.command.command_id,
          status: driven.status,
          outcome: driven.outcome,
          timing_ms: driven.timing,
          ...runtimeProjection.receipt ? { receipt: runtimeProjection.receipt } : {},
          ...durableUsage ? {
            usage: {
              usage_ref: durableUsage.usage_ref,
              input_tokens: durableUsage.input_tokens,
              cached_input_tokens: durableUsage.cached_input_tokens,
              output_tokens: durableUsage.output_tokens,
              // Carried only when the round ran on the metered rail, so the
              // embedder can reconcile true cost against gateway telemetry
              // rather than trusting an estimated rate card (ADR 0085 §3).
              //
              // Taken from the *host's* observation rather than the runtime
              // projection, and the split is the point: WhippleScript owns
              // the token counts as signed evidence, while the gateway's log
              // id is something only this Worker saw, on a response header.
              // Folding a host observation into the runtime's meter would
              // misattribute who vouched for it.
              // Every round's log id, not the last one's. A turn is billed
              // as a whole; pricing it from its final round under-bills by
              // however many rounds preceded it.
              ...driven.gateway_log_ids?.length ? { reconciliation_refs: driven.gateway_log_ids } : {}
            }
          } : {},
          ...durableOutput ? { output: durableOutput } : {}
        },
        { status: driven.outcome === "failed" ? 502 : 200 }
      );
    } catch (error) {
      const instanceId = typeof request.command.instance_ref === "string" ? request.command.instance_ref : "";
      const commandId = typeof request.command.command_id === "string" ? request.command.command_id : "";
      if (instanceId && commandId) {
        this.ctx.storage.sql.exec(
          "DELETE FROM host_turn_images WHERE instance_id = ?1 AND command_id = ?2",
          instanceId,
          commandId
        );
        this.finishHostTurnStream(instanceId, commandId);
      }
      return Response.json(
        { error: `turn rejected: ${error instanceof Error ? error.message : String(error)}` },
        { status: 400 }
      );
    }
  }
  async exportHostFork(instanceId, url) {
    ensureSchema(this.ctx.storage.sql);
    const sequence = Number(url.searchParams.get("sequence"));
    if (!Number.isSafeInteger(sequence) || sequence <= 0) {
      return Response.json({ error: "fork export requires a positive exact sequence" }, { status: 400 });
    }
    const packageDocs = await this.ctx.storage.get(
      `host-package:${instanceId}`
    );
    if (!packageDocs) return Response.json({ error: "host package not found" }, { status: 404 });
    const rows = this.ctx.storage.sql.exec("SELECT input_json FROM instances WHERE instance_id = ?1", instanceId).toArray();
    if (!rows.length) return Response.json({ error: "instance not found" }, { status: 404 });
    const metadata = JSON.parse(rows[0].input_json);
    const epoch = metadata.policy?.epoch;
    const envelopeHash = metadata.policy?.envelope_hash;
    if (!Number.isSafeInteger(epoch) || typeof envelopeHash !== "string") {
      return Response.json({ error: "source instance has no host policy binding" }, { status: 409 });
    }
    const policy = await this.ctx.storage.get(
      `host-policy:${String(epoch)}:${envelopeHash}`
    );
    if (!policy) return Response.json({ error: "source policy bootstrap not found" }, { status: 409 });
    const root = this.pinnedGovernanceRoot();
    if (root instanceof Response) return root;
    try {
      return Response.json(JSON.parse(hostFunctions.host_export_thread(
        makeBridge(this.ctx.storage.sql),
        BigInt(epoch),
        policy.signed_envelope,
        root.signer,
        root.key,
        JSON.stringify({ instance_ref: instanceId, sequence }),
        packageDocs.manifest,
        packageDocs.source,
        packageDocs.system_prompt
      )));
    } catch (error) {
      return Response.json({ error: `fork export rejected: ${String(error)}` }, { status: 409 });
    }
  }
  async importHostFork(parsed) {
    const request = this.hostCommandRequest(parsed);
    if (request instanceof Response) return request;
    const exported = parsed.export;
    if (!exported || typeof exported !== "object" || Array.isArray(exported)) {
      return Response.json({ error: "fork import requires a source export" }, { status: 400 });
    }
    const policy = await this.hostPolicy(request.command);
    if (policy instanceof Response) return policy;
    const root = this.pinnedGovernanceRoot();
    if (root instanceof Response) return root;
    ensureSchema(this.ctx.storage.sql);
    try {
      const forked = JSON.parse(hostFunctions.host_import_fork(
        makeBridge(this.ctx.storage.sql),
        BigInt(policy.epoch),
        policy.signed_envelope,
        root.signer,
        root.key,
        JSON.stringify(request.command),
        JSON.stringify(exported),
        request.package.manifest,
        request.package.source,
        request.package.system_prompt
      ));
      await this.ctx.storage.put(
        `host-package:${String(forked.target?.instance_ref ?? "")}`,
        request.package
      );
      return Response.json(forked, { status: 201 });
    } catch (error) {
      return Response.json({ error: `fork import rejected: ${String(error)}` }, { status: 409 });
    }
  }
  async bootstrapHostPolicy(parsed) {
    const epoch = typeof parsed.epoch === "number" ? parsed.epoch : Number.NaN;
    const signedEnvelope = typeof parsed.signed_envelope === "string" ? parsed.signed_envelope : void 0;
    const root = this.pinnedGovernanceRoot();
    if (!Number.isSafeInteger(epoch) || epoch <= 0 || !signedEnvelope) {
      return Response.json(
        { error: "host policy requires a positive epoch and signed_envelope" },
        { status: 400 }
      );
    }
    if (root instanceof Response) return root;
    let policy;
    try {
      policy = JSON.parse(
        verifyHostPolicy(BigInt(epoch), signedEnvelope, root.signer, root.key)
      );
    } catch (error) {
      return Response.json(
        { error: `policy rejected: ${error instanceof Error ? error.message : String(error)}` },
        { status: 403 }
      );
    }
    const key = `host-policy:${epoch}:${policy.envelope_hash}`;
    const existing = await this.ctx.storage.get(key);
    if (existing) {
      return Response.json(existing.policy);
    }
    const bootstrap = {
      epoch,
      signed_envelope: signedEnvelope,
      policy
    };
    await this.ctx.storage.put(key, bootstrap);
    return Response.json(policy, { status: 201 });
  }
  // The DO's single wake-up (DR-0033 Phase 6): a parked instance with pending
  // timers/deadlines scheduled this; re-enter and drive — the due-time pass
  // fires the timers, the rule pass sees the facts, and the run continues.
  async alarm() {
    try {
      await this.sessionRetentionAlarm();
    } catch (error) {
      if (!(error instanceof UnknownLifecycleEventError) && !(error instanceof UnreadableSessionStateError) && !(error instanceof UnsupportedSchemaVersionError)) {
        throw error;
      }
      console.log(
        JSON.stringify({
          event: "session_retention_fail_closed",
          error: String(error)
        })
      );
      const due = await this.ctx.storage.get(INSTANCE_DUE_KEY);
      const retryAt = Date.now() + 60 * 60 * 1e3;
      await this.ctx.storage.setAlarm(
        due != null ? Math.min(due, retryAt) : retryAt
      );
    }
    const bootstrap = await this.ctx.storage.get("bootstrap");
    if (bootstrap) {
      const result = await this.drive(bootstrap);
      console.log(`alarm fired: drove instance to ${result.status} (${result.outcome})`);
    }
  }
  async sessionRetentionAlarm() {
    const publicSession = await this.readPublicSessionState();
    if (publicSession) {
      if (!this.publicSessionExpired(publicSession)) {
        await this.schedulePublicSessionExpiry(publicSession);
      } else if (this.lifecycleState().phase !== "tornDown") {
        await this.emitCollection(publicSession);
        const torn = this.admitLifecycle({ kind: "tearDown" });
        if (!torn) {
          await this.schedulePublicSessionExpiry(publicSession);
        } else {
          const expired = await this.sessionAdmissionCommand(
            publicSession,
            "expire",
            {}
          );
          if (expired instanceof Response) {
            throw new Error(
              `session admission refused expiry: ${expired.status} ${await expired.text()}`
            );
          }
          for (const socket of this.ctx.getWebSockets()) {
            socket.close(1001, "session expired");
          }
          await this.tombstonePublicSession();
        }
      }
    }
  }
  // Build (get-or-create) the wasm instance from the persisted bootstrap, wiring
  // the effect ports from DO secrets/bindings. Shared by `drive` (the step loop)
  // and the operator command path (checkpoint/restore).
  makeInstance(bootstrap) {
    ensureSchema(this.ctx.storage.sql);
    const bridge = makeBridge(this.ctx.storage.sql);
    const anthropicConfig = /* @__PURE__ */ __name((model, maxTokens) => this.env.ANTHROPIC_API_KEY ? JSON.stringify({
      provider: "anthropic",
      base_url: this.env.WHIP_PROVIDER_BASE_URL ?? "https://api.anthropic.com",
      api_key: this.env.ANTHROPIC_API_KEY,
      model,
      max_tokens: maxTokens
    }) : void 0, "anthropicConfig");
    const coerceConfig = anthropicConfig("claude-3-5-sonnet-latest", 1024);
    const agentConfig = anthropicConfig("claude-3-5-sonnet-latest", 4096);
    const execConfig = this.env.WHIP_EXECUTOR_URL ? JSON.stringify({
      base_url: this.env.WHIP_EXECUTOR_URL,
      environment_epoch: this.env.WHIP_COMPUTE_ENV_HASH,
      env: {
        ...this.env.ANTHROPIC_API_KEY ? { ANTHROPIC_API_KEY: this.env.ANTHROPIC_API_KEY } : {},
        ...this.env.OPENAI_API_KEY ? { OPENAI_API_KEY: this.env.OPENAI_API_KEY } : {}
      },
      auth_token: this.env.WHIP_EXECUTOR_TOKEN
    }) : void 0;
    const turnConfig = this.env.WHIP_TURN_URL ? JSON.stringify({
      base_url: this.env.WHIP_TURN_URL,
      provider: this.env.ANTHROPIC_API_KEY ? {
        provider: "anthropic",
        base_url: this.env.WHIP_PROVIDER_BASE_URL ?? "https://api.anthropic.com",
        api_key: this.env.ANTHROPIC_API_KEY,
        model: "claude-3-5-sonnet-latest",
        max_tokens: 4096
      } : { provider: "fixture" },
      auth_token: this.env.WHIP_EXECUTOR_TOKEN
    }) : void 0;
    return WasmDurableInstance.create(
      bridge,
      bootstrap.program,
      bootstrap.input,
      bootstrap.principal,
      coerceConfig,
      agentConfig,
      this.env.WHIP_PROJECT_CONTEXT_JSON,
      execConfig,
      this.env.WHIP_SCRIPT_CAPABILITIES_JSON,
      turnConfig
    );
  }
  async drive(bootstrap) {
    return this.driveInstance(this.makeInstance(bootstrap));
  }
  async driveInstance(instance, hostedInstanceId, providerBinding, onTextDelta, traceId) {
    const startedAt = performance.now();
    const timing = {};
    const mark = /* @__PURE__ */ __name((event) => {
      if (timing[event] !== void 0) return;
      timing[event] = Math.round((performance.now() - startedAt) * 10) / 10;
      console.log(JSON.stringify({
        event: "gaugewright_turn_boundary",
        trace_id: traceId ?? hostedInstanceId ?? "unscoped",
        boundary: event,
        elapsed_ms: timing[event]
      }));
      this.sendPublicLatency(
        traceId ?? "",
        "runtime",
        event,
        timing[event]
      );
    }, "mark");
    let responseJson = void 0;
    let step = 0;
    let transportFailures = 0;
    let usage;
    const gatewayLogIds = [];
    const observeUsage = /* @__PURE__ */ __name((observed) => {
      usage = observed;
    }, "observeUsage");
    const observeGatewayLog = /* @__PURE__ */ __name((id) => {
      if (id && !gatewayLogIds.includes(id)) gatewayLogIds.push(id);
    }, "observeGatewayLog");
    for (; ; ) {
      const stepStartedAt = performance.now();
      const outcome = JSON.parse(instance.step(responseJson, Date.now()));
      if (hostedInstanceId) await this.publishAppliedTurnCommands();
      timing[`wasm_step_${step}_ms`] = Math.round((performance.now() - stepStartedAt) * 10) / 10;
      step += 1;
      if (hostedInstanceId) this.broadcastHostProgress(hostedInstanceId);
      if (outcome.kind === "needs_http") {
        mark("model_round_start");
        if (providerBinding?.execution === "model-broker") {
          try {
            const privateBroker = this.privateModelBrokerConfig();
            responseJson = await performModelBrokerFetch(
              outcome.request,
              providerBinding,
              privateBroker ?? {
                url: this.env.WHIP_MODEL_BROKER_URL,
                token: this.env.WHIP_MODEL_BROKER_TOKEN
              },
              fetch,
              (delta) => {
                mark("runtime_first_delta");
                onTextDelta?.(delta);
              },
              traceId,
              (event, _elapsedMs) => mark(event)
            );
            transportFailures = 0;
            mark("model_round_complete");
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            console.log(`model broker transport failed: ${message}`);
            transportFailures += 1;
            if (transportFailures >= 3) {
              throw new Error(`model broker failed repeatedly: ${message}`);
            }
            responseJson = JSON.stringify({ error: message });
          }
        } else if (providerBinding?.execution === "managed") {
          try {
            const replay = providerBinding.credential_class ? this.publicProviderRoundReplay(
              hostedInstanceId ?? "",
              traceId ?? "",
              outcome.request
            ) : void 0;
            responseJson = await performManagedGatewayFetch(
              outcome.request,
              providerBinding,
              { token: /* @__PURE__ */ __name(() => this.env.WHIP_GATEWAY_TOKEN, "token") },
              fetch,
              (delta) => {
                if (replay && !replay.accept(delta)) return;
                mark("runtime_first_delta");
                onTextDelta?.(delta);
              },
              (event, _elapsedMs) => mark(event),
              observeUsage,
              observeGatewayLog
            );
            replay?.complete();
            transportFailures = 0;
            mark("model_round_complete");
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            console.log(`managed gateway transport failed: ${message}`);
            transportFailures += 1;
            if (transportFailures >= 3) {
              throw new Error(`managed gateway failed repeatedly: ${message}`);
            }
            responseJson = JSON.stringify({ error: message });
          }
        } else if (providerBinding?.execution === "direct") {
          try {
            const replay = providerBinding.credential_class ? this.publicProviderRoundReplay(
              hostedInstanceId ?? "",
              traceId ?? "",
              outcome.request
            ) : void 0;
            responseJson = await performDirectProviderFetch(
              outcome.request,
              providerBinding,
              {
                resolve: /* @__PURE__ */ __name((credentialRef) => this.resolveOwnerPublicCredential(credentialRef), "resolve")
              },
              fetch,
              (delta) => {
                if (replay && !replay.accept(delta)) return;
                mark("runtime_first_delta");
                onTextDelta?.(delta);
              },
              (event, _elapsedMs) => mark(event),
              (observed) => {
                observeUsage(observed);
              }
            );
            replay?.complete();
            transportFailures = 0;
            mark("model_round_complete");
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            console.log(`direct provider transport failed: ${message}`);
            transportFailures += 1;
            if (transportFailures >= 3) {
              throw new Error(`direct provider failed repeatedly: ${message}`);
            }
            responseJson = JSON.stringify({ error: message });
          }
        } else {
          responseJson = await performFetch(outcome.request, this.env);
        }
        continue;
      }
      if (outcome.kind === "parked" && outcome.next_due_unix_ms != null) {
        const at = Math.max(outcome.next_due_unix_ms, Date.now() + 1);
        await this.ctx.storage.put(INSTANCE_DUE_KEY, at);
      } else {
        await this.ctx.storage.delete(INSTANCE_DUE_KEY);
      }
      await this.armAlarm();
      mark("drive_complete");
      return {
        status: instance.status(),
        outcome: outcome.kind,
        timing,
        ...usage ? { usage } : {},
        ...gatewayLogIds.length > 0 ? { gateway_log_ids: gatewayLogIds } : {}
      };
    }
  }
  async resolveOwnerPublicCredential(credentialRef) {
    const ownerId = /^credential:public:([0-9a-f]{64}):(?:openai|anthropic):[0-9a-f]{32}$/.exec(credentialRef)?.[1];
    const token = this.env.WHIP_PUBLIC_CONTROL_TOKEN?.trim();
    if (!ownerId || !this.env.PUBLIC_CREDENTIALS || !token) {
      throw new Error(`direct provider credential ${credentialRef} is unavailable`);
    }
    const response = await this.env.PUBLIC_CREDENTIALS.get(this.env.PUBLIC_CREDENTIALS.idFromName(ownerId)).fetch("https://credential.internal/resolve", {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json"
      },
      body: JSON.stringify({ credential_ref: credentialRef })
    });
    if (!response.ok) {
      throw new Error(`direct provider credential ${credentialRef} is unavailable`);
    }
    return response.json();
  }
};
var index_default = {
  async fetch(request, env, _ctx) {
    const url = new URL(request.url);
    if (url.pathname === "/healthz") {
      return Response.json({ ok: true });
    }
    const authError = controlAuthError(request, env) ?? requestBodyTooLarge(request);
    if (authError) {
      return authError;
    }
    const placement = url.pathname.match(
      /^\/v1\/tenants\/([^/]+)\/placements\/([^/]+)(\/host(?:\/.*)?)$/
    );
    let id;
    let forwarded = request;
    if (placement) {
      let tenantId;
      let placementId;
      try {
        tenantId = decodeURIComponent(placement[1]);
        placementId = decodeURIComponent(placement[2]);
      } catch {
        return Response.json(
          { error: "invalid tenant or placement id" },
          { status: 400 }
        );
      }
      const validId = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
      if (!validId.test(tenantId) || !validId.test(placementId)) {
        return Response.json({ error: "invalid tenant or placement id" }, { status: 400 });
      }
      id = `tenant:${tenantId}:placement:${placementId}`;
      const inner = new URL(request.url);
      inner.pathname = placement[3];
      forwarded = new Request(inner, request);
    } else {
      const legacy = url.pathname === "/start" || url.pathname === "/host/policy" || url.pathname === "/host/instances/open" || url.pathname === "/host/turns" || url.pathname === "/host/forks/import" || /^\/host\/instances\/[^/]+\/(events|evidence|files|position|pending|checkpoint|restore)$/.test(url.pathname) || /^\/host\/instances\/[^/]+\/events\/(stream|live)$/.test(url.pathname) || /^\/host\/instances\/[^/]+\/human\/answer$/.test(url.pathname) || /^\/host\/instances\/[^/]+\/fork-export$/.test(url.pathname) || /^\/host\/instances\/[^/]+\/files\/sync$/.test(url.pathname) || /^\/host\/instances\/[^/]+\/turns\/[^/]+(?:\/transcript|\/result|\/cancel|\/stream)?$/.test(url.pathname);
      if (!legacy) return Response.json({ error: "not found" }, { status: 404 });
      id = url.searchParams.get("id") ?? "default";
    }
    const stub = env.WORKFLOW_INSTANCE.get(env.WORKFLOW_INSTANCE.idFromName(id));
    return stub.fetch(forwarded);
  }
};
export {
  ExecutorContainer,
  WorkflowInstance,
  index_default as default
};
//# sourceMappingURL=index.js.map
