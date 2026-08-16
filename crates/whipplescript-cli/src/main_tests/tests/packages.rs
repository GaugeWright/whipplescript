//! Package manifest, lock, and registry behaviour (`package_*`).
//!
//! Split out of `main_tests/tests.rs`; `use super::*` keeps the shared
//! fixtures and the crate-root imports in scope.

use super::*;
#[test]
fn package_manifest_rejects_old_manifest_without_package_schema() {
    let error = package_manifest_from_json(
        Path::new("memory.json"),
        include_str!("../../../../../examples/legacy-plugin-manifests/memory.json").to_owned(),
    )
    .expect_err("old manifest shape should be rejected");

    assert!(
        error.contains("must have non-empty `schema` string"),
        "{error}"
    );
}

#[test]
fn package_manifest_accepts_first_class_library_shape() {
    let manifest = package_manifest_from_json(
        Path::new("memory.json"),
        include_str!("../../../vendored-std/manifests/memory.json").to_owned(),
    )
    .expect("manifest parses");

    assert_eq!(manifest.package_id, "std.memory");
    assert!(manifest
        .registry
        .libraries
        .iter()
        .any(|library| library.id == "std.memory" && library.version == "0.1.0"));
    let query_contract = manifest
        .registry
        .effect_contracts
        .iter()
        .find(|contract| contract.id == "memory.query")
        .expect("memory query contract");
    assert_eq!(query_contract.effect_kind, "capability.call");
    assert_eq!(
        query_contract.validation,
        TypedOutputValidation::RuntimeBoundary
    );
    let write_contract = manifest
        .registry
        .effect_contracts
        .iter()
        .find(|contract| contract.id == "memory.write")
        .expect("memory write contract");
    assert_eq!(write_contract.effect_kind, "capability.call");
    assert_eq!(
        write_contract.validation,
        TypedOutputValidation::RuntimeBoundary
    );
    let recall_form = manifest
        .registry
        .constructs
        .iter()
        .find(|form| form.id == "memory.recall")
        .expect("memory recall construct");
    assert_eq!(recall_form.library_id, "std.memory");
    assert_eq!(recall_form.construct_family, "effect_operation");
    assert_eq!(recall_form.keyword, "recall");
    assert_eq!(recall_form.scope, "rule_body");
    assert_eq!(recall_form.lowering_target, "capability_call");
    assert_eq!(
        recall_form.target_capability.as_deref(),
        Some("memory.query")
    );
    assert_eq!(recall_form.fields.len(), 3);
    assert!(recall_form.requires.iter().any(|interface| {
        interface.kind == CONSTRUCT_INTERFACE_CAPABILITY
            && interface.name.as_deref() == Some("memory.query")
    }));
    assert!(recall_form
        .provides
        .iter()
        .any(|interface| interface.kind == "EffectHandle"
            && interface.type_ref.as_deref() == Some("memory.query.output")));
    assert_eq!(manifest.registry.validate(), Vec::new());
}

#[test]
fn package_manifest_rejects_unknown_closed_schema_fields() {
    let error = package_manifest_from_json(
        Path::new("unknown-fields.json"),
        r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-memory",
  "name": "memory",
  "version": "0.1.0",
  "unexpected_top": true,
  "libraries": [
    {
      "id": "memory",
      "unexpected_library": true,
      "effect_contracts": [
        {
          "id": "memory.query",
          "unexpected_effect": true
        }
      ],
      "constructs": [
        {
          "id": "memory.recall",
          "construct_family": "effect_operation",
          "keyword": "recall",
          "unexpected_construct": true,
          "fields": [
            {
              "name": "pool",
              "kind": "identifier",
              "unexpected_field": true
            }
          ],
          "requires": [
            {
              "kind": "Capability",
              "name": "memory.query",
              "unexpected_interface": true
            }
          ]
        }
      ]
    }
  ],
  "capabilities": [
    {
      "id": "memory.query",
      "unexpected_capability": true
    }
  ],
  "providers": [
    {
      "id": "provider-memory-query",
      "provider_kind": "memory-provider",
      "capability": "memory.query",
      "unexpected_provider": true
    }
  ],
  "profiles": [
    {
      "id": "profile-memory-user",
      "name": "memory-user",
      "allowed_capabilities": ["memory.query"],
      "unexpected_profile": true
    }
  ],
  "bindings": [
    {
      "id": "binding-memory-query-global",
      "capability": "memory.query",
      "provider": "memory-provider",
      "unexpected_binding": true
    }
  ]
}
"#
        .to_owned(),
    )
    .expect_err("manifest should reject unknown schema fields");

    for expected in [
            "package manifest field `unexpected_top` is not allowed",
            "package manifest.libraries[0] field `unexpected_library` is not allowed",
            "package manifest.libraries[0].effect_contracts[0] field `unexpected_effect` is not allowed",
            "package manifest.libraries[0].constructs[0] field `unexpected_construct` is not allowed",
            "package manifest.libraries[0].constructs[0].fields[0] field `unexpected_field` is not allowed",
            "package manifest.libraries[0].constructs[0].requires[0] field `unexpected_interface` is not allowed",
            "package manifest.capabilities[0] field `unexpected_capability` is not allowed",
            "package manifest.providers[0] field `unexpected_provider` is not allowed",
            "package manifest.profiles[0] field `unexpected_profile` is not allowed",
            "package manifest.bindings[0] field `unexpected_binding` is not allowed",
        ] {
            assert!(error.contains(expected), "missing `{expected}` in {error}");
        }
}

#[test]
fn package_manifest_rejects_missing_required_nested_fields() {
    let error = package_manifest_from_json(
        Path::new("missing-required-fields.json"),
        r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-memory",
  "name": "memory",
  "version": "0.1.0",
  "libraries": [
    {
      "effect_contracts": [
        {
          "effect_kind": "capability.call"
        }
      ],
      "constructs": [
        {
          "scope": "rule_body",
          "fields": [
            {
              "name": "pool"
            }
          ],
          "requires": [
            {
              "name": "memory.query"
            }
          ]
        }
      ]
    }
  ],
  "capabilities": [
    {
      "description": "Query package memory."
    }
  ],
  "providers": [
    {
      "provider_kind": "memory-provider",
      "capability": "memory.query"
    }
  ],
  "profiles": [
    {
      "id": "profile-memory-user"
    }
  ],
  "bindings": [
    {
      "capability": "memory.query",
      "provider": "memory-provider"
    }
  ]
}
"#
        .to_owned(),
    )
    .expect_err("manifest should reject missing required schema fields");

    for expected in [
        "package manifest.libraries[0] missing required field `id`",
        "package manifest.libraries[0].effect_contracts[0] missing required field `id`",
        "package manifest.libraries[0].constructs[0] missing required field `id`",
        "package manifest.libraries[0].constructs[0] missing required field `construct_family`",
        "package manifest.libraries[0].constructs[0] missing required field `keyword`",
        "package manifest.libraries[0].constructs[0].fields[0] missing required field `kind`",
        "package manifest.libraries[0].constructs[0].requires[0] missing required field `kind`",
        "package manifest.capabilities[0] missing required field `id`",
        "package manifest.providers[0] missing required field `id`",
        "package manifest.profiles[0] missing required field `name`",
        "package manifest.profiles[0] missing required field `allowed_capabilities`",
        "package manifest.bindings[0] missing required field `id`",
    ] {
        assert!(error.contains(expected), "missing `{expected}` in {error}");
    }
}

#[test]
fn package_manifest_rejects_schema_invalid_field_types() {
    let error = package_manifest_from_json(
        Path::new("invalid-field-types.json"),
        r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-memory",
  "name": "memory",
  "version": "0.1.0",
  "libraries": [
    {
      "id": null,
      "standard": "yes",
      "effect_contracts": [
        {
          "id": null,
          "source_forms": ["call memory.query", 42],
          "required_capabilities": "memory.query"
        }
      ],
      "constructs": [
        {
          "id": "memory.recall",
          "construct_family": 42,
          "keyword": "recall",
          "fields": [
            {
              "name": "pool",
              "kind": "identifier",
              "required": "yes"
            }
          ],
          "requires": [
            {
              "kind": null
            }
          ]
        }
      ]
    }
  ],
  "capabilities": [
    {
      "id": null
    }
  ],
  "providers": [
    {
      "id": null,
      "provider_kind": "memory-provider",
      "capability": "memory.query"
    }
  ],
  "profiles": [
    {
      "id": "profile-memory-user",
      "name": null,
      "allowed_capabilities": "memory.query"
    }
  ],
  "bindings": [
    {
      "id": null,
      "program_id": 42,
      "capability": "memory.query",
      "provider": "memory-provider"
    }
  ]
}
"#
        .to_owned(),
    )
    .expect_err("manifest should reject schema-invalid field types");

    for expected in [
            "package manifest.libraries[0] field `id` must be a non-empty string",
            "package manifest.libraries[0] field `standard` must be a boolean",
            "package manifest.libraries[0].effect_contracts[0] field `id` must be a non-empty string",
            "package manifest.libraries[0].effect_contracts[0].source_forms[1] must be a non-empty string",
            "package manifest.libraries[0].effect_contracts[0] field `required_capabilities` must be an array",
            "package manifest.libraries[0].constructs[0] field `construct_family` must be a non-empty string",
            "package manifest.libraries[0].constructs[0].fields[0] field `required` must be a boolean",
            "package manifest.libraries[0].constructs[0].requires[0] field `kind` must be a non-empty string",
            "package manifest.capabilities[0] field `id` must be a non-empty string",
            "package manifest.providers[0] field `id` must be a non-empty string",
            "package manifest.profiles[0] field `name` must be a non-empty string",
            "package manifest.profiles[0] field `allowed_capabilities` must be an array",
            "package manifest.bindings[0] field `id` must be a non-empty string",
            "package manifest.bindings[0] field `program_id` must be a string or null",
        ] {
            assert!(error.contains(expected), "missing `{expected}` in {error}");
        }
}

#[test]
fn package_manifest_rejects_duplicate_package_identity_declarations() {
    let error = package_manifest_from_json(
            Path::new("duplicate-identities.json"),
            r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-memory",
  "name": "memory",
  "version": "0.1.0",
  "libraries": [
    {
      "id": "memory",
      "effect_contracts": [
        {
          "id": "memory.query",
          "required_capabilities": ["memory.query", "memory.query"],
          "provider_kinds": ["memory-provider", "memory-provider"]
        }
      ],
      "constructs": [
        {
          "id": "memory.recall",
          "construct_family": "effect_operation",
          "keyword": "recall"
        }
      ]
    },
    {
      "id": "memory",
      "effect_contracts": [
        {"id": "memory.query"}
      ],
      "constructs": [
        {
          "id": "memory.recall",
          "construct_family": "effect_operation",
          "keyword": "remember"
        }
      ]
    }
  ],
  "capabilities": [
    {"id": "memory.query"},
    {"id": "memory.query"}
  ],
  "providers": [
    {"id": "provider-memory", "provider_kind": "memory-provider", "capability": "memory.query"},
    {"id": "provider-memory", "provider_kind": "memory-provider", "capability": "memory.query"}
  ],
  "profiles": [
    {"id": "profile-memory", "name": "Memory", "allowed_capabilities": ["memory.query", "memory.query"]},
    {"id": "profile-memory", "name": "Memory again", "allowed_capabilities": ["memory.query"]}
  ],
  "bindings": [
    {"id": "binding-memory", "capability": "memory.query", "provider": "memory-provider"},
    {"id": "binding-memory", "capability": "memory.query", "provider": "memory-provider"}
  ]
}
"#
            .to_owned(),
        )
        .expect_err("manifest should reject duplicate package identities");

    assert!(
        error.contains("library `memory` is declared more than once"),
        "{error}"
    );
    assert!(
        error.contains("capability `memory.query` is declared more than once"),
        "{error}"
    );
    assert!(
        error.contains("provider `provider-memory` is declared more than once"),
        "{error}"
    );
    assert!(
        error.contains("profile `profile-memory` is declared more than once"),
        "{error}"
    );
    assert!(
        error.contains("binding `binding-memory` is declared more than once"),
        "{error}"
    );
    assert!(
        error.contains("effect contract `memory.query` is declared more than once"),
        "{error}"
    );
    assert!(
        error.contains("construct `memory.recall` is declared more than once"),
        "{error}"
    );
    assert!(error.contains("effect contract `memory.query` declares `required_capabilities` value `memory.query` more than once"), "{error}");
    assert!(error.contains("profile `profile-memory` declares `allowed_capabilities` value `memory.query` more than once"), "{error}");
}

#[test]
fn package_manifest_rejects_effect_contract_alias_conflict() {
    let error = package_manifest_from_json(
        Path::new("effect-alias-conflict.json"),
        r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-memory",
  "name": "memory",
  "version": "0.1.0",
  "libraries": [
    {
      "id": "memory",
      "effect_contracts": [{"id": "memory.query"}],
      "effects": [{"id": "memory.write"}]
    }
  ],
  "capabilities": [
    {"id": "memory.query"},
    {"id": "memory.write"}
  ]
}
"#
        .to_owned(),
    )
    .expect_err("manifest should reject ambiguous effect aliases");

    assert!(
        error.contains("declares both `effect_contracts` and `effects`; use `effect_contracts`"),
        "{error}"
    );
}

#[test]
fn package_manifest_schema_construct_vocabulary_matches_platform_catalog() {
    let schema: Value = serde_json::from_str(include_str!(
        "../../../../../spec/report-schemas/package_manifest_v0.schema.json"
    ))
    .expect("package manifest schema parses");

    assert_eq!(
        schema_string_enum(
            &schema,
            &[
                "$defs",
                "construct",
                "properties",
                "construct_family",
                "enum"
            ]
        ),
        PLATFORM_CONSTRUCT_CATALOG
            .family_ids()
            .filter(|family_id| {
                PLATFORM_CONSTRUCT_CATALOG
                    .lowerings_for_family(family_id)
                    .any(|lowering| lowering.package_authorable)
            })
            .map(str::to_owned)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        schema_string_enum(
            &schema,
            &[
                "$defs",
                "construct",
                "properties",
                "lowering_target",
                "enum"
            ]
        ),
        PLATFORM_CONSTRUCT_CATALOG
            .lowerings
            .iter()
            .filter(|lowering| lowering.package_authorable)
            .map(|lowering| lowering.id)
            .map(str::to_owned)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        schema_string_enum(
            &schema,
            &["$defs", "construct", "properties", "scope", "enum"]
        ),
        PLATFORM_CONSTRUCT_CATALOG
            .scopes
            .iter()
            .copied()
            .map(str::to_owned)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        schema_string_enum(
            &schema,
            &["$defs", "constructField", "properties", "kind", "enum"]
        ),
        PLATFORM_CONSTRUCT_CATALOG
            .field_kinds
            .iter()
            .copied()
            .map(str::to_owned)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        schema_string_enum(
            &schema,
            &["$defs", "constructInterface", "properties", "kind", "enum"]
        ),
        PLATFORM_CONSTRUCT_CATALOG
            .interface_kinds
            .iter()
            .copied()
            .map(str::to_owned)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        schema_string_enum(
            &schema,
            &["$defs", "constructInterface", "properties", "phase", "enum"]
        ),
        PLATFORM_CONSTRUCT_CATALOG
            .interface_phases
            .iter()
            .copied()
            .map(str::to_owned)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        schema_string_enum(
            &schema,
            &[
                "$defs",
                "constructInterface",
                "properties",
                "cardinality",
                "enum"
            ]
        ),
        PLATFORM_CONSTRUCT_CATALOG
            .interface_cardinalities
            .iter()
            .copied()
            .map(str::to_owned)
            .collect::<Vec<_>>()
    );
}

#[test]
fn package_manifest_rejects_unsupported_package_effect_kind() {
    let error = package_manifest_from_json(
        Path::new("bad-effect-kind.json"),
        r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-memory",
  "name": "memory",
  "version": "0.1.0",
  "libraries": [
    {
      "id": "memory",
      "effect_contracts": [
        {
          "id": "memory.query",
          "effect_kind": "schema.coerce",
          "required_capabilities": ["memory.query"]
        }
      ]
    }
  ],
  "capabilities": [
    {"id": "memory.query"}
  ]
}
"#
        .to_owned(),
    )
    .expect_err("manifest should reject unsupported effect kind");
    assert!(
        error.contains("packages currently support only `capability.call`"),
        "{error}"
    );
}

#[test]
fn package_manifest_rejects_undeclared_required_capability() {
    let error = package_manifest_from_json(
        Path::new("missing-capability.json"),
        r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-memory",
  "name": "memory",
  "version": "0.1.0",
  "libraries": [
    {
      "id": "memory",
      "effect_contracts": [
        {
          "id": "memory.query",
          "effect_kind": "capability.call",
          "required_capabilities": ["memory.missing"]
        }
      ]
    }
  ],
  "capabilities": [
    {"id": "memory.query"}
  ]
}
"#
        .to_owned(),
    )
    .expect_err("manifest should reject missing required capability");
    assert!(
        error.contains("references undeclared capability `memory.missing`"),
        "{error}"
    );
}

#[test]
fn package_manifest_rejects_unsupported_capability_input_schema() {
    let error = package_manifest_from_json(
        Path::new("bad-input-schema.json"),
        r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-memory",
  "name": "memory",
  "version": "0.1.0",
  "capabilities": [
    {
      "id": "memory.query",
      "schema": {
        "input": {
          "query": true
        }
      }
    }
  ]
}
"#
        .to_owned(),
    )
    .expect_err("manifest should reject unsupported input schema fragments");
    assert!(
        error.contains("capability `memory.query`")
            && error.contains("invalid input_schema")
            && error.contains("input_schema.query uses unsupported package schema fragment"),
        "{error}"
    );
}

#[test]
fn package_manifest_rejects_unsupported_effect_output_schema() {
    let error = package_manifest_from_json(
        Path::new("bad-output-schema.json"),
        r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-memory",
  "name": "memory",
  "version": "0.1.0",
  "libraries": [
    {
      "id": "memory",
      "effect_contracts": [
        {
          "id": "memory.query",
          "effect_kind": "capability.call",
          "output_schema": ["string", "integer"],
          "required_capabilities": ["memory.query"]
        }
      ]
    }
  ],
  "capabilities": [
    {"id": "memory.query"}
  ]
}
"#
        .to_owned(),
    )
    .expect_err("manifest should reject unsupported output schema fragments");
    assert!(
        error.contains("effect contract `memory.query`")
            && error.contains("invalid output_schema")
            && error.contains("output_schema uses unsupported package tuple schema"),
        "{error}"
    );
}

#[test]
fn package_manifest_rejects_construct_missing_required_input_schema_field() {
    let error = package_manifest_from_json(
        Path::new("bad-construct-input-fields.json"),
        r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-memory",
  "name": "memory",
  "version": "0.1.0",
  "libraries": [
    {
      "id": "memory",
      "effect_contracts": [
        {
          "id": "memory.query",
          "effect_kind": "capability.call",
          "input_schema": {
            "query": "string"
          },
          "required_capabilities": ["memory.query"]
        }
      ],
      "constructs": [
        {
          "id": "memory.recall",
          "construct_family": "effect_operation",
          "keyword": "recall",
          "scope": "rule_body",
          "fields": [
            {"name": "pool", "kind": "identifier", "required": true},
            {"name": "binding", "kind": "identifier", "required": true}
          ],
          "requires": [
            {"kind": "Capability", "name": "memory.query"}
          ],
          "provides": [
            {"kind": "EffectHandle", "type": "memory.query.output"}
          ],
          "lowering_target": "capability_call",
          "target_capability": "memory.query"
        }
      ]
    }
  ],
  "capabilities": [
    {"id": "memory.query"}
  ]
}
"#
        .to_owned(),
    )
    .expect_err("manifest should reject construct fields that cannot supply target input");
    assert!(
        error.contains("construct `memory.recall` lowers to `memory.query`")
            && error.contains(
                "target input_schema field `query` has no matching required construct field"
            ),
        "{error}"
    );
}

#[test]
fn package_manifest_rejects_binding_without_matching_provider() {
    let error = package_manifest_from_json(
        Path::new("bad-binding.json"),
        r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-memory",
  "name": "memory",
  "version": "0.1.0",
  "capabilities": [
    {"id": "memory.query"}
  ],
  "providers": [
    {
      "id": "provider-memory-query",
      "provider_kind": "memory-provider",
      "capability": "memory.query",
      "config": {}
    }
  ],
  "bindings": [
    {
      "id": "binding-memory-query-global",
      "capability": "memory.query",
      "provider": "other-provider",
      "config": {}
    }
  ]
}
"#
        .to_owned(),
    )
    .expect_err("manifest should reject provider mismatch");
    assert!(
        error.contains("references provider `other-provider`"),
        "{error}"
    );
}

#[test]
fn package_manifest_rejects_unsupported_construct_lowering_target() {
    let error = package_manifest_from_json(
        Path::new("bad-construct.json"),
        r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-memory",
  "name": "memory",
  "version": "0.1.0",
  "libraries": [
    {
      "id": "memory",
      "constructs": [
        {
          "id": "memory.recall",
          "construct_family": "effect_operation",
          "keyword": "recall",
          "scope": "rule_body",
          "lowering_target": "core_rule"
        }
      ]
    }
  ]
}
"#
        .to_owned(),
    )
    .expect_err("manifest should reject executable construct lowering");
    assert!(
        error.contains("expected one of `metadata_only`, `capability_call`"),
        "{error}"
    );
}

#[test]
fn package_manifest_rejects_platform_internal_construct_lowering_target() {
    let error = package_manifest_from_json(
        Path::new("bad-internal-construct.json"),
        r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-memory",
  "name": "memory",
  "version": "0.1.0",
  "libraries": [
    {
      "id": "memory",
      "constructs": [
        {
          "id": "memory.wait",
          "construct_family": "effect_operation",
          "keyword": "wait",
          "scope": "rule_body",
          "lowering_target": "core_effect"
        }
      ]
    }
  ]
}
"#
        .to_owned(),
    )
    .expect_err("manifest should reject platform-internal construct lowering");
    assert!(
        error.contains("platform-internal lowering_target `core_effect`"),
        "{error}"
    );
}

#[test]
fn package_manifest_rejects_internal_lowering_without_embedded_privilege() {
    // The normal (vendor/lock/file) path: the manifest is not the platform's
    // embedded copy, so the flat rejection stands.
    let error = package_manifest_from_json(
        Path::new("std-pulse.json"),
        INTERNAL_LOWERING_STD_MANIFEST.to_owned(),
    )
    .expect_err("a non-embedded manifest must not author an internal lowering");
    assert!(
        error.contains("platform-internal lowering_target `signal_source`")
            && error.contains("only platform-embedded std manifests"),
        "{error}"
    );
}

#[test]
fn package_manifest_admits_internal_lowering_for_embedded_copy() {
    // The authorability door: the same bytes validated as an entry of the
    // embedded manifest set are the platform copy and may use internal
    // lowerings.
    let manifest = package_manifest_from_json_with_embedded(
        Path::new("<embedded:std.pulse>"),
        INTERNAL_LOWERING_STD_MANIFEST.to_owned(),
        &[("std.pulse", INTERNAL_LOWERING_STD_MANIFEST)],
    )
    .expect("the platform's own embedded copy may use internal lowerings");
    assert_eq!(manifest.name, "std.pulse");
    assert_eq!(manifest.registry.constructs.len(), 1);
    assert_eq!(
        manifest.registry.constructs[0].lowering_target,
        "signal_source"
    );
}

#[test]
fn package_manifest_std_name_grants_no_internal_lowering_privilege() {
    // Name alone grants nothing: a `std.evil` manifest with an internal
    // lowering is rejected through the normal path, and stays rejected even
    // against an embedded set whose entries have different bytes — only
    // byte-identity with the embedded copy is the privilege key.
    let evil = INTERNAL_LOWERING_STD_MANIFEST.replace("std.pulse", "std.evil");
    let error = package_manifest_from_json(Path::new("std-evil.json"), evil.clone())
        .expect_err("a std.*-named manifest file must not author an internal lowering");
    assert!(
        error.contains("platform-internal lowering_target `signal_source`"),
        "{error}"
    );
    let error = package_manifest_from_json_with_embedded(
        Path::new("std-evil.json"),
        evil,
        &[("std.pulse", INTERNAL_LOWERING_STD_MANIFEST)],
    )
    .expect_err("different bytes must not inherit embedded privilege");
    assert!(
        error.contains("platform-internal lowering_target `signal_source`"),
        "{error}"
    );
}

/// std.coord slice 4 privilege acceptance (std-tracker.json claim-keyword
/// precedent, extended through the authorability wall): a manifest whose
/// (library, keyword, family, scope, lowering) tuple is in the platform
/// catalog may author a `resource_effect` construct WITHOUT being the
/// embedded byte-identical copy — the privilege-tuple leg of the door.
/// The embedded set is explicitly EMPTY so byte-identity cannot be the
/// key that admitted it.
#[test]
fn package_manifest_privilege_tuple_admits_resource_effect_construct() {
    let manifest = RESOURCE_EFFECT_MANIFEST_TEMPLATE
        .replace("{LIB}", "std.coord")
        .replace("{KW}", "acquire");
    let manifest = package_manifest_from_json_with_embedded(Path::new("coord.json"), manifest, &[])
        .expect("the catalog privilege tuple authorizes the resource_effect class");
    assert_eq!(manifest.registry.constructs.len(), 1);
    assert_eq!(
        manifest.registry.constructs[0].lowering_target,
        "resource_effect"
    );
}

/// Negative fixture (slice 4 gate): a NON-privileged manifest cannot
/// author a `resource_effect` construct — no catalog tuple, no row. Both
/// coordinates bite: a vendor library with the same keyword, and the
/// privileged library with a keyword outside its tuples.
#[test]
fn package_manifest_without_privilege_tuple_cannot_author_resource_effect() {
    let vendor = RESOURCE_EFFECT_MANIFEST_TEMPLATE
        .replace("{LIB}", "acme.coord")
        .replace("{KW}", "acquire");
    let error = package_manifest_from_json_with_embedded(Path::new("acme-coord.json"), vendor, &[])
        .expect_err("a vendor library holds no resource_effect tuple");
    assert!(
        error.contains("platform-internal lowering_target `resource_effect`"),
        "{error}"
    );

    let wrong_keyword = RESOURCE_EFFECT_MANIFEST_TEMPLATE
        .replace("{LIB}", "std.coord")
        .replace("{KW}", "seize");
    let error =
        package_manifest_from_json_with_embedded(Path::new("coord-seize.json"), wrong_keyword, &[])
            .expect_err("std.coord holds no tuple for an un-cataloged keyword");
    assert!(
        error.contains("platform-internal lowering_target `resource_effect`"),
        "{error}"
    );
}

/// std.ingress I2b, privilege-tuple leg (spec/std-ingress.md "Catalog
/// privilege additions"): the catalog tuples (`signal`, std.ingress,
/// declaration_block, metadata_only) and (`emit`, std.ingress,
/// effect_operation, signal_emit) admit the construct rows WITHOUT the
/// embedded-copy key (empty embedded set), the same door std.coord's
/// resource_effect rows ride.
#[test]
fn package_manifest_privilege_tuples_admit_ingress_signal_and_emit() {
    let manifest = INGRESS_KEYWORD_MANIFEST_TEMPLATE.replace("{LIB}", "std.ingress");
    let manifest =
        package_manifest_from_json_with_embedded(Path::new("ingress.json"), manifest, &[])
            .expect("the catalog tuples authorize the signal/emit rows");
    assert_eq!(manifest.registry.constructs.len(), 2);
    assert!(manifest
        .registry
        .constructs
        .iter()
        .any(|form| form.keyword == "emit" && form.lowering_target == "signal_emit"));
}

/// Negative fixture (I2b gate): a NON-privileged manifest cannot author
/// the `signal`/`emit` keywords or the `signal_emit` lowering — the tuples
/// are exact, so a vendor library with the same rows is refused.
#[test]
fn package_manifest_without_ingress_tuples_cannot_author_signal_or_emit() {
    let vendor = INGRESS_KEYWORD_MANIFEST_TEMPLATE.replace("{LIB}", "acme.ingress");
    let error =
        package_manifest_from_json_with_embedded(Path::new("acme-ingress.json"), vendor, &[])
            .expect_err("a vendor library holds neither ingress tuple");
    assert!(
        error.contains("reserved construct keyword")
            || error.contains("platform-internal lowering_target `signal_emit`"),
        "{error}"
    );
}

#[test]
fn package_manifest_rejects_unsupported_construct_family() {
    let error = package_manifest_from_json(
        Path::new("bad-construct-family.json"),
        r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-memory",
  "name": "memory",
  "version": "0.1.0",
  "libraries": [
    {
      "id": "memory",
      "constructs": [
        {
          "id": "memory.recall",
          "construct_family": "macro",
          "keyword": "recall",
          "scope": "rule_body",
          "lowering_target": "metadata_only"
        }
      ]
    }
  ]
}
"#
        .to_owned(),
    )
    .expect_err("manifest should reject unsupported construct family");
    assert!(
        error.contains("unsupported construct_family `macro`"),
        "{error}"
    );
}

#[test]
fn package_manifest_rejects_capability_call_family_mismatch() {
    let error = package_manifest_from_json(
        Path::new("bad-construct-family.json"),
        r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-memory",
  "name": "memory",
  "version": "0.1.0",
  "libraries": [
    {
      "id": "memory",
      "effect_contracts": [
        {
          "id": "memory.query",
          "effect_kind": "capability.call",
          "required_capabilities": ["memory.query"]
        }
      ],
      "constructs": [
        {
          "id": "memory.recall",
          "construct_family": "declaration_block",
          "keyword": "recall",
          "scope": "rule_body",
          "lowering_target": "capability_call",
          "target_capability": "memory.query"
        }
      ]
    }
  ],
  "capabilities": [
    {"id": "memory.query"}
  ]
}
"#
        .to_owned(),
    )
    .expect_err("manifest should reject capability_call family mismatch");
    assert!(
        error.contains("uses capability_call lowering but construct_family is `declaration_block`"),
        "{error}"
    );
}

#[test]
fn package_manifest_rejects_capability_call_form_without_target() {
    let error = package_manifest_from_json(
        Path::new("bad-construct.json"),
        r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-memory",
  "name": "memory",
  "version": "0.1.0",
  "libraries": [
    {
      "id": "memory",
      "effect_contracts": [
        {
          "id": "memory.query",
          "effect_kind": "capability.call",
          "required_capabilities": ["memory.query"]
        }
      ],
      "constructs": [
        {
          "id": "memory.recall",
          "construct_family": "effect_operation",
          "keyword": "recall",
          "scope": "rule_body",
          "lowering_target": "capability_call"
        }
      ]
    }
  ],
  "capabilities": [
    {"id": "memory.query"}
  ]
}
"#
        .to_owned(),
    )
    .expect_err("manifest should reject capability_call without target");
    assert!(
        error.contains("uses capability_call lowering but has no target_capability"),
        "{error}"
    );
}

#[test]
fn package_manifest_rejects_capability_call_without_required_capability_interface() {
    let error = package_manifest_from_json(
        Path::new("bad-construct-interface.json"),
        r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-memory",
  "name": "memory",
  "version": "0.1.0",
  "libraries": [
    {
      "id": "memory",
      "effect_contracts": [
        {
          "id": "memory.query",
          "effect_kind": "capability.call",
          "required_capabilities": ["memory.query"]
        }
      ],
      "constructs": [
        {
          "id": "memory.recall",
          "construct_family": "effect_operation",
          "keyword": "recall",
          "scope": "rule_body",
          "provides": [{"kind": "EffectHandle"}],
          "lowering_target": "capability_call",
          "target_capability": "memory.query"
        }
      ]
    }
  ],
  "capabilities": [
    {"id": "memory.query"}
  ]
}
"#
        .to_owned(),
    )
    .expect_err("manifest should reject missing Capability interface");
    assert!(
        error.contains("declares no required `Capability` interface"),
        "{error}"
    );
    assert!(
        error.contains("declares no required Capability interface named `memory.query`"),
        "{error}"
    );
}

#[test]
fn package_manifest_rejects_capability_call_without_effect_handle_interface() {
    let error = package_manifest_from_json(
        Path::new("bad-construct-interface.json"),
        r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-memory",
  "name": "memory",
  "version": "0.1.0",
  "libraries": [
    {
      "id": "memory",
      "effect_contracts": [
        {
          "id": "memory.query",
          "effect_kind": "capability.call",
          "required_capabilities": ["memory.query"]
        }
      ],
      "constructs": [
        {
          "id": "memory.recall",
          "construct_family": "effect_operation",
          "keyword": "recall",
          "scope": "rule_body",
          "requires": [{"kind": "Capability", "name": "memory.query"}],
          "lowering_target": "capability_call",
          "target_capability": "memory.query"
        }
      ]
    }
  ],
  "capabilities": [
    {"id": "memory.query"}
  ]
}
"#
        .to_owned(),
    )
    .expect_err("manifest should reject missing EffectHandle interface");
    assert!(
        error.contains("declares no provided `EffectHandle` interface"),
        "{error}"
    );
}

#[test]
fn package_manifest_rejects_unsupported_construct_interface_kind() {
    let error = package_manifest_from_json(
        Path::new("bad-construct-interface.json"),
        r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-memory",
  "name": "memory",
  "version": "0.1.0",
  "libraries": [
    {
      "id": "memory",
      "constructs": [
        {
          "id": "memory.pool",
          "construct_family": "declaration_block",
          "keyword": "memory",
          "provides": [{"kind": "Magic"}],
          "lowering_target": "metadata_only"
        }
      ]
    }
  ],
  "capabilities": []
}
"#
        .to_owned(),
    )
    .expect_err("manifest should reject unsupported interface kind");
    assert!(
        error.contains("provides interface uses unsupported kind `Magic`"),
        "{error}"
    );
}

#[test]
fn package_manifest_rejects_reserved_construct_keyword() {
    let error = package_manifest_from_json(
        Path::new("bad-construct-keyword.json"),
        r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-memory",
  "name": "memory",
  "version": "0.1.0",
  "libraries": [
    {
      "id": "memory",
      "constructs": [
        {
          "id": "memory.call.form",
          "construct_family": "declaration_block",
          "keyword": "call",
          "scope": "rule_body",
          "lowering_target": "metadata_only"
        }
      ]
    }
  ]
}
"#
        .to_owned(),
    )
    .expect_err("manifest should reject reserved construct keyword");
    assert!(
        error.contains("uses reserved construct keyword `call`"),
        "{error}"
    );
}

#[test]
fn package_manifest_accepts_authorized_reserved_construct_keyword() {
    let manifest = package_manifest_from_json(
        Path::new("std-tracker.json"),
        r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "std-tracker",
  "name": "tracker",
  "version": "0.1.0",
  "libraries": [
    {
      "id": "std.tracker",
      "standard": true,
      "effect_contracts": [
        {
          "id": "tracker.claim",
          "effect_kind": "capability.call",
          "input_schema": {"issue": "string"},
          "required_capabilities": ["tracker.claim"]
        }
      ],
      "constructs": [
        {
          "id": "tracker.claim",
          "construct_family": "effect_operation",
          "keyword": "claim",
          "scope": "rule_body",
          "fields": [
            {"name": "issue", "kind": "expression", "required": true}
          ],
          "requires": [
            {"kind": "Capability", "name": "tracker.claim"}
          ],
          "provides": [
            {"kind": "EffectHandle"}
          ],
          "lowering_target": "typed_effect_call"
        }
      ]
    }
  ],
  "capabilities": [
    {"id": "tracker.claim"}
  ]
}
"#
        .to_owned(),
    )
    .expect("std.tracker claim keyword privilege should be accepted");

    assert!(manifest.registry.constructs.iter().any(|form| {
        form.library_id == "std.tracker"
            && form.keyword == "claim"
            && form.lowering_target == "typed_effect_call"
    }));
}

#[test]
fn package_manifest_rejects_unprivileged_reserved_construct_keyword() {
    let error = package_manifest_from_json(
        Path::new("bad-memory-claim.json"),
        r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-memory",
  "name": "memory",
  "version": "0.1.0",
  "libraries": [
    {
      "id": "memory",
      "effect_contracts": [
        {
          "id": "memory.claim",
          "effect_kind": "capability.call",
          "input_schema": {"issue": "string"},
          "required_capabilities": ["memory.claim"]
        }
      ],
      "constructs": [
        {
          "id": "memory.claim",
          "construct_family": "effect_operation",
          "keyword": "claim",
          "scope": "rule_body",
          "fields": [
            {"name": "issue", "kind": "expression", "required": true}
          ],
          "requires": [
            {"kind": "Capability", "name": "memory.claim"}
          ],
          "provides": [
            {"kind": "EffectHandle"}
          ],
          "lowering_target": "capability_call",
          "target_capability": "memory.claim"
        }
      ]
    }
  ],
  "capabilities": [
    {"id": "memory.claim"}
  ]
}
"#
        .to_owned(),
    )
    .expect_err("unprivileged package should not own claim keyword");

    assert!(
        error.contains("uses reserved construct keyword `claim`"),
        "{error}"
    );
    assert!(
        error.contains("platform catalog authorization for library `memory`"),
        "{error}"
    );
}

#[test]
fn package_manifest_accepts_declaration_block_grammar() {
    // A flag clause, a connective-introduced value clause, and a list
    // clause. The default `metadata_only` lowering is declaration_block-
    // compatible, so no capabilities or effect contracts are required.
    let manifest = package_manifest_from_json(
            Path::new("gadget-grammar.json"),
            declaration_grammar_manifest(
                r#"
              {"name": "shared", "kind": "flag", "required": false, "list": false,
               "unknown_hint": "no such field", "missing_summary": "add a field"},
              {"name": "partition", "kind": "identifier", "required": true, "list": false,
               "connective": "by", "unknown_hint": "no such field", "missing_summary": "add a field"},
              {"name": "allow read", "kind": "glob", "required": false, "list": true,
               "unknown_hint": "no such field", "missing_summary": "add a field"}
            "#,
            ),
        )
        .expect("declaration_block grammar manifest should validate");

    let form = manifest
        .registry
        .constructs
        .iter()
        .find(|form| form.id == "gadget.widget")
        .expect("gadget.widget construct");
    assert_eq!(form.construct_family, "declaration_block");
    let grammar = form
        .grammar
        .as_ref()
        .expect("grammar carried on the registration");
    assert_eq!(
        grammar.shape,
        whipplescript_core::CONSTRUCT_GRAMMAR_SHAPE_DECLARATION_BLOCK
    );
    let clauses = grammar
        .clauses
        .as_ref()
        .expect("declaration_block grammar carries clauses");
    assert_eq!(clauses.len(), 3);
    assert_eq!(clauses[1].connective.as_deref(), Some("by"));
    // The derived flat `fields[]` view: flag -> optional boolean, value
    // clause -> its own kind, list clause -> the `list` field kind.
    assert_eq!(
        form.fields,
        vec![
            ConstructField {
                name: "shared".to_owned(),
                kind: "boolean".to_owned(),
                required: false,
            },
            ConstructField {
                name: "partition".to_owned(),
                kind: "identifier".to_owned(),
                required: true,
            },
            ConstructField {
                name: "allow read".to_owned(),
                kind: "list".to_owned(),
                required: false,
            },
        ]
    );
}

#[test]
fn package_manifest_rejects_declaration_flag_with_list() {
    let error = package_manifest_from_json(
        Path::new("gadget-grammar.json"),
        declaration_grammar_manifest(
            r#"{"name": "shared", "kind": "flag", "required": false, "list": true,
                    "unknown_hint": "h", "missing_summary": "s"}"#,
        ),
    )
    .expect_err("a flag clause cannot be a list");
    assert!(
        error.contains("is a `flag` and cannot set `list: true`"),
        "{error}"
    );
}

#[test]
fn package_manifest_rejects_declaration_flag_with_connective() {
    let error = package_manifest_from_json(
        Path::new("gadget-grammar.json"),
        declaration_grammar_manifest(
            r#"{"name": "shared", "kind": "flag", "required": false, "list": false,
                    "connective": "by", "unknown_hint": "h", "missing_summary": "s"}"#,
        ),
    )
    .expect_err("a flag clause cannot carry a connective");
    assert!(
        error.contains("is a `flag` and cannot carry a connective"),
        "{error}"
    );
}

#[test]
fn package_manifest_rejects_declaration_unknown_clause_kind() {
    let error = package_manifest_from_json(
        Path::new("gadget-grammar.json"),
        declaration_grammar_manifest(
            r#"{"name": "x", "kind": "mystery", "required": true, "list": false,
                    "unknown_hint": "h", "missing_summary": "s"}"#,
        ),
    )
    .expect_err("an unknown clause kind is rejected");
    assert!(error.contains("uses unsupported kind `mystery`"), "{error}");
}

#[test]
fn package_manifest_rejects_declaration_unknown_connective() {
    let error = package_manifest_from_json(
        Path::new("gadget-grammar.json"),
        declaration_grammar_manifest(
            r#"{"name": "x", "kind": "identifier", "required": true, "list": false,
                    "connective": "beside", "unknown_hint": "h", "missing_summary": "s"}"#,
        ),
    )
    .expect_err("an unknown connective is rejected");
    assert!(
        error.contains("uses unsupported connective `beside`"),
        "{error}"
    );
}

#[test]
fn package_manifest_rejects_declaration_unknown_clause_key() {
    let error = package_manifest_from_json(
        Path::new("gadget-grammar.json"),
        declaration_grammar_manifest(
            r#"{"name": "x", "kind": "identifier", "required": true, "list": false,
                    "unknown_hint": "h", "missing_summary": "s", "extra": true}"#,
        ),
    )
    .expect_err("an unknown clause key is rejected");
    assert!(error.contains("field `extra` is not allowed"), "{error}");
}

#[test]
fn package_check_accepts_std_grammar_manifests() {
    // The five grammar-only std manifests (read by `build.rs` for the parse
    // table) are now fully-checkable first-class package manifests: each
    // passes `whip package check` (parse + consistency + registry
    // diagnostics) now that `declaration_block` is a supported shape.
    let sources = [
        (
            "std/grammars/tracker.json",
            include_str!("../../../../../std/grammars/tracker.json"),
        ),
        (
            "std/grammars/coord.json",
            include_str!("../../../../../std/grammars/coord.json"),
        ),
        (
            "std/grammars/files.json",
            include_str!("../../../../../std/grammars/files.json"),
        ),
        (
            "std/grammars/messaging-grammar.json",
            include_str!("../../../../../std/grammars/messaging-grammar.json"),
        ),
        (
            "std/grammars/memory-grammar.json",
            include_str!("../../../../../std/grammars/memory-grammar.json"),
        ),
    ];
    for (label, json) in sources {
        let manifest = package_manifest_from_json(Path::new(label), json.to_owned())
            .unwrap_or_else(|error| {
                panic!("std grammar manifest `{label}` must validate: {error}")
            });
        let registry = package_registry(std::slice::from_ref(&manifest));
        let diagnostics = registry.validate();
        assert!(
            diagnostics.is_empty(),
            "std grammar manifest `{label}` must pass package check: {diagnostics:?}"
        );
    }
}

#[test]
fn package_manifest_rejects_unsupported_construct_field_kind() {
    let error = package_manifest_from_json(
        Path::new("bad-construct-field-kind.json"),
        r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-memory",
  "name": "memory",
  "version": "0.1.0",
  "libraries": [
    {
      "id": "memory",
      "constructs": [
        {
          "id": "memory.recall",
          "construct_family": "declaration_block",
          "keyword": "recall",
          "scope": "rule_body",
          "fields": [
            {"name": "pool", "kind": "macro"}
          ],
          "lowering_target": "metadata_only"
        }
      ]
    }
  ]
}
"#
        .to_owned(),
    )
    .expect_err("manifest should reject unsupported construct field kind");
    assert!(
        error.contains("field `pool` uses unsupported kind `macro`"),
        "{error}"
    );
}

#[test]
fn package_lock_json_emits_portable_source_shape_no_absolute_path() {
    let manifest_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/packages/notes.json");
    let manifest = load_package_manifest(&manifest_path).expect("manifest loads");
    let base_dir = manifest_path
        .parent()
        .expect("manifest parent")
        .to_path_buf();
    let lock_json = package_lock_json(&[manifest], &base_dir);

    let entry = &lock_json["packages"][0];
    // No absolute manifest_path field; only a portable relative source.
    assert!(entry.get("manifest_path").is_none(), "{lock_json}");
    assert_eq!(entry["source"]["type"], "path");
    let source_path = entry["source"]["path"].as_str().expect("source path");
    assert_eq!(source_path, "notes.json");
    assert!(
        is_portable_relative_path(source_path),
        "source path must be portable: {source_path}"
    );
    // The serialized lock must not contain any absolute path or the old key.
    let serialized = canonical_lock_text(&lock_json);
    assert!(!serialized.contains("manifest_path"), "{serialized}");
    assert!(
        !serialized.contains(&base_dir.display().to_string()),
        "lock must not embed the absolute base dir: {serialized}"
    );
}

#[test]
fn package_lock_json_sorts_packages_by_name_then_package_id() {
    fn manifest(name: &str, id: &str) -> PackageManifest {
        PackageManifest {
            path: PathBuf::from(format!("{name}.json")),
            manifest_json: String::new(),
            manifest_sha256: "0".repeat(64),
            package_id: id.to_owned(),
            name: name.to_owned(),
            version: "0.1.0".to_owned(),
            registry: ContractRegistry::default(),
            workflow_tools: Vec::new(),
        }
    }
    let manifests = vec![
        manifest("beta", "pkg-beta"),
        manifest("alpha", "pkg-alpha-2"),
        manifest("alpha", "pkg-alpha-1"),
    ];
    let lock = package_lock_json(&manifests, Path::new("."));
    let names = lock["packages"]
        .as_array()
        .expect("packages")
        .iter()
        .map(|entry| {
            (
                entry["name"].as_str().expect("present").to_owned(),
                entry["package_id"].as_str().expect("present").to_owned(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        vec![
            ("alpha".to_owned(), "pkg-alpha-1".to_owned()),
            ("alpha".to_owned(), "pkg-alpha-2".to_owned()),
            ("beta".to_owned(), "pkg-beta".to_owned()),
        ]
    );
}

#[test]
fn package_sync_resolution_is_byte_identical_across_runs() {
    let (temp_dir, set_path) = write_notes_package_set("deterministic");
    let lock_path = temp_dir.join("whip.lock");

    let first = resolve_package_sync(Some(set_path.clone()), Some(lock_path.clone()))
        .expect("first sync resolves");
    let second = resolve_package_sync(Some(set_path.clone()), Some(lock_path.clone()))
        .expect("second sync resolves");

    // Deterministic on-disk bytes and digest -> --check-only is stable.
    assert_eq!(first.lock_text, second.lock_text);
    assert_eq!(first.package_lock_digest, second.package_lock_digest);
    // Portable source, no absolute manifest path.
    assert!(
        !first.lock_text.contains("manifest_path"),
        "{}",
        first.lock_text
    );
    assert!(
        first.lock_text.contains("packages/notes.json"),
        "{}",
        first.lock_text
    );

    // Writing then re-resolving yields bytes identical to what was written.
    write_lock_atomically(&lock_path, &first.lock_text).expect("lock writes");
    let written = fs::read_to_string(&lock_path).expect("lock reads");
    assert_eq!(written, first.lock_text);

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn package_sync_rejects_nonportable_source_path() {
    let manifest_src =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/packages/notes.json");
    let temp_dir = env::temp_dir().join(format!(
        "whipplescript-sync-escape-{}",
        stable_hash_hex(&manifest_src.display().to_string())
    ));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).expect("temp dir");
    let set = json!({
        "schema": PACKAGE_SET_SCHEMA,
        "packages": [
            {"name": "notes", "source": {"type": "path", "path": "../escape.json"}}
        ],
    });
    let set_path = temp_dir.join("whip.packages.json");
    fs::write(&set_path, canonical_lock_text(&set)).expect("set writes");

    let diagnostics = resolve_package_sync(Some(set_path), Some(temp_dir.join("whip.lock")))
        .expect_err("nonportable path must fail");
    assert!(
        diagnostics
            .iter()
            .any(|d| d.code == "package_source.nonportable_path"),
        "{:?}",
        diagnostics.iter().map(|d| d.code).collect::<Vec<_>>()
    );
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn package_lock_supplies_package_import_registry() {
    let (temp_dir, lock_path, lock_json) = write_portable_notes_lock("import-registry");
    // The portable lock must record a relative source, never an absolute path.
    let source_path = lock_json["packages"][0]["source"]["path"]
        .as_str()
        .expect("source path");
    assert_eq!(source_path, "notes.json");
    assert!(lock_json["packages"][0].get("manifest_path").is_none());
    let lock = load_package_lock_file(&lock_path).expect("lock loads");
    let _ = fs::remove_dir_all(&temp_dir);

    let source = r#"
workflow PackageLockRegistry

use notes

class Task {
  title string
}

rule start
  when Task as task
=> {
  call notes.query for task as context
}
"#;
    let compiled = whipplescript_parser::compile_program(source);
    let ir = compiled.ir.expect("source compiles");
    // `memory` ships as the embedded `std.memory` manifest (M5), so
    // `use std.memory` + `recall` resolves with no lock at all — no supply
    // chain required.
    let embedded_ir = whipplescript_parser::compile_program(
        r#"
workflow EmbeddedMemory

use std.memory

memory pool project_memory {
  context limit 8
}

class Task {
  title string
}

rule start
  when Task as task
=> {
  recall project_memory for task as context
}
"#,
    )
    .ir
    .expect("embedded source compiles");
    let embedded = contract_registry_for_ir(None, &embedded_ir)
        .expect("embedded `std.memory` manifest resolves without a lock");
    assert!(
        embedded.constructs.iter().any(|form| {
            form.keyword == "recall" && form.target_capability.as_deref() == Some("memory.query")
        }),
        "embedded resolution authorizes the `recall` construct"
    );
    // A genuinely-unlocked (non-embedded) import still trips the no-lock guard.
    let unlocked_ir = whipplescript_parser::compile_program(
        r#"
workflow Unlocked

use notebook

class Task {
  title string
}

rule start
  when Task as task
=> {
  record Task {
    title "keep"
  }
}
"#,
    )
    .ir
    .expect("unlocked source compiles");
    let no_lock_error = contract_registry_for_ir(None, &unlocked_ir)
        .expect_err("a non-embedded import requires a package lock");
    assert!(
        no_lock_error.contains("requires a package lock")
            && no_lock_error.contains("whip package sync")
            && no_lock_error.contains("import `notebook`"),
        "{no_lock_error}"
    );
    let registry = lock.registry_for_ir(&ir).expect("registry resolves");

    assert!(registry
        .libraries
        .iter()
        .any(|library| library.id == "notes" && library.version == "0.1.0"));
    assert!(registry
        .effect_contracts
        .iter()
        .any(|contract| contract.id == "notes.query" && contract.effect_kind == "capability.call"));
    assert_eq!(registry.validate(), Vec::new());
}

#[test]
fn package_lock_rejects_reserved_std_namespace_entries() {
    // A supply-chain lock can never provide a `std.*` package: std packages
    // ship embedded in the platform, and embedded always wins.
    let (temp_dir, lock_path, mut lock_json) = write_portable_notes_lock("reserved-std");
    let manifest_path = temp_dir.join("std.memory.json");
    let manifest_json = fs::read_to_string(temp_dir.join("notes.json"))
        .expect("read notes manifest")
        .replace("\"name\": \"notes\"", "\"name\": \"std.memory\"");
    fs::write(&manifest_path, &manifest_json).expect("write std-named manifest");
    let entry = lock_json
        .get_mut("packages")
        .and_then(Value::as_array_mut)
        .and_then(|packages| packages.first_mut())
        .and_then(Value::as_object_mut)
        .expect("package entry object");
    entry.insert("name".to_owned(), Value::String("std.memory".to_owned()));
    entry.insert(
        "source".to_owned(),
        json!({"type": "path", "path": "std.memory.json"}),
    );
    entry.insert(
        "manifest_sha256".to_owned(),
        Value::String(sha256_hex(manifest_json.as_bytes())),
    );
    fs::write(&lock_path, canonical_lock_text(&lock_json)).expect("lock writes");
    let error = load_package_lock_file(&lock_path)
        .expect_err("a reserved std.* lock entry must be rejected");
    let _ = fs::remove_dir_all(&temp_dir);

    assert!(
        error.contains("entry `std.memory` claims the reserved std namespace")
            && error.contains("cannot be provided by a package lock"),
        "{error}"
    );
}

#[test]
fn package_sync_refuses_reserved_std_manifest_names() {
    let (temp_dir, set_path) = write_notes_package_set("reserved-std");
    // Point the package set at a manifest claiming the reserved namespace.
    let manifest_path = temp_dir.join("packages/notes.json");
    let manifest_json = fs::read_to_string(&manifest_path)
        .expect("read notes manifest")
        .replace("\"name\": \"notes\"", "\"name\": \"std.notes\"");
    fs::write(&manifest_path, manifest_json).expect("write std-named manifest");
    let set = json!({
        "schema": PACKAGE_SET_SCHEMA,
        "packages": [
            {"name": "std.notes", "source": {"type": "path", "path": "packages/notes.json"}}
        ],
    });
    fs::write(&set_path, canonical_lock_text(&set)).expect("set writes");

    let diagnostics = resolve_package_sync(Some(set_path), Some(temp_dir.join("whip.lock")))
        .expect_err("a reserved std.* manifest name must refuse to sync");
    let _ = fs::remove_dir_all(&temp_dir);
    assert!(
        diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "package_manifest.reserved_std_name"
                && diagnostic.message.contains("reserved std namespace")
        }),
        "{:?}",
        diagnostics
            .iter()
            .map(|diagnostic| (diagnostic.code, diagnostic.message.as_str()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn package_lock_rejects_duplicate_package_entries() {
    let (temp_dir, lock_path, mut lock_json) = write_portable_notes_lock("duplicate-entries");
    let packages = lock_json
        .get_mut("packages")
        .and_then(Value::as_array_mut)
        .expect("packages array");
    packages.push(packages[0].clone());
    fs::write(&lock_path, canonical_lock_text(&lock_json)).expect("lock writes");
    let error = load_package_lock_file(&lock_path)
        .expect_err("duplicate package entries should be rejected");
    let _ = fs::remove_dir_all(&temp_dir);

    assert!(
        error.contains("package_id `package-notes` more than once"),
        "{error}"
    );
    assert!(
        error.contains("package name `notes` more than once"),
        "{error}"
    );
}

#[test]
fn package_lock_rejects_unknown_closed_schema_fields() {
    let (temp_dir, lock_path, mut lock_json) = write_portable_notes_lock("unknown-fields");
    lock_json
        .as_object_mut()
        .expect("lock object")
        .insert("unexpected_top".to_owned(), Value::Bool(true));
    lock_json
        .get_mut("packages")
        .and_then(Value::as_array_mut)
        .and_then(|packages| packages.first_mut())
        .and_then(Value::as_object_mut)
        .expect("package entry object")
        .insert("unexpected_entry".to_owned(), Value::Bool(true));
    fs::write(&lock_path, canonical_lock_text(&lock_json)).expect("lock writes");
    let error = load_package_lock_file(&lock_path).expect_err("unknown lock fields should reject");
    let _ = fs::remove_dir_all(&temp_dir);

    assert!(
        error.contains("package lock field `unexpected_top` is not allowed"),
        "{error}"
    );
    assert!(
        error.contains("package lock.packages[0] field `unexpected_entry` is not allowed"),
        "{error}"
    );
}

#[test]
fn package_lock_rejects_missing_required_fields() {
    let (temp_dir, lock_path, mut lock_json) = write_portable_notes_lock("missing-fields");
    let package = lock_json
        .get_mut("packages")
        .and_then(Value::as_array_mut)
        .and_then(|packages| packages.first_mut())
        .and_then(Value::as_object_mut)
        .expect("package entry object");
    package.remove("source");
    package.remove("manifest_sha256");
    fs::write(&lock_path, canonical_lock_text(&lock_json)).expect("lock writes");
    let error = load_package_lock_file(&lock_path).expect_err("missing lock fields should reject");
    let _ = fs::remove_dir_all(&temp_dir);

    assert!(
        error.contains("package lock.packages[0] missing required field `source`"),
        "{error}"
    );
    assert!(
        error.contains("package lock.packages[0] missing required field `manifest_sha256`"),
        "{error}"
    );
}

#[test]
fn package_lock_rejects_invalid_field_types_and_hash_shape() {
    let (temp_dir, lock_path, mut lock_json) = write_portable_notes_lock("invalid-fields");
    let package = lock_json
        .get_mut("packages")
        .and_then(Value::as_array_mut)
        .and_then(|packages| packages.first_mut())
        .and_then(Value::as_object_mut)
        .expect("package entry object");
    package.insert("package_id".to_owned(), Value::Null);
    package.insert(
        "source".to_owned(),
        json!({"type": "path", "path": "/etc/passwd"}),
    );
    package.insert(
        "manifest_sha256".to_owned(),
        Value::String("ABC".to_owned()),
    );
    fs::write(&lock_path, canonical_lock_text(&lock_json)).expect("lock writes");
    let error = load_package_lock_file(&lock_path).expect_err("invalid lock fields should reject");
    let _ = fs::remove_dir_all(&temp_dir);

    assert!(
        error.contains("package lock.packages[0] field `package_id` must be a non-empty string"),
        "{error}"
    );
    assert!(
        error.contains(
            "package lock.packages[0].source.path must be a portable project-relative path"
        ),
        "{error}"
    );
    assert!(
            error.contains(
                "package lock.packages[0] field `manifest_sha256` must be a 64-character lowercase hex digest"
            ),
            "{error}"
        );
}
