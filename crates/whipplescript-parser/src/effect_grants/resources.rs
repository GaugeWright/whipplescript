//! Declaration-dependent grant checks shared by ordinary and composed bodies.
//! This proves vocabulary/kind compatibility, not effective runtime authority.
use super::*;
use whipplescript_custody::{CredentialKind, Operation};

#[derive(Default)]
struct Resources {
    files: BTreeSet<String>,
    memory: BTreeSet<String>,
    vaults: BTreeSet<String>,
    credentials: BTreeMap<String, String>,
}
impl Resources {
    fn from_program(program: &Program) -> Self {
        let mut resources = Self::default();
        for item in &program.items {
            match item {
                Item::FileStore(store) => {
                    resources.files.insert(store.name.name.clone());
                }
                Item::MemoryPool(pool) => {
                    resources.memory.insert(pool.name.name.clone());
                }
                Item::Vault(vault) => {
                    resources.vaults.insert(vault.name.name.clone());
                }
                Item::Credential(credential) => {
                    resources.credentials.insert(
                        credential.name.name.clone(),
                        credential.kind.name.replace('_', "-"),
                    );
                }
                _ => {}
            }
        }
        resources
    }
    fn from_ir(ir: &IrProgram) -> Self {
        Self {
            files: ir.file_stores.iter().map(|r| r.name.clone()).collect(),
            memory: ir.memory_pools.iter().map(|r| r.name.clone()).collect(),
            vaults: ir.vaults.iter().map(|r| r.name.clone()).collect(),
            credentials: ir
                .credentials
                .iter()
                .map(|r| (r.name.clone(), r.kind.clone()))
                .collect(),
        }
    }
}
#[derive(Clone, Copy)]
enum Family {
    File,
    Memory,
    Credential,
    Vault,
}
// Preserve the ordinary post-lowering diagnostic order.
const FAMILIES: [Family; 4] = [
    Family::File,
    Family::Memory,
    Family::Credential,
    Family::Vault,
];

struct Reporter<'a> {
    owner: &'a str,
    span: SourceSpan,
    diagnostics: &'a mut Vec<Diagnostic>,
}
impl Reporter<'_> {
    fn report(&mut self, code: DiagnosticCode, detail: String, suggestion: String) {
        self.diagnostics.push(
            Diagnostic::error(code, self.span, format!("{} {detail}", self.owner))
                .with_suggestion(suggestion),
        );
    }
}
fn validate(
    family: Family,
    resources: &Resources,
    grants: &[IrAccessGrant],
    report: &mut Reporter<'_>,
) {
    for grant in grants {
        match family {
            Family::File | Family::Memory => {
                let (declared, operations, noun, instruction): (
                    &BTreeSet<String>,
                    &[&str],
                    &str,
                    &str,
                ) = match family {
                    Family::File => (
                        &resources.files,
                        &["read", "write", "import", "export"],
                        "file store",
                        "file-store grants allow `read`, `write`, `import`, or `export`",
                    ),
                    _ => (
                        &resources.memory,
                        &["recall", "learn", "curate"],
                        "memory pool",
                        "memory-pool grants allow `recall`, `learn`, or `curate`",
                    ),
                };
                // Package resource vocabularies belong to their owning registry.
                if !declared.contains(&grant.resource) {
                    continue;
                }
                let adjective = if matches!(family, Family::File) {
                    "file"
                } else {
                    "memory"
                };
                for op in &grant.operations {
                    if !operations.contains(&op.operation.as_str()) {
                        report.report(
                            diagnostic_code!("capability.invalid_grant_operation"),
                            format!(
                                "grants `{}` on {noun} `{}`, which is not a {adjective} operation",
                                op.operation, grant.resource
                            ),
                            suggest_then_keyword(
                                &op.operation,
                                operations.iter().copied(),
                                instruction,
                            ),
                        );
                    }
                }
            }
            Family::Vault => {
                let Some(name) = grant.resource.strip_prefix("vault ") else {
                    continue;
                };
                if !resources.vaults.contains(name) {
                    report.report(
                        diagnostic_code!("type.unknown_resource"),
                        format!("grants access to undeclared vault `{name}`"),
                        format!(
                            "declare it with `vault {name} {{ kind <kind>  allow [<op>, ...] }}`"
                        ),
                    );
                    continue;
                }
                let container_names = || {
                    Operation::CONTAINER
                        .iter()
                        .map(|op| op.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                for op in &grant.operations {
                    let Ok(operation) = Operation::parse(&op.operation) else {
                        report.report(
                            diagnostic_code!("capability.invalid_grant_operation"),
                            format!(
                                "grants unknown operation `{}` on vault `{name}`",
                                op.operation
                            ),
                            format!(
                                "a vault grant names container operations: {}",
                                container_names()
                            ),
                        );
                        continue;
                    };
                    if !operation.is_container() {
                        report.report(diagnostic_code!("capability.invalid_narrowing"),
                            format!("grants member operation `{}` on vault `{name}`, which is a container grant", operation.as_str()),
                            format!("a vault grant names what may be done TO the container ({}); what its members may do is the vault's own `allow` list", container_names()));
                    }
                }
            }
            Family::Credential => {
                let Some(name) = grant.resource.strip_prefix("credential ") else {
                    continue;
                };
                let Some(declared) = resources.credentials.get(name) else {
                    continue;
                };
                // The declaration's own parser/lowerer owns malformed kinds.
                let Ok(kind) = CredentialKind::parse(declared) else {
                    continue;
                };
                for op in &grant.operations {
                    let Ok(operation) = Operation::parse(&op.operation) else {
                        continue;
                    };
                    if kind.supports(operation) {
                        continue;
                    }
                    let able = CredentialKind::ALL
                        .into_iter()
                        .filter(|candidate| candidate.supports(operation))
                        .map(|candidate| candidate.as_str())
                        .collect::<Vec<_>>();
                    report.report(diagnostic_code!("capability.credential_kind_mismatch"),
                        format!("grants `{}` on credential `{name}`, whose kind `{declared}` cannot perform it", op.operation),
                        format!("`{}` needs a credential of kind {}", op.operation, able.join(" or ")));
                }
            }
        }
    }
}

pub(crate) fn validate_ir(ir: &IrProgram, diagnostics: &mut Vec<Diagnostic>) {
    let resources = Resources::from_ir(ir);
    for family in FAMILIES {
        for rule in &ir.rules {
            for effect in &rule.metadata.effects {
                validate(
                    family,
                    &resources,
                    &effect.access_grants,
                    &mut Reporter {
                        owner: &format!("rule `{}`", rule.name),
                        span: effect.span,
                        diagnostics,
                    },
                );
            }
        }
    }
}

pub(crate) fn validate_composition(
    program: &Program,
    actions: &[ActionDecl],
    rules: &[&RuleDecl],
) -> Vec<Diagnostic> {
    let resources = Resources::from_program(program);
    visit_composition(actions, rules, &mut |owner, effect, diagnostics| {
        let grants = ir_access_grants_for_body(&effect.kind);
        for family in FAMILIES {
            validate(
                family,
                &resources,
                &grants,
                &mut Reporter {
                    owner,
                    span: effect.span,
                    diagnostics,
                },
            );
        }
    })
}

#[cfg(test)]
mod tests;
