use super::*;
use whipplescript_parser::action_plan::resolved::resolve_rule_types;

const SOURCE: &str = r#"workflow Demo
tracker jobs { provider builtin }
lease slots { key Ticket slots 1 ttl 5m }
class Ticket { id string }
action finish_it(item WorkItem) -> null {
  claim item as held
  finish held { summary "done" } as finished
  return null
}
rule run
  when jobs has ready issue as item
  when Ticket as key
=> {
  finish_it(item) as result
  acquire slots for key until ttl as slot
  renew slot as renewed
}"#;

#[test]
fn kernel_resource_adapter_matches_the_compiler_owned_projection() {
    let parsed = whipplescript_parser::parse_program(SOURCE);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let typed = resolve_rule_types(&parsed.program, "run").unwrap();
    let compiled = whipplescript_parser::compile_program(SOURCE);
    let ir = compiled
        .ir
        .unwrap_or_else(|| panic!("{:?}", compiled.diagnostics));

    let compiler = whipplescript_parser::action_plan::resources::resolve(&typed, &ir).unwrap();
    assert_eq!(resolve(&typed, &ir).unwrap(), compiler);
    assert_eq!(
        managed_statement_executor_sinks(&typed, &ir)
            .unwrap()
            .effects,
        compiler
    );
}
