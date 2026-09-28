//! Alpha-renaming of locals for the canonical print (norm-plane §9).
//!
//! Two units that differ only in the names of their local bindings print,
//! and so hash, identically: each binding is replaced by a positional name,
//! `#0`, `#1`, ..., in the order the scope walk binds them (a `let` binds
//! after its initializer is walked), and every use that resolves to it
//! carries the same name. `#` begins no identifier in either
//! language, so a canonical name never collides with a name left as written.
//!
//! Soundness is the whole contract. A renaming must never make two units
//! print alike when they are not alpha-equivalent, so the resolver answers
//! for a whole unit or not at all: any construct whose scoping it does not
//! decide exactly (a macro, a destructuring pattern, a nested item, `var`,
//! `eval`, a shorthand field) leaves the unit printed as written, which errs
//! toward staleness.
//!
//! The walk is an allow-list. Each expression and statement kind it descends
//! is named; any other kind stops it. Types are opaque: nothing in them is
//! renamed. Last, a net: an identifier left as written whose name is also a
//! local's anywhere in the unit might be a use the walk misclassified, so
//! the unit is not renamed.

use std::collections::{BTreeSet, HashMap};

use tree_sitter::Node;

/// Canonical names by the node id of the identifier they replace.
pub(crate) type Renames = HashMap<usize, String>;

/// A construct whose scoping the resolver does not decide exactly.
struct Unresolved;

type Walk = Result<(), Unresolved>;

/// The lexical scopes of one unit, innermost last, and what they decided.
struct Scopes<'s> {
    source: &'s [u8],
    stack: Vec<Vec<(String, String)>>,
    renames: Renames,
    bound: BTreeSet<String>,
    next: usize,
}

impl<'s> Scopes<'s> {
    fn new(source: &'s [u8]) -> Self {
        Self {
            source,
            stack: Vec::new(),
            renames: Renames::new(),
            bound: BTreeSet::new(),
            next: 0,
        }
    }

    /// An identifier's name, as scopes compare it. `r#x` is `x`. A name with
    /// an escape or outside ASCII has more than one spelling, so the unit is
    /// not renamed rather than compared by bytes.
    fn name(&self, node: Node<'_>) -> Result<String, Unresolved> {
        let text = node.utf8_text(self.source).map_err(|_| Unresolved)?;
        let text = text.strip_prefix("r#").unwrap_or(text);
        let plain = !text.is_empty()
            && text
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$');
        if plain {
            Ok(text.to_owned())
        } else {
            Err(Unresolved)
        }
    }

    fn open(&mut self) {
        self.stack.push(Vec::new());
    }

    fn close(&mut self) {
        self.stack.pop();
    }

    /// A new binding in the innermost scope, shadowing any earlier one.
    /// Only an identifier binds. A destructuring pattern is refused here, and
    /// so is a parameter named `undefined`, whose uses parse as a keyword
    /// and would keep their name while it lost its own.
    fn bind(&mut self, node: Node<'_>) -> Result<String, Unresolved> {
        if node.kind() != "identifier" {
            return Err(Unresolved);
        }
        let name = self.name(node)?;
        let canonical = format!("#{}", self.next);
        self.next += 1;
        self.stack
            .last_mut()
            .ok_or(Unresolved)?
            .push((name.clone(), canonical.clone()));
        self.renames.insert(node.id(), canonical.clone());
        self.bound.insert(name);
        Ok(canonical)
    }

    /// A use: renamed when it resolves to a local, left as written when it
    /// names a global, an import or an item.
    fn refer(&mut self, node: Node<'_>) -> Walk {
        let name = self.name(node)?;
        let resolved = self
            .stack
            .iter()
            .rev()
            .flat_map(|scope| scope.iter().rev())
            .find(|(bound, _)| *bound == name)
            .map(|(_, canonical)| canonical.clone());
        if let Some(canonical) = resolved {
            self.renames.insert(node.id(), canonical);
        }
        Ok(())
    }

    /// The renames, once the net has passed them. `None` when there is
    /// nothing to rename or the net refuses.
    fn finish(self, unit: Node<'_>, excluded: fn(Node<'_>) -> bool) -> Option<Renames> {
        if self.renames.is_empty() {
            return None;
        }
        let mut stack = vec![unit];
        while let Some(node) = stack.pop() {
            let named = matches!(
                node.kind(),
                "identifier"
                    | "shorthand_field_identifier"
                    | "shorthand_property_identifier"
                    | "shorthand_property_identifier_pattern"
            );
            if named && !self.renames.contains_key(&node.id()) && !excluded(node) {
                let name = self.name(node).ok()?;
                if self.bound.contains(&name) {
                    return None;
                }
            }
            let mut cursor = node.walk();
            stack.extend(node.children(&mut cursor));
        }
        Some(self.renames)
    }
}

/// Whether `node` is its parent's `field`.
fn is_field(node: Node<'_>, field: &str) -> bool {
    node.parent()
        .and_then(|parent| parent.child_by_field_name(field))
        .is_some_and(|named| named.id() == node.id())
}

fn named_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

fn children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.children(&mut cursor).collect()
}

/// The renames for one Rust unit: a function, or the methods of an impl or
/// trait. `None` prints the unit as written.
pub(crate) fn rust(unit: Node<'_>, source: &[u8]) -> Option<Renames> {
    let mut scopes = Scopes::new(source);
    let walked = match unit.kind() {
        "function_item" | "function_signature_item" => rust_function(unit, &mut scopes),
        "impl_item" | "trait_item" => rust_members(unit, &mut scopes),
        _ => return None,
    };
    walked.ok()?;
    scopes.finish(unit, rust_excluded)
}

/// Identifiers that are never a local: an item's own name, a path segment,
/// a label, a lifetime, and anything inside an attribute on a member.
fn rust_excluded(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if matches!(parent.kind(), "function_item" | "function_signature_item")
        && is_field(node, "name")
    {
        return true;
    }
    if matches!(
        parent.kind(),
        "scoped_identifier" | "scoped_type_identifier" | "label" | "lifetime"
    ) {
        return true;
    }
    let mut ancestor = Some(parent);
    while let Some(node) = ancestor {
        if matches!(node.kind(), "attribute_item" | "inner_attribute_item") {
            return true;
        }
        ancestor = node.parent();
    }
    false
}

fn rust_members(unit: Node<'_>, scopes: &mut Scopes<'_>) -> Walk {
    let Some(body) = unit.child_by_field_name("body") else {
        return Ok(());
    };
    for member in named_children(body) {
        match member.kind() {
            "line_comment"
            | "block_comment"
            | "attribute_item"
            | "inner_attribute_item"
            | "type_item"
            | "associated_type" => {}
            "function_item" | "function_signature_item" => rust_function(member, scopes)?,
            "const_item" => {
                if let Some(value) = member.child_by_field_name("value") {
                    rust_expression(value, scopes)?;
                }
            }
            // A macro invocation among the members, or anything else: the
            // expression walk refuses what it does not know.
            _ => rust_expression(member, scopes)?,
        }
    }
    Ok(())
}

/// A function: its parameters bind in one scope and its body is a block
/// inside it. The name, generics, return type and where clause are opaque.
fn rust_function(function: Node<'_>, scopes: &mut Scopes<'_>) -> Walk {
    scopes.open();
    if let Some(parameters) = function.child_by_field_name("parameters") {
        for parameter in named_children(parameters) {
            match parameter.kind() {
                "line_comment" | "block_comment" | "self_parameter" => {}
                "parameter" => rust_parameter(parameter, scopes)?,
                // An attribute (a `cfg` could remove the binding), a C
                // variadic, or a bare type.
                // MUTATION-SUCCESS-EXPR: {}
                _ => return Err(Unresolved),
            }
        }
    }
    if let Some(body) = function.child_by_field_name("body") {
        rust_block(body, scopes)?;
    }
    scopes.close();
    Ok(())
}

fn rust_parameter(parameter: Node<'_>, scopes: &mut Scopes<'_>) -> Walk {
    let pattern = parameter.child_by_field_name("pattern").ok_or(Unresolved)?;
    rust_bind(pattern, scopes)
}

/// A binding pattern: a plain identifier, with or without `mut` or `ref`,
/// or `_`. Any other pattern is not resolved. An identifier beginning in
/// upper case may name a unit struct, a variant or a constant rather than
/// bind, so it is not resolved either.
fn rust_bind(pattern: Node<'_>, scopes: &mut Scopes<'_>) -> Walk {
    match pattern.kind() {
        "_" => Ok(()),
        "identifier" => {
            let name = scopes.name(pattern)?;
            if name.starts_with(|first: char| first.is_ascii_uppercase()) {
                return Err(Unresolved);
            }
            scopes.bind(pattern).map(|_| ())
        }
        // `mut x`, `ref x`, `ref mut x`: the pattern inside decides.
        "mut_pattern" | "ref_pattern" => named_children(pattern)
            .into_iter()
            .filter(|child| child.kind() != "mutable_specifier")
            .try_for_each(|inner| rust_bind(inner, scopes)),
        // MUTATION-SUCCESS-EXPR: Ok(())
        _ => Err(Unresolved),
    }
}

/// A block is a scope; a `let` binds from the statement after it, so its
/// initializer sees the binding it shadows.
fn rust_block(block: Node<'_>, scopes: &mut Scopes<'_>) -> Walk {
    scopes.open();
    for statement in named_children(block) {
        match statement.kind() {
            "line_comment" | "block_comment" | "label" | "empty_statement" => {}
            "let_declaration" => {
                if statement.child_by_field_name("alternative").is_some() {
                    // `let ... else`: the pattern may be refutable.
                    return Err(Unresolved);
                }
                if let Some(value) = statement.child_by_field_name("value") {
                    rust_expression(value, scopes)?;
                }
                rust_bind(
                    statement.child_by_field_name("pattern").ok_or(Unresolved)?,
                    scopes,
                )?;
            }
            // An expression statement, the tail expression, or an item,
            // which the expression walk refuses.
            _ => rust_expression(statement, scopes)?,
        }
    }
    scopes.close();
    Ok(())
}

/// Kinds with no local in them, left as written: literals, types, paths,
/// field names, labels and lifetimes.
fn rust_opaque(kind: &str) -> bool {
    matches!(
        kind,
        "line_comment"
            | "block_comment"
            | "boolean_literal"
            | "char_literal"
            | "float_literal"
            | "integer_literal"
            | "raw_string_literal"
            | "string_literal"
            | "field_identifier"
            | "label"
            | "lifetime"
            | "scoped_identifier"
            | "self"
            | "super"
            | "crate"
            | "mutable_specifier"
            | "abstract_type"
            | "array_type"
            | "bounded_type"
            | "bracketed_type"
            | "dynamic_type"
            | "function_type"
            | "generic_type"
            | "generic_type_with_turbofish"
            | "never_type"
            | "pointer_type"
            | "primitive_type"
            | "qualified_type"
            | "reference_type"
            | "scoped_type_identifier"
            | "tuple_type"
            | "type_arguments"
            | "type_identifier"
            | "unit_type"
    )
}

/// Kinds that bind nothing and whose children are walked in the same scope.
fn rust_transparent(kind: &str) -> bool {
    matches!(
        kind,
        "arguments"
            | "array_expression"
            | "assignment_expression"
            | "async_block"
            | "await_expression"
            | "base_field_initializer"
            | "binary_expression"
            | "break_expression"
            | "call_expression"
            | "compound_assignment_expr"
            | "const_block"
            | "continue_expression"
            | "else_clause"
            | "empty_statement"
            | "expression_statement"
            | "field_expression"
            | "field_initializer"
            | "field_initializer_list"
            | "gen_block"
            | "generic_function"
            | "if_expression"
            | "index_expression"
            | "loop_expression"
            | "parenthesized_expression"
            | "range_expression"
            | "reference_expression"
            | "return_expression"
            | "struct_expression"
            | "try_block"
            | "try_expression"
            | "tuple_expression"
            | "type_cast_expression"
            | "unary_expression"
            | "unit_expression"
            | "unsafe_block"
            | "while_expression"
            | "yield_expression"
    )
}

/// An expression. Anything not named here stops the walk: a macro, a match,
/// `if let` and `while let`, a shorthand field, an attribute, a nested item.
fn rust_expression(node: Node<'_>, scopes: &mut Scopes<'_>) -> Walk {
    let kind = node.kind();
    match kind {
        "identifier" => scopes.refer(node),
        "block" => rust_block(node, scopes),
        "closure_expression" => {
            scopes.open();
            let parameters = node.child_by_field_name("parameters").ok_or(Unresolved)?;
            for parameter in children(parameters) {
                match parameter.kind() {
                    "|" | "," | "line_comment" | "block_comment" => {}
                    "parameter" => rust_parameter(parameter, scopes)?,
                    _ => rust_bind(parameter, scopes)?,
                }
            }
            rust_expression(node.child_by_field_name("body").ok_or(Unresolved)?, scopes)?;
            scopes.close();
            Ok(())
        }
        "for_expression" => {
            // The iterator is evaluated outside the loop's binding.
            rust_expression(node.child_by_field_name("value").ok_or(Unresolved)?, scopes)?;
            scopes.open();
            rust_bind(
                node.child_by_field_name("pattern").ok_or(Unresolved)?,
                scopes,
            )?;
            rust_expression(node.child_by_field_name("body").ok_or(Unresolved)?, scopes)?;
            scopes.close();
            Ok(())
        }
        _ if rust_opaque(kind) => Ok(()),
        _ if rust_transparent(kind) => {
            for child in named_children(node) {
                rust_expression(child, scopes)?;
            }
            Ok(())
        }
        // MUTATION-SUCCESS-EXPR: Ok(())
        _ => Err(Unresolved),
    }
}

/// The renames for one TypeScript declaration: a function, a class's
/// members, or a `const`/`let` initializer. `None` prints it as written.
pub(crate) fn typescript(declaration: Node<'_>, source: &[u8]) -> Option<Renames> {
    let mut scopes = Scopes::new(source);
    let walked = match declaration.kind() {
        "function_declaration" | "generator_function_declaration" => {
            typescript_function(declaration, &mut scopes)
        }
        "class_declaration" | "abstract_class_declaration" => {
            typescript_class(declaration, &mut scopes)
        }
        "lexical_declaration" => named_children(declaration)
            .into_iter()
            .filter(|child| child.kind() == "variable_declarator")
            .filter_map(|declarator| declarator.child_by_field_name("value"))
            .try_for_each(|value| typescript_expression(value, &mut scopes)),
        _ => return None,
    };
    walked.ok()?;
    scopes.finish(declaration, typescript_excluded)
}

/// The declaration's own name is never a local.
fn typescript_excluded(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        matches!(
            parent.kind(),
            "function_declaration" | "generator_function_declaration" | "variable_declarator"
        )
    }) && is_field(node, "name")
}

fn typescript_class(class: Node<'_>, scopes: &mut Scopes<'_>) -> Walk {
    let Some(body) = class.child_by_field_name("body") else {
        return Ok(());
    };
    for member in named_children(body) {
        match member.kind() {
            "comment"
            | "decorator"
            | "method_signature"
            | "abstract_method_signature"
            | "index_signature" => {}
            "method_definition" => typescript_function(member, scopes)?,
            "public_field_definition" => {
                if let Some(value) = member.child_by_field_name("value") {
                    typescript_expression(value, scopes)?;
                }
            }
            "class_static_block" => {
                typescript_block(
                    member.child_by_field_name("body").ok_or(Unresolved)?,
                    scopes,
                )?;
            }
            // Anything else: the expression walk refuses what it does not
            // know.
            _ => typescript_expression(member, scopes)?,
        }
    }
    Ok(())
}

/// A function or method: its parameters bind in one scope, and its body is
/// a block inside it.
fn typescript_function(function: Node<'_>, scopes: &mut Scopes<'_>) -> Walk {
    scopes.open();
    typescript_parameters(
        function
            .child_by_field_name("parameters")
            .ok_or(Unresolved)?,
        scopes,
    )?;
    if let Some(body) = function.child_by_field_name("body") {
        typescript_block(body, scopes)?;
    }
    scopes.close();
    Ok(())
}

/// Plain identifier parameters, optional or rest. A destructuring pattern,
/// a decorator, or a parameter property (`private x`, which also declares a
/// field named after it) is not resolved. A default that refers to any
/// parameter is not resolved either.
fn typescript_parameters(parameters: Node<'_>, scopes: &mut Scopes<'_>) -> Walk {
    let mut canonicals = BTreeSet::new();
    let mut defaults = Vec::new();
    for parameter in named_children(parameters) {
        if parameter.kind() == "comment" {
            continue;
        }
        if children(parameter).iter().any(|child| {
            matches!(
                child.kind(),
                "decorator" | "accessibility_modifier" | "override_modifier" | "readonly"
            )
        }) {
            return Err(Unresolved);
        }
        let pattern = parameter.child_by_field_name("pattern").ok_or(Unresolved)?;
        // A destructuring pattern reaches `bind`, which refuses it.
        let binding = match pattern.kind() {
            "this" => None,
            "rest_pattern" => Some(pattern.named_child(0).ok_or(Unresolved)?),
            _ => Some(pattern),
        };
        if let Some(binding) = binding {
            canonicals.insert(scopes.bind(binding)?);
        }
        if let Some(value) = parameter.child_by_field_name("value") {
            defaults.push(value);
        }
    }
    for value in defaults {
        typescript_expression(value, scopes)?;
        let mut stack = vec![value];
        while let Some(node) = stack.pop() {
            if scopes
                .renames
                .get(&node.id())
                .is_some_and(|canonical| canonicals.contains(canonical))
            {
                return Err(Unresolved);
            }
            stack.extend(children(node));
        }
    }
    Ok(())
}

/// A block is a scope, and its `let` and `const` bindings are in it from the
/// block's first statement: a use before the declaration is the inner
/// binding in its dead zone, never an outer one.
fn typescript_block(block: Node<'_>, scopes: &mut Scopes<'_>) -> Walk {
    scopes.open();
    let statements = named_children(block);
    for statement in &statements {
        if statement.kind() == "lexical_declaration" {
            typescript_bind_declarators(*statement, scopes)?;
        }
    }
    for statement in statements {
        if statement.kind() == "lexical_declaration" {
            typescript_declarator_values(statement, scopes)?;
        } else {
            typescript_expression(statement, scopes)?;
        }
    }
    scopes.close();
    Ok(())
}

/// Binds each declarator's name; `bind` refuses a destructuring pattern.
fn typescript_bind_declarators(declaration: Node<'_>, scopes: &mut Scopes<'_>) -> Walk {
    for declarator in named_children(declaration) {
        if declarator.kind() == "variable_declarator" {
            scopes.bind(declarator.child_by_field_name("name").ok_or(Unresolved)?)?;
        }
    }
    Ok(())
}

fn typescript_declarator_values(declaration: Node<'_>, scopes: &mut Scopes<'_>) -> Walk {
    for declarator in named_children(declaration) {
        if let Some(value) = declarator.child_by_field_name("value") {
            typescript_expression(value, scopes)?;
        }
    }
    Ok(())
}

/// Kinds with no local in them, left as written: literals, property and
/// label names, JSX text, and every type.
fn typescript_opaque(kind: &str) -> bool {
    matches!(
        kind,
        "comment"
            | "string"
            | "number"
            | "regex"
            | "true"
            | "false"
            | "null"
            | "undefined"
            | "this"
            | "super"
            | "import"
            | "meta_property"
            | "property_identifier"
            | "private_property_identifier"
            | "statement_identifier"
            | "string_fragment"
            | "escape_sequence"
            | "jsx_text"
            | "jsx_namespace_name"
            | "html_character_reference"
            | "type_annotation"
            | "type_arguments"
            | "type_parameters"
            | "predefined_type"
            | "type_identifier"
            | "generic_type"
            | "nested_type_identifier"
            | "array_type"
            | "tuple_type"
            | "union_type"
            | "intersection_type"
            | "function_type"
            | "constructor_type"
            | "object_type"
            | "parenthesized_type"
            | "literal_type"
            | "lookup_type"
            | "conditional_type"
            | "infer_type"
            | "index_type_query"
            | "readonly_type"
            | "rest_type"
            | "optional_type"
            | "template_literal_type"
            | "type_query"
            | "type_predicate"
            | "type_predicate_annotation"
            | "asserts"
            | "asserts_annotation"
            | "this_type"
            | "existential_type"
            | "flow_maybe_type"
    )
}

/// Kinds that bind nothing and whose children are walked in the same scope.
fn typescript_transparent(kind: &str) -> bool {
    matches!(
        kind,
        "arguments"
            | "array"
            | "as_expression"
            | "assignment_expression"
            | "augmented_assignment_expression"
            | "await_expression"
            | "binary_expression"
            | "break_statement"
            | "call_expression"
            | "computed_property_name"
            | "continue_statement"
            | "debugger_statement"
            | "do_statement"
            | "else_clause"
            | "empty_statement"
            | "expression_statement"
            | "finally_clause"
            | "if_statement"
            | "instantiation_expression"
            | "jsx_attribute"
            | "jsx_closing_element"
            | "jsx_element"
            | "jsx_expression"
            | "jsx_opening_element"
            | "jsx_self_closing_element"
            | "labeled_statement"
            | "member_expression"
            | "new_expression"
            | "non_null_expression"
            | "object"
            | "optional_chain"
            | "pair"
            | "parenthesized_expression"
            | "return_statement"
            | "satisfies_expression"
            | "sequence_expression"
            | "spread_element"
            | "subscript_expression"
            | "switch_body"
            | "switch_case"
            | "switch_default"
            | "switch_statement"
            | "template_string"
            | "template_substitution"
            | "ternary_expression"
            | "throw_statement"
            | "try_statement"
            | "unary_expression"
            | "update_expression"
            | "while_statement"
            | "yield_expression"
    )
}

/// An expression or statement. Anything not named here stops the walk:
/// `var`, `with`, a destructuring pattern, a shorthand property, a function
/// expression or declaration, a class, a method in an object literal, and a
/// `let` or `const` anywhere but directly in a block or a `for` header.
fn typescript_expression(node: Node<'_>, scopes: &mut Scopes<'_>) -> Walk {
    let kind = node.kind();
    match kind {
        "identifier" => {
            let jsx_name = node.parent().is_some_and(|parent| {
                matches!(
                    parent.kind(),
                    "jsx_opening_element" | "jsx_closing_element" | "jsx_self_closing_element"
                )
            }) && is_field(node, "name");
            let text = node.utf8_text(scopes.source).map_err(|_| Unresolved)?;
            if jsx_name && text.starts_with(|first: char| first.is_ascii_lowercase()) {
                // `<div>` names an intrinsic element, not a binding.
                return Ok(());
            }
            if matches!(text, "arguments" | "eval") {
                return Err(Unresolved);
            }
            scopes.refer(node)
        }
        "statement_block" => typescript_block(node, scopes),
        "arrow_function" => {
            scopes.open();
            match node.child_by_field_name("parameter") {
                Some(parameter) => {
                    scopes.bind(parameter)?;
                }
                None => typescript_parameters(
                    node.child_by_field_name("parameters").ok_or(Unresolved)?,
                    scopes,
                )?,
            }
            typescript_expression(node.child_by_field_name("body").ok_or(Unresolved)?, scopes)?;
            scopes.close();
            Ok(())
        }
        "for_statement" => {
            scopes.open();
            if let Some(initializer) = node.child_by_field_name("initializer") {
                if initializer.kind() == "lexical_declaration" {
                    typescript_bind_declarators(initializer, scopes)?;
                    typescript_declarator_values(initializer, scopes)?;
                } else {
                    typescript_expression(initializer, scopes)?;
                }
            }
            for field in ["condition", "increment", "body"] {
                if let Some(child) = node.child_by_field_name(field) {
                    typescript_expression(child, scopes)?;
                }
            }
            scopes.close();
            Ok(())
        }
        "for_in_statement" => {
            let left = node.child_by_field_name("left").ok_or(Unresolved)?;
            let right = node.child_by_field_name("right").ok_or(Unresolved)?;
            let body = node.child_by_field_name("body").ok_or(Unresolved)?;
            let declared = node
                .child_by_field_name("kind")
                .map(|kind| kind.kind().to_owned());
            scopes.open();
            match declared.as_deref() {
                None => typescript_expression(left, scopes)?,
                // The iterable is evaluated with the loop's binding in its
                // dead zone, so it is bound first.
                Some("let" | "const") => {
                    scopes.bind(left)?;
                }
                // `var`, which hoists to the function.
                // MUTATION-SUCCESS-EXPR: {}
                _ => return Err(Unresolved),
            }
            typescript_expression(right, scopes)?;
            typescript_expression(body, scopes)?;
            scopes.close();
            Ok(())
        }
        "catch_clause" => {
            scopes.open();
            if let Some(parameter) = node.child_by_field_name("parameter") {
                scopes.bind(parameter)?;
            }
            typescript_block(node.child_by_field_name("body").ok_or(Unresolved)?, scopes)?;
            scopes.close();
            Ok(())
        }
        _ if typescript_opaque(kind) => Ok(()),
        _ if typescript_transparent(kind) => {
            for child in named_children(node) {
                typescript_expression(child, scopes)?;
            }
            Ok(())
        }
        // MUTATION-SUCCESS-EXPR: Ok(())
        _ => Err(Unresolved),
    }
}
