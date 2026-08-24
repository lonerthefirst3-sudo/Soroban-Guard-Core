//! Flags `.expect(msg)` calls where `msg` leaks internal storage key names or
//! contains `{}` format specifiers, exposing implementation details on-chain.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File, Lit};

const CHECK_NAME: &str = "expect-leaks";

/// Detects `.expect(msg)` calls where `msg` contains `{}` format specifiers or
/// references to storage key variable names, leaking internal state information
/// into on-chain transaction output.
pub struct ExpectLeaksCheck;

impl Check for ExpectLeaksCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            // Collect storage key variable names from this function's local bindings.
            let key_names = collect_key_names(&method.block);
            let fn_name = method.sig.ident.to_string();
            let mut v = ExpectLeaksVisitor {
                fn_name,
                key_names,
                out: &mut out,
            };
            v.visit_block(&method.block);
        }
        out
    }
}

/// Collect identifiers that look like storage keys: variables bound via `let`
/// whose names contain "key", "KEY", or are used as storage arguments.
fn collect_key_names(block: &syn::Block) -> Vec<String> {
    let mut names = Vec::new();
    for stmt in &block.stmts {
        if let syn::Stmt::Local(local) = stmt {
            if let syn::Pat::Ident(pat_ident) = &local.pat {
                let name = pat_ident.ident.to_string();
                if name.to_lowercase().contains("key") {
                    names.push(name);
                }
            }
        }
    }
    names
}

/// Returns true if the string literal leaks internal details:
/// - contains `{}` format specifiers, or
/// - contains any of the provided key names.
fn msg_leaks(msg: &str, key_names: &[String]) -> bool {
    if msg.contains("{}") {
        return true;
    }
    for key in key_names {
        if msg.contains(key.as_str()) {
            return true;
        }
    }
    false
}

struct ExpectLeaksVisitor<'a> {
    fn_name: String,
    key_names: Vec<String>,
    out: &'a mut Vec<Finding>,
}

impl Visit<'_> for ExpectLeaksVisitor<'_> {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if i.method == "expect" {
            if let Some(Expr::Lit(expr_lit)) = i.args.first() {
                if let Lit::Str(lit_str) = &expr_lit.lit {
                    let msg = lit_str.value();
                    if msg_leaks(&msg, &self.key_names) {
                        self.out.push(Finding {
                            check_name: CHECK_NAME.to_string(),
                            severity: Severity::Low,
                            file_path: String::new(),
                            line: i.span().start().line,
                            function_name: self.fn_name.clone(),
                            description: format!(
                                "`.expect(\"{msg}\")` in `{}` leaks internal storage key \
                                     or state information into on-chain output. Use a generic \
                                     error message that does not reference internal keys or \
                                     format specifiers.",
                                self.fn_name
                            ),
                        });
                    }
                }
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        let file = parse_file(src).expect("parse");
        ExpectLeaksCheck.run(&file, src)
    }

    const WRAPPER: &str = r#"
pub struct C;
#[contractimpl]
impl C {
    pub fn f(env: Env) -> i128 {
        let balance_key = symbol_short!("bal");
        BODY
    }
}
"#;

    fn with_body(body: &str) -> String {
        WRAPPER.replace("BODY", body)
    }

    #[test]
    fn flags_format_specifier() {
        let src = with_body(r#"env.storage().persistent().get(&balance_key).expect("failed: {}")"#);
        let hits = run(&src);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        assert_eq!(hits[0].severity, Severity::Low);
        assert_eq!(hits[0].function_name, "f");
    }

    #[test]
    fn flags_key_name_in_message() {
        let src = with_body(
            r#"env.storage().persistent().get(&balance_key).expect("balance_key not found")"#,
        );
        let hits = run(&src);
        assert_eq!(hits.len(), 1);
        assert!(hits[0].description.contains("balance_key not found"));
    }

    #[test]
    fn does_not_flag_generic_message() {
        let src = with_body(
            r#"env.storage().persistent().get(&balance_key).expect("storage read failed")"#,
        );
        let hits = run(&src);
        assert_eq!(hits.len(), 0);
    }

    #[test]
    fn does_not_flag_outside_contractimpl() {
        let src = r#"
fn helper() -> i128 {
    let balance_key = "key";
    some_result.expect("balance_key missing")
}
"#;
        let hits = run(src);
        assert_eq!(hits.len(), 0);
    }

    #[test]
    fn flags_multiple_leaking_expects() {
        let src = with_body(
            r#"
            let v1 = env.storage().persistent().get(&balance_key).expect("balance_key read");
            let v2 = env.storage().persistent().get(&balance_key).expect("value is {}");
            v1
            "#,
        );
        let hits = run(&src);
        assert_eq!(hits.len(), 2);
    }
}
