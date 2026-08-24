//! Flags `env.storage()...remove(key)` calls without a preceding `has(key)` guard.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Block, Expr, ExprMethodCall, File, Stmt};

const CHECK_NAME: &str = "remove-without-has";

/// Flags `env.storage()...remove(key)` calls in `#[contractimpl]` functions
/// that have no preceding `env.storage()...has(key)` call in the same function body.
pub struct RemoveWithoutHasCheck;

impl Check for RemoveWithoutHasCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = RemoveVisitor {
                fn_name: fn_name.clone(),
                out: &mut out,
            };
            v.visit_block(&method.block);
        }
        out
    }
}

fn receiver_chain_contains_storage(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "storage" {
                return true;
            }
            receiver_chain_contains_storage(&m.receiver)
        }
        Expr::Field(f) => receiver_chain_contains_storage(&f.base),
        _ => false,
    }
}

fn is_remove_call(m: &ExprMethodCall) -> bool {
    m.method == "remove" && receiver_chain_contains_storage(&m.receiver)
}

fn is_has_call(m: &ExprMethodCall) -> bool {
    m.method == "has" && receiver_chain_contains_storage(&m.receiver)
}

fn extract_key_from_call(m: &ExprMethodCall) -> Option<String> {
    if m.args.is_empty() {
        return None;
    }
    // Simple heuristic: convert first arg to string representation
    Some(format!("{:?}", m.args[0]))
}

struct RemoveVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl<'a> Visit<'a> for RemoveVisitor<'a> {
    fn visit_block(&mut self, i: &'a Block) {
        let mut has_keys = Vec::new();
        let mut remove_calls = Vec::new();

        // First pass: collect all has() and remove() calls
        for stmt in &i.stmts {
            let mut collector = CallCollector {
                has_keys: &mut has_keys,
                remove_calls: &mut remove_calls,
            };
            collector.visit_stmt(stmt);
        }

        // Check each remove() call against has() calls
        for (remove_call, line) in remove_calls {
            if !has_keys.contains(&remove_call) {
                self.out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Low,
                    file_path: String::new(),
                    line,
                    function_name: self.fn_name.clone(),
                    description: "storage.remove() called without a preceding has() guard. \
                                   Removing a non-existent key is a no-op, which may indicate \
                                   a logic error."
                        .to_string(),
                });
            }
        }

        visit::visit_block(self, i);
    }
}

struct CallCollector<'a> {
    has_keys: &'a mut Vec<String>,
    remove_calls: &'a mut Vec<(String, usize)>,
}

impl<'a> Visit<'a> for CallCollector<'a> {
    fn visit_expr_method_call(&mut self, i: &'a ExprMethodCall) {
        if is_has_call(i) {
            if let Some(key) = extract_key_from_call(i) {
                self.has_keys.push(key);
            }
        } else if is_remove_call(i) {
            if let Some(key) = extract_key_from_call(i) {
                self.remove_calls.push((key, i.span().start().line));
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run_on_src(src: &str) -> Result<Vec<Finding>, syn::Error> {
        let file = parse_file(src)?;
        Ok(RemoveWithoutHasCheck.run(&file, src))
    }

    #[test]
    fn flags_remove_without_has() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn remove_key(env: Env) {
        env.storage().instance().remove(&Symbol::new(&env, "key"));
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "remove_key");
        assert_eq!(hits[0].severity, Severity::Low);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        Ok(())
    }

    #[test]
    fn passes_when_has_precedes_remove() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn remove_key(env: Env) {
        if env.storage().instance().has(&Symbol::new(&env, "key")) {
            env.storage().instance().remove(&Symbol::new(&env, "key"));
        }
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_non_contractimpl_impl() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{Env, Symbol};

pub struct Contract;

impl Contract {
    pub fn helper(env: Env) {
        env.storage().instance().remove(&Symbol::new(&env, "key"));
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }
}
