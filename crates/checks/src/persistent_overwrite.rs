//! Flags persistent().set(key, val) without reading existing value first.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Block, Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "persistent-overwrite";

/// Flags `env.storage().persistent().set(key, ...)` calls in `#[contractimpl]` functions
/// that have no preceding `env.storage().persistent().get(key)` or `.has(key)` call in the same function body.
pub struct PersistentOverwriteCheck;

impl Check for PersistentOverwriteCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = PersistentVisitor {
                fn_name: fn_name.clone(),
                out: &mut out,
            };
            v.visit_block(&method.block);
        }
        out
    }
}

fn receiver_chain_contains_persistent(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "persistent" {
                return true;
            }
            receiver_chain_contains_persistent(&m.receiver)
        }
        Expr::Field(f) => receiver_chain_contains_persistent(&f.base),
        _ => false,
    }
}

fn is_persistent_set_call(m: &ExprMethodCall) -> bool {
    m.method == "set" && receiver_chain_contains_persistent(&m.receiver)
}

fn is_persistent_get_or_has_call(m: &ExprMethodCall) -> bool {
    (m.method == "get" || m.method == "has") && receiver_chain_contains_persistent(&m.receiver)
}

fn extract_key_from_call(m: &ExprMethodCall) -> Option<String> {
    if m.args.is_empty() {
        return None;
    }
    Some(m.args[0].to_token_stream().to_string())
}

struct PersistentVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl<'a> Visit<'a> for PersistentVisitor<'a> {
    fn visit_block(&mut self, i: &'a Block) {
        let mut get_keys = Vec::new();
        let mut set_calls = Vec::new();

        // First pass: collect all get/has and set calls
        for stmt in &i.stmts {
            let mut collector = CallCollector {
                get_keys: &mut get_keys,
                set_calls: &mut set_calls,
            };
            collector.visit_stmt(stmt);
        }

        // Check each set() call against get/has calls
        for (set_call, line) in set_calls {
            if !get_keys.contains(&set_call) {
                self.out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Medium,
                    file_path: String::new(),
                    line,
                    function_name: self.fn_name.clone(),
                    description: "persistent().set() called without a preceding get() or has() \
                                   guard. Writing without reading the existing value may indicate \
                                   accidental data loss in multi-user contracts."
                        .to_string(),
                });
            }
        }
    }
}

struct CallCollector<'a> {
    get_keys: &'a mut Vec<String>,
    set_calls: &'a mut Vec<(String, usize)>,
}

impl<'a> Visit<'a> for CallCollector<'a> {
    fn visit_expr_method_call(&mut self, i: &'a ExprMethodCall) {
        if is_persistent_get_or_has_call(i) {
            if let Some(key) = extract_key_from_call(i) {
                self.get_keys.push(key);
            }
        } else if is_persistent_set_call(i) {
            if let Some(key) = extract_key_from_call(i) {
                self.set_calls.push((key, i.span().start().line));
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
        Ok(PersistentOverwriteCheck.run(&file, src))
    }

    #[test]
    fn flags_persistent_set_without_get() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn update_value(env: Env, val: u32) {
        env.storage().persistent().set(&symbol_short!("key"), &val);
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        Ok(())
    }

    #[test]
    fn passes_when_get_precedes_set() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn update_value(env: Env, val: u32) {
        let _old = env.storage().persistent().get(&symbol_short!("key"));
        env.storage().persistent().set(&symbol_short!("key"), &val);
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_when_has_precedes_set() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn update_value(env: Env, val: u32) {
        if env.storage().persistent().has(&symbol_short!("key")) {
            env.storage().persistent().set(&symbol_short!("key"), &val);
        }
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }
}
