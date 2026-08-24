//! Flags instance().set(key, ...) without prior has() guard for first-time init.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Block, Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "instance-set-no-has";

/// Flags `env.storage().instance().set(key, ...)` calls in non-initializer functions
/// that have no preceding `env.storage().instance().has(key)` call in the same function body.
pub struct InstanceSetNoHasCheck;

impl Check for InstanceSetNoHasCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            // Skip obvious initializer functions
            if fn_name.contains("init") {
                continue;
            }
            let mut v = InstanceVisitor {
                fn_name: fn_name.clone(),
                out: &mut out,
            };
            v.visit_block(&method.block);
        }
        out
    }
}

fn receiver_chain_contains_instance(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "instance" {
                return true;
            }
            receiver_chain_contains_instance(&m.receiver)
        }
        Expr::Field(f) => receiver_chain_contains_instance(&f.base),
        _ => false,
    }
}

fn is_instance_set_call(m: &ExprMethodCall) -> bool {
    m.method == "set" && receiver_chain_contains_instance(&m.receiver)
}

fn is_instance_has_call(m: &ExprMethodCall) -> bool {
    m.method == "has" && receiver_chain_contains_instance(&m.receiver)
}

fn extract_key_from_call(m: &ExprMethodCall) -> Option<String> {
    if m.args.is_empty() {
        return None;
    }
    Some(m.args[0].to_token_stream().to_string())
}

struct InstanceVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl<'a> Visit<'a> for InstanceVisitor<'a> {
    fn visit_block(&mut self, i: &'a Block) {
        let mut has_keys = Vec::new();
        let mut set_calls = Vec::new();

        // First pass: collect all has and set calls
        for stmt in &i.stmts {
            let mut collector = CallCollector {
                has_keys: &mut has_keys,
                set_calls: &mut set_calls,
            };
            collector.visit_stmt(stmt);
        }

        // Check each set() call against has() calls
        for (set_call, line) in set_calls {
            if !has_keys.contains(&set_call) {
                self.out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Low,
                    file_path: String::new(),
                    line,
                    function_name: self.fn_name.clone(),
                    description: "instance().set() called without a preceding has() guard. \
                                   Writing to instance storage without checking init status may \
                                   silently overwrite existing state."
                        .to_string(),
                });
            }
        }
    }
}

struct CallCollector<'a> {
    has_keys: &'a mut Vec<String>,
    set_calls: &'a mut Vec<(String, usize)>,
}

impl<'a> Visit<'a> for CallCollector<'a> {
    fn visit_expr_method_call(&mut self, i: &'a ExprMethodCall) {
        if is_instance_has_call(i) {
            if let Some(key) = extract_key_from_call(i) {
                self.has_keys.push(key);
            }
        } else if is_instance_set_call(i) {
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
        Ok(InstanceSetNoHasCheck.run(&file, src))
    }

    #[test]
    fn flags_instance_set_without_has() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn update_state(env: Env, val: u32) {
        env.storage().instance().set(&symbol_short!("state"), &val);
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Low);
        assert_eq!(hits[0].check_name, CHECK_NAME);
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
    pub fn update_state(env: Env, val: u32) {
        if env.storage().instance().has(&symbol_short!("state")) {
            env.storage().instance().set(&symbol_short!("state"), &val);
        }
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn skips_init_functions() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn initialize(env: Env, val: u32) {
        env.storage().instance().set(&symbol_short!("state"), &val);
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }
}
