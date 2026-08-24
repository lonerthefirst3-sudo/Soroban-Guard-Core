//! Flags extend_ttl called before storage has been written (no-op).

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Block, Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "ttl-before-write";

/// Flags `extend_ttl` calls that appear before any `set` call on the same storage tier
/// in the same function body, as extending TTL on a non-existent entry is a no-op.
pub struct TtlBeforeWriteCheck;

impl Check for TtlBeforeWriteCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = TtlVisitor {
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

fn get_storage_tier(expr: &Expr) -> Option<String> {
    match expr {
        Expr::MethodCall(m) => {
            if matches!(
                m.method.to_string().as_str(),
                "instance" | "persistent" | "temporary"
            ) {
                return Some(m.method.to_string());
            }
            get_storage_tier(&m.receiver)
        }
        Expr::Field(f) => get_storage_tier(&f.base),
        _ => None,
    }
}

fn is_extend_ttl_call(m: &ExprMethodCall) -> bool {
    m.method == "extend_ttl" && receiver_chain_contains_storage(&m.receiver)
}

fn is_set_call(m: &ExprMethodCall) -> bool {
    m.method == "set" && receiver_chain_contains_storage(&m.receiver)
}

fn extract_key_from_call(m: &ExprMethodCall) -> Option<String> {
    if m.args.is_empty() {
        return None;
    }
    Some(m.args[0].to_token_stream().to_string())
}

struct TtlVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl<'a> Visit<'a> for TtlVisitor<'a> {
    fn visit_block(&mut self, i: &'a Block) {
        let mut set_keys_by_tier: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        let mut ttl_calls = Vec::new();

        // First pass: collect all set and extend_ttl calls in order
        for stmt in &i.stmts {
            let mut collector = CallCollector {
                set_keys_by_tier: &mut set_keys_by_tier,
                ttl_calls: &mut ttl_calls,
            };
            collector.visit_stmt(stmt);
        }

        // Check each extend_ttl call
        for (ttl_call, tier, line) in ttl_calls {
            if let Some(keys) = set_keys_by_tier.get(&tier) {
                if !keys.contains(&ttl_call) {
                    self.out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::Low,
                        file_path: String::new(),
                        line,
                        function_name: self.fn_name.clone(),
                        description: format!(
                            "extend_ttl() called on {} storage key that has not been written \
                             (set) in this function. Extending TTL on a non-existent entry is a no-op.",
                            tier
                        ),
                    });
                }
            } else {
                // No set calls on this tier at all
                self.out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Low,
                    file_path: String::new(),
                    line,
                    function_name: self.fn_name.clone(),
                    description: format!(
                        "extend_ttl() called on {} storage without any preceding set() call. \
                         This is likely a logic error.",
                        tier
                    ),
                });
            }
        }

        visit::visit_block(self, i);
    }
}

struct CallCollector<'a> {
    set_keys_by_tier: &'a mut std::collections::HashMap<String, Vec<String>>,
    ttl_calls: &'a mut Vec<(String, String, usize)>,
}

impl<'a> Visit<'a> for CallCollector<'a> {
    fn visit_expr_method_call(&mut self, i: &'a ExprMethodCall) {
        if is_set_call(i) {
            if let Some(key) = extract_key_from_call(i) {
                if let Some(tier) = get_storage_tier(&i.receiver) {
                    self.set_keys_by_tier.entry(tier).or_default().push(key);
                }
            }
        } else if is_extend_ttl_call(i) {
            if let Some(key) = extract_key_from_call(i) {
                if let Some(tier) = get_storage_tier(&i.receiver) {
                    self.ttl_calls.push((key, tier, i.span().start().line));
                }
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
        Ok(TtlBeforeWriteCheck.run(&file, src))
    }

    #[test]
    fn flags_extend_ttl_without_set() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn extend_only(env: Env) {
        env.storage().instance().extend_ttl(&symbol_short!("key"), 100, 200);
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Low);
        Ok(())
    }

    #[test]
    fn passes_when_set_precedes_extend_ttl() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set_and_extend(env: Env, val: u32) {
        env.storage().instance().set(&symbol_short!("key"), &val);
        env.storage().instance().extend_ttl(&symbol_short!("key"), 100, 200);
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn flags_extend_ttl_on_different_key() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn mismatch(env: Env, val: u32) {
        env.storage().instance().set(&symbol_short!("key1"), &val);
        env.storage().instance().extend_ttl(&symbol_short!("key2"), 100, 200);
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        Ok(())
    }
}
