//! Detects repeated env.storage() calls without caching in local variable.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "storage-no-cache";

/// Flags functions with more than 3 distinct env.storage().instance/persistent/temporary() calls.
pub struct StorageNoCacheCheck;

impl Check for StorageNoCacheCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = StorageVisitor {
                storage_calls: Vec::new(),
            };
            v.visit_block(&method.block);

            if v.storage_calls.len() > 3 {
                if let Some(first_line) = v.storage_calls.first() {
                    out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::Low,
                        file_path: String::new(),
                        line: *first_line,
                        function_name: fn_name,
                        description: format!(
                            "Function makes {} distinct env.storage() calls without caching. \
                             Each call is a host call with compute cost. Cache the result in a \
                             local variable to optimize compute budget usage.",
                            v.storage_calls.len()
                        ),
                    });
                }
            }
        }
        out
    }
}

fn is_storage_tier_call(m: &ExprMethodCall) -> bool {
    let method_name = m.method.to_string();
    if !matches!(
        method_name.as_str(),
        "instance" | "persistent" | "temporary"
    ) {
        return false;
    }

    match &*m.receiver {
        Expr::MethodCall(recv_m) => recv_m.method == "storage",
        _ => false,
    }
}

struct StorageVisitor {
    storage_calls: Vec<usize>,
}

impl<'ast> Visit<'ast> for StorageVisitor {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if is_storage_tier_call(i) {
            self.storage_calls.push(i.span().start().line);
        }
        visit::visit_expr_method_call(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    #[test]
    fn flags_multiple_storage_calls() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};

pub struct C;

const K1: soroban_sdk::Symbol = symbol_short!("k1");
const K2: soroban_sdk::Symbol = symbol_short!("k2");
const K3: soroban_sdk::Symbol = symbol_short!("k3");
const K4: soroban_sdk::Symbol = symbol_short!("k4");

#[contractimpl]
impl C {
    pub fn process(env: Env) {
        env.require_auth();
        env.storage().instance().set(&K1, &1u32);
        env.storage().instance().set(&K2, &2u32);
        env.storage().instance().set(&K3, &3u32);
        env.storage().instance().set(&K4, &4u32);
    }
}
"#,
        )?;
        let hits = StorageNoCacheCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Low);
        assert!(hits[0].description.contains("4 distinct"));
        Ok(())
    }

    #[test]
    fn passes_cached_storage() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};

pub struct C;

const K1: soroban_sdk::Symbol = symbol_short!("k1");
const K2: soroban_sdk::Symbol = symbol_short!("k2");
const K3: soroban_sdk::Symbol = symbol_short!("k3");

#[contractimpl]
impl C {
    pub fn process(env: Env) {
        env.require_auth();
        let storage = env.storage().instance();
        storage.set(&K1, &1u32);
        storage.set(&K2, &2u32);
        storage.set(&K3, &3u32);
    }
}
"#,
        )?;
        let hits = StorageNoCacheCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_three_or_fewer_calls() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};

pub struct C;

const K1: soroban_sdk::Symbol = symbol_short!("k1");
const K2: soroban_sdk::Symbol = symbol_short!("k2");
const K3: soroban_sdk::Symbol = symbol_short!("k3");

#[contractimpl]
impl C {
    pub fn process(env: Env) {
        env.require_auth();
        env.storage().instance().set(&K1, &1u32);
        env.storage().instance().set(&K2, &2u32);
        env.storage().instance().set(&K3, &3u32);
    }
}
"#,
        )?;
        let hits = StorageNoCacheCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
