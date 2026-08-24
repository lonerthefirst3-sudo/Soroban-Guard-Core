//! Detects bump_to_ttl used instead of extend_ttl for persistent storage.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "bump-to-ttl-persistent";

/// Flags `bump_to_ttl` method calls on persistent or instance storage.
/// `bump_to_ttl` only extends TTL if remaining TTL is below threshold, unlike `extend_ttl`.
pub struct BumpToTtlCheck;

impl Check for BumpToTtlCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = StorageVisitor {
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

fn receiver_chain_contains_persistent_or_instance(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if matches!(m.method.to_string().as_str(), "persistent" | "instance") {
                return true;
            }
            receiver_chain_contains_persistent_or_instance(&m.receiver)
        }
        Expr::Field(f) => receiver_chain_contains_persistent_or_instance(&f.base),
        _ => false,
    }
}

struct StorageVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl Visit<'_> for StorageVisitor<'_> {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if i.method == "bump_to_ttl"
            && receiver_chain_contains_storage(&i.receiver)
            && receiver_chain_contains_persistent_or_instance(&i.receiver)
        {
            self.out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::Medium,
                file_path: String::new(),
                line: i.span().start().line,
                function_name: self.fn_name.clone(),
                description: format!(
                    "`bump_to_ttl` is called on persistent/instance storage in `{}`. \
                     `bump_to_ttl` only extends TTL if remaining TTL is below the threshold, \
                     unlike `extend_ttl` which guarantees extension. For critical persistent data, \
                     use `extend_ttl` to ensure TTL is always extended.",
                    self.fn_name
                ),
            });
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
    fn flags_bump_to_ttl_on_persistent() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};

pub struct C;

const K: soroban_sdk::Symbol = symbol_short!("k");

#[contractimpl]
impl C {
    pub fn update(env: Env) {
        env.require_auth();
        env.storage().persistent().bump_to_ttl(&K, 100, 1000);
    }
}
"#,
        )?;
        let hits = BumpToTtlCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        assert!(hits[0].description.contains("bump_to_ttl"));
        Ok(())
    }

    #[test]
    fn flags_bump_to_ttl_on_instance() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};

pub struct C;

const K: soroban_sdk::Symbol = symbol_short!("k");

#[contractimpl]
impl C {
    pub fn update(env: Env) {
        env.require_auth();
        env.storage().instance().bump_to_ttl(&K, 100, 1000);
    }
}
"#,
        )?;
        let hits = BumpToTtlCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        Ok(())
    }

    #[test]
    fn passes_extend_ttl_on_persistent() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};

pub struct C;

const K: soroban_sdk::Symbol = symbol_short!("k");

#[contractimpl]
impl C {
    pub fn update(env: Env) {
        env.require_auth();
        env.storage().persistent().extend_ttl(&K, 100, 1000);
    }
}
"#,
        )?;
        let hits = BumpToTtlCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_bump_to_ttl_on_temporary() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};

pub struct C;

const K: soroban_sdk::Symbol = symbol_short!("k");

#[contractimpl]
impl C {
    pub fn update(env: Env) {
        env.require_auth();
        env.storage().temporary().bump_to_ttl(&K, 100, 1000);
    }
}
"#,
        )?;
        let hits = BumpToTtlCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
