//! Detects transient data (nonces, locks, caches, temp flags) stored in
//! `persistent()` storage, which wastes ledger space and incurs unnecessary
//! TTL management overhead. Such data belongs in `temporary()` or `instance()`.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "persistent-for-temp";

/// Heuristic: key names that strongly suggest transient data.
fn key_looks_transient(key: &str) -> bool {
    let lower = key.to_lowercase();
    lower.contains("tmp")
        || lower.contains("temp")
        || lower.contains("nonce")
        || lower.contains("lock")
        || lower.contains("cache")
}

fn receiver_chain_contains_persistent(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            m.method == "persistent" || receiver_chain_contains_persistent(&m.receiver)
        }
        Expr::Field(f) => receiver_chain_contains_persistent(&f.base),
        _ => false,
    }
}

/// Extract the first argument of a `.set(key, val)` call as a string.
/// Handles `&IDENT`, `"literal"`, `symbol_short!(...)`, and bare `IDENT`.
fn first_arg_str(m: &ExprMethodCall) -> Option<String> {
    let arg = m.args.first()?;
    let inner = match arg {
        Expr::Reference(r) => &*r.expr,
        other => other,
    };
    let s = match inner {
        Expr::Path(p) => p
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default(),
        Expr::Lit(l) => match &l.lit {
            syn::Lit::Str(s) => s.value(),
            _ => String::new(),
        },
        Expr::Macro(mac) => mac
            .mac
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default(),
        _ => String::new(),
    };
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

pub struct PersistentForTempCheck;

impl Check for PersistentForTempCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let mut v = PersistentForTempVisitor {
                fn_name: method.sig.ident.to_string(),
                out: &mut out,
            };
            v.visit_block(&method.block);
        }
        out
    }
}

struct PersistentForTempVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl Visit<'_> for PersistentForTempVisitor<'_> {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if i.method == "set" && receiver_chain_contains_persistent(&i.receiver) {
            if let Some(key) = first_arg_str(i) {
                if key_looks_transient(&key) {
                    self.out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::Low,
                        file_path: String::new(),
                        line: i.span().start().line,
                        function_name: self.fn_name.clone(),
                        description: format!(
                            "Method `{}` stores a transient-looking key (`{}`) in \
                             `env.storage().persistent()`. Transient data such as nonces, \
                             locks, and caches should use `temporary()` or `instance()` \
                             to avoid wasting ledger space and incurring unnecessary TTL \
                             management overhead.",
                            self.fn_name, key
                        ),
                    });
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

    #[test]
    fn flags_nonce_in_persistent() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, symbol_short, Env};
pub struct C;
const NONCE: soroban_sdk::Symbol = symbol_short!("nonce");
#[contractimpl]
impl C {
    pub fn use_nonce(env: Env) {
        env.storage().persistent().set(&NONCE, &1u64);
    }
}
"#,
        )?;
        let hits = PersistentForTempCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Low);
        assert!(hits[0].description.contains("NONCE"));
        Ok(())
    }

    #[test]
    fn flags_lock_in_persistent() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn acquire(env: Env) {
        env.storage().persistent().set("lock", &true);
    }
}
"#,
        )?;
        let hits = PersistentForTempCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert!(hits[0].description.contains("lock"));
        Ok(())
    }

    #[test]
    fn flags_cache_in_persistent() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn warm_cache(env: Env, val: u32) {
        env.storage().persistent().set("cache_price", &val);
    }
}
"#,
        )?;
        let hits = PersistentForTempCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    fn flags_temp_key_in_persistent() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn store(env: Env, val: u32) {
        env.storage().persistent().set("temp_flag", &val);
    }
}
"#,
        )?;
        let hits = PersistentForTempCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    fn no_finding_for_persistent_balance() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn set_balance(env: Env, val: i128) {
        env.storage().persistent().set("balance", &val);
    }
}
"#,
        )?;
        let hits = PersistentForTempCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn no_finding_for_nonce_in_temporary() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn use_nonce(env: Env) {
        // Correct: nonce in temporary storage
        env.storage().temporary().set("nonce", &1u64);
    }
}
"#,
        )?;
        let hits = PersistentForTempCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn flags_tmp_prefix_in_persistent() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn store(env: Env, val: u32) {
        env.storage().persistent().set("tmp_state", &val);
    }
}
"#,
        )?;
        let hits = PersistentForTempCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    fn no_finding_outside_contractimpl() -> Result<(), syn::Error> {
        // A plain impl block (no #[contractimpl]) should not be scanned.
        let file = parse_file(
            r#"
pub struct C;
impl C {
    pub fn store(env: soroban_sdk::Env) {
        env.storage().persistent().set("nonce", &1u64);
    }
}
"#,
        )?;
        let hits = PersistentForTempCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
