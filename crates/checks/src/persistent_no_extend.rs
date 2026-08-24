//! Flags persistent storage keys that are written via `persistent().set(key, …)` but
//! never appear in any `extend_ttl(key, …)` call across the file.
//!
//! A persistent entry that is never TTL-extended will expire and become inaccessible,
//! effectively bricking the contract.

use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "persistent-no-extend";

pub struct PersistentNoExtendCheck;

impl Check for PersistentNoExtendCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut v = PersistentTtlVisitor::default();
        v.visit_file(file);

        let mut out = Vec::new();
        for (key, line) in &v.set_keys {
            if !v.extend_keys.contains(key) {
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Medium,
                    file_path: String::new(),
                    line: *line,
                    function_name: String::new(),
                    description: format!(
                        "Persistent storage key `{key}` is written via `persistent().set()` but \
                         `extend_ttl()` is never called for it. The entry will expire and become \
                         inaccessible, potentially bricking the contract."
                    ),
                });
            }
        }
        out
    }
}

#[derive(Default)]
struct PersistentTtlVisitor {
    /// (key_repr, first_set_line)
    set_keys: Vec<(String, usize)>,
    extend_keys: Vec<String>,
}

impl<'ast> Visit<'ast> for PersistentTtlVisitor {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        let method = i.method.to_string();

        if method == "set" && receiver_chain_has_persistent(&i.receiver) && i.args.len() == 2 {
            if let Some(key) = key_repr(&i.args[0]) {
                // Only record first occurrence per key
                if !self.set_keys.iter().any(|(k, _)| k == &key) {
                    self.set_keys.push((key, i.span().start().line));
                }
            }
        }

        if method == "extend_ttl" && receiver_chain_has_persistent(&i.receiver) && !i.args.is_empty() {
            if let Some(key) = key_repr(&i.args[0]) {
                if !self.extend_keys.contains(&key) {
                    self.extend_keys.push(key);
                }
            }
        }

        visit::visit_expr_method_call(self, i);
    }
}

fn receiver_chain_has_persistent(expr: &Expr) -> bool {
    let mut cur = expr;
    loop {
        match cur {
            Expr::MethodCall(m) => {
                if m.method == "persistent" {
                    return true;
                }
                cur = &m.receiver;
            }
            _ => return false,
        }
    }
}

/// Produce a stable string representation of a key expression for comparison.
fn key_repr(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Reference(r) => key_repr(&r.expr),
        Expr::Path(p) => Some(
            p.path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect::<Vec<_>>()
                .join("::"),
        ),
        Expr::Lit(l) => Some(quote_lit(l)),
        Expr::Macro(m) => Some(
            m.mac
                .path
                .segments
                .last()
                .map(|s| s.ident.to_string())
                .unwrap_or_default(),
        ),
        _ => None,
    }
}

fn quote_lit(l: &syn::ExprLit) -> String {
    match &l.lit {
        syn::Lit::Str(s) => s.value(),
        syn::Lit::Int(i) => i.base10_digits().to_string(),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        PersistentNoExtendCheck.run(&parse_file(src).unwrap(), src)
    }

    #[test]
    fn flags_persistent_set_without_extend_ttl() {
        let hits = run(r#"
use soroban_sdk::{contract, contractimpl, Env};
#[contract] pub struct C;
#[contractimpl]
impl C {
    pub fn store(env: Env, val: i128) {
        env.storage().persistent().set(&KEY, &val);
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        assert_eq!(hits[0].check_name, CHECK_NAME);
    }

    #[test]
    fn passes_when_extend_ttl_present() {
        let hits = run(r#"
use soroban_sdk::{contract, contractimpl, Env};
#[contract] pub struct C;
#[contractimpl]
impl C {
    pub fn store(env: Env, val: i128) {
        env.storage().persistent().set(&KEY, &val);
        env.storage().persistent().extend_ttl(&KEY, 1000, 2000);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn ignores_instance_storage() {
        let hits = run(r#"
use soroban_sdk::{contract, contractimpl, Env};
#[contract] pub struct C;
#[contractimpl]
impl C {
    pub fn store(env: Env, val: i128) {
        env.storage().instance().set(&KEY, &val);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn extend_in_separate_fn_suppresses_flag() {
        let hits = run(r#"
use soroban_sdk::{contract, contractimpl, Env};
#[contract] pub struct C;
#[contractimpl]
impl C {
    pub fn store(env: Env, val: i128) {
        env.storage().persistent().set(&KEY, &val);
    }
    pub fn refresh(env: Env) {
        env.storage().persistent().extend_ttl(&KEY, 1000, 2000);
    }
}
"#);
        assert!(hits.is_empty());
    }
}
