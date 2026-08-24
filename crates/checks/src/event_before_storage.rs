//! Event emitted before storage write: `env.events().publish(…)` precedes
//! `env.storage()…set(…)` in statement order within a `#[contractimpl]` method.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{Expr, ExprMethodCall, File, Stmt};

const CHECK_NAME: &str = "event-before-storage";

/// Flags `#[contractimpl]` functions where `env.events().publish(…)` appears at a
/// lower statement index than `env.storage()…set(…)`.  An event emitted before the
/// storage write is observable on-chain even if the write subsequently panics.
pub struct EventBeforeStorageCheck;

impl Check for EventBeforeStorageCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let stmts = &method.block.stmts;

            let publish_indices = stmt_indices_matching(stmts, is_events_publish);
            let set_indices = stmt_indices_matching(stmts, is_storage_set);

            // Flag if any publish comes before any storage set.
            for &pi in &publish_indices {
                if set_indices.iter().any(|&si| pi < si) {
                    let line = stmt_line(&stmts[pi]);
                    out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::Medium,
                        file_path: String::new(),
                        line,
                        function_name: fn_name.clone(),
                        description: format!(
                            "`{}` emits an event via `env.events().publish(…)` before a \
                             `env.storage()…set(…)` call. The event is observable on-chain \
                             even if the storage write later panics. Move all event emissions \
                             after all state changes.",
                            fn_name
                        ),
                    });
                    break; // one finding per function is enough
                }
            }
        }
        out
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn receiver_chain_contains(expr: &Expr, name: &str) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == name {
                return true;
            }
            receiver_chain_contains(&m.receiver, name)
        }
        _ => false,
    }
}

fn is_events_publish(m: &ExprMethodCall) -> bool {
    m.method == "publish" && receiver_chain_contains(&m.receiver, "events")
}

fn is_storage_set(m: &ExprMethodCall) -> bool {
    m.method == "set" && receiver_chain_contains(&m.receiver, "storage")
}

/// Collect top-level statement indices where a method call matching `pred` appears.
fn stmt_indices_matching(stmts: &[Stmt], pred: fn(&ExprMethodCall) -> bool) -> Vec<usize> {
    stmts
        .iter()
        .enumerate()
        .filter(|(_, s)| stmt_contains(s, pred))
        .map(|(i, _)| i)
        .collect()
}

fn stmt_contains(stmt: &Stmt, pred: fn(&ExprMethodCall) -> bool) -> bool {
    let mut v = MethodCallFinder { pred, found: false };
    v.visit_stmt(stmt);
    v.found
}

struct MethodCallFinder {
    pred: fn(&ExprMethodCall) -> bool,
    found: bool,
}

impl<'ast> Visit<'ast> for MethodCallFinder {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if (self.pred)(i) {
            self.found = true;
        }
        syn::visit::visit_expr_method_call(self, i);
    }
}

fn stmt_line(stmt: &Stmt) -> usize {
    match stmt {
        Stmt::Expr(e, _) => e.span().start().line,
        Stmt::Local(l) => l.span().start().line,
        _ => 0,
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    const VULNERABLE: &str = r#"
use soroban_sdk::{contract, contractimpl, symbol_short, Env, Symbol};

#[contract]
pub struct C;

const KEY: Symbol = symbol_short!("bal");

#[contractimpl]
impl C {
    pub fn deposit(env: Env, amount: i128) {
        env.events().publish((symbol_short!("deposit"),), amount);
        env.storage().persistent().set(&KEY, &amount);
    }
}
"#;

    const SAFE: &str = r#"
use soroban_sdk::{contract, contractimpl, symbol_short, Env, Symbol};

#[contract]
pub struct C;

const KEY: Symbol = symbol_short!("bal");

#[contractimpl]
impl C {
    pub fn deposit(env: Env, amount: i128) {
        env.storage().persistent().set(&KEY, &amount);
        env.events().publish((symbol_short!("deposit"),), amount);
    }
}
"#;

    #[test]
    fn flags_publish_before_set() -> Result<(), syn::Error> {
        let file = parse_file(VULNERABLE)?;
        let hits = EventBeforeStorageCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        Ok(())
    }

    #[test]
    fn passes_publish_after_set() -> Result<(), syn::Error> {
        let file = parse_file(SAFE)?;
        let hits = EventBeforeStorageCheck.run(&file, "");
        assert!(hits.is_empty(), "got: {hits:?}");
        Ok(())
    }

    #[test]
    fn ignores_publish_only_no_set() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contract, contractimpl, symbol_short, Env};
#[contract] pub struct C;
#[contractimpl]
impl C {
    pub fn notify(env: Env, v: i128) {
        env.events().publish((symbol_short!("x"),), v);
    }
}
"#,
        )?;
        let hits = EventBeforeStorageCheck.run(&file, "");
        assert!(hits.is_empty(), "got: {hits:?}");
        Ok(())
    }

    #[test]
    fn ignores_set_only_no_publish() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contract, contractimpl, symbol_short, Env, Symbol};
#[contract] pub struct C;
const K: Symbol = symbol_short!("k");
#[contractimpl]
impl C {
    pub fn store(env: Env, v: i128) {
        env.storage().persistent().set(&K, &v);
    }
}
"#,
        )?;
        let hits = EventBeforeStorageCheck.run(&file, "");
        assert!(hits.is_empty(), "got: {hits:?}");
        Ok(())
    }

    #[test]
    fn ignores_non_contractimpl() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{symbol_short, Env, Symbol};
pub struct C;
const K: Symbol = symbol_short!("k");
impl C {
    pub fn deposit(env: Env, amount: i128) {
        env.events().publish((symbol_short!("deposit"),), amount);
        env.storage().persistent().set(&K, &amount);
    }
}
"#,
        )?;
        let hits = EventBeforeStorageCheck.run(&file, "");
        assert!(hits.is_empty(), "got: {hits:?}");
        Ok(())
    }
}
