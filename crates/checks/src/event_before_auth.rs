//! Event published before require_auth check (unauthenticated event).

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{Expr, ExprMethodCall, File, Stmt};

const CHECK_NAME: &str = "event-before-auth";

/// Flags `#[contractimpl]` functions where `env.events().publish(...)` appears
/// before `env.require_auth()` or `env.require_auth_for_args(...)` in statement order.
pub struct EventBeforeAuthCheck;

impl Check for EventBeforeAuthCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let stmts = &method.block.stmts;

            let publish_indices = stmt_indices_matching(stmts, is_events_publish);
            let auth_indices = stmt_indices_matching(stmts, is_require_auth);

            // Flag if any publish comes before any auth check
            for &pi in &publish_indices {
                if auth_indices.iter().any(|&ai| pi < ai) {
                    let line = stmt_line(&stmts[pi]);
                    out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::Low,
                        file_path: String::new(),
                        line,
                        function_name: fn_name.clone(),
                        description: format!(
                            "`{}` publishes an event via `env.events().publish(...)` before \
                             calling `env.require_auth()` or `env.require_auth_for_args(...)`. \
                             Publishing events before authorization leaks information about \
                             failed or unauthorized attempts. Move all event emissions after \
                             authorization checks.",
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

fn is_require_auth(m: &ExprMethodCall) -> bool {
    (m.method == "require_auth" || m.method == "require_auth_for_args")
        && matches!(&*m.receiver, Expr::Path(p) if p.path.is_ident("env"))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    #[test]
    fn flags_publish_before_require_auth() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contract, contractimpl, Address, Env, symbol_short};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn transfer(env: Env, to: Address, amount: i128) {
        env.events().publish((symbol_short!("transfer"),), (to, amount));
        env.require_auth();
        env.storage().instance().set(&"balance", &amount);
    }
}
"#,
        )?;
        let hits = EventBeforeAuthCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Low);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        Ok(())
    }

    #[test]
    fn passes_publish_after_require_auth() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contract, contractimpl, Address, Env, symbol_short};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn transfer(env: Env, to: Address, amount: i128) {
        env.require_auth();
        env.events().publish((symbol_short!("transfer"),), (to, amount));
        env.storage().instance().set(&"balance", &amount);
    }
}
"#,
        )?;
        let hits = EventBeforeAuthCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn flags_publish_before_require_auth_for_args() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contract, contractimpl, Address, Env, symbol_short};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn transfer(env: Env, to: Address, amount: i128) {
        env.events().publish((symbol_short!("transfer"),), (to, amount));
        env.require_auth_for_args((&to,).into_val(&env));
    }
}
"#,
        )?;
        let hits = EventBeforeAuthCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    fn ignores_publish_only_no_auth() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contract, contractimpl, Env, symbol_short};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn notify(env: Env, amount: i128) {
        env.events().publish((symbol_short!("notify"),), amount);
    }
}
"#,
        )?;
        let hits = EventBeforeAuthCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_auth_only_no_publish() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn protected(env: Env) {
        env.require_auth();
        env.storage().instance().set(&"key", &42);
    }
}
"#,
        )?;
        let hits = EventBeforeAuthCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
