//! Expiry/deadline parameter stored without validating against current timestamp.
//!
//! A function that accepts `expiry`, `deadline`, `expires_at`, or `valid_until`
//! and writes it to storage without checking `expiry > env.ledger().timestamp()`
//! allows callers to set already-expired deadlines, bypassing time-lock logic.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, ExprBinary, ExprMethodCall, File, FnArg, Pat, Stmt};

const CHECK_NAME: &str = "expired-deadline";

const DEADLINE_PARAM_NAMES: &[&str] = &["expiry", "deadline", "expires_at", "valid_until"];

fn is_deadline_param(name: &str) -> bool {
    DEADLINE_PARAM_NAMES.contains(&name)
}

fn collect_deadline_params(inputs: &syn::punctuated::Punctuated<FnArg, syn::token::Comma>) -> Vec<String> {
    let mut params = Vec::new();
    for input in inputs {
        if let FnArg::Typed(pt) = input {
            if let Pat::Ident(pi) = &*pt.pat {
                let name = pi.ident.to_string();
                if is_deadline_param(&name) {
                    params.push(name);
                }
            }
        }
    }
    params
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

fn receiver_chain_contains_ledger(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "ledger" {
                return true;
            }
            receiver_chain_contains_ledger(&m.receiver)
        }
        Expr::Field(f) => receiver_chain_contains_ledger(&f.base),
        _ => false,
    }
}

fn expr_is_timestamp_call(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            m.method == "timestamp" && receiver_chain_contains_ledger(&m.receiver)
        }
        _ => false,
    }
}

fn expr_references_param(expr: &Expr, params: &[String]) -> bool {
    match expr {
        Expr::Path(p) => {
            if let Some(seg) = p.path.segments.last() {
                return params.contains(&seg.ident.to_string());
            }
            false
        }
        Expr::Reference(r) => expr_references_param(&r.expr, params),
        _ => false,
    }
}

/// Check if a binary expression is a timestamp comparison involving a deadline param.
/// Accepts: `deadline > timestamp()`, `deadline >= timestamp()`,
///          `timestamp() < deadline`, `timestamp() <= deadline`
fn is_timestamp_comparison(e: &ExprBinary, params: &[String]) -> bool {
    let is_gt_ge = matches!(e.op, BinOp::Gt(_) | BinOp::Ge(_));
    let is_lt_le = matches!(e.op, BinOp::Lt(_) | BinOp::Le(_));

    if is_gt_ge {
        // deadline > timestamp() or deadline >= timestamp()
        expr_references_param(&e.left, params) && expr_is_timestamp_call(&e.right)
    } else if is_lt_le {
        // timestamp() < deadline or timestamp() <= deadline
        expr_is_timestamp_call(&e.left) && expr_references_param(&e.right, params)
    } else {
        false
    }
}

struct DeadlineVisitor<'a> {
    fn_name: String,
    deadline_params: Vec<String>,
    timestamp_checked: bool,
    out: &'a mut Vec<Finding>,
}

impl<'a> DeadlineVisitor<'a> {
    fn check_macro_for_timestamp(&mut self, mac: &syn::Macro) {
        let mac_name = mac.path.segments.last().map(|s| s.ident.to_string()).unwrap_or_default();
        if matches!(mac_name.as_str(), "assert" | "require") {
            if let Ok(expr) = mac.parse_body::<Expr>() {
                let mut inner = TimestampCompFinder {
                    params: &self.deadline_params,
                    found: false,
                };
                inner.visit_expr(&expr);
                if inner.found {
                    self.timestamp_checked = true;
                }
            }
        }
    }
}

impl<'ast> Visit<'ast> for DeadlineVisitor<'ast> {
    fn visit_expr_binary(&mut self, i: &'ast ExprBinary) {
        if is_timestamp_comparison(i, &self.deadline_params) {
            self.timestamp_checked = true;
        }
        visit::visit_expr_binary(self, i);
    }

    fn visit_expr_macro(&mut self, i: &'ast syn::ExprMacro) {
        self.check_macro_for_timestamp(&i.mac);
        visit::visit_expr_macro(self, i);
    }

    fn visit_stmt_macro(&mut self, i: &'ast syn::StmtMacro) {
        self.check_macro_for_timestamp(&i.mac);
        visit::visit_stmt_macro(self, i);
    }

    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if i.method == "set" && receiver_chain_contains_storage(&i.receiver) {
            if !self.timestamp_checked {
                // Check if any deadline param is being stored
                for arg in &i.args {
                    if expr_references_param(arg, &self.deadline_params) {
                        self.out.push(Finding {
                            check_name: CHECK_NAME.to_string(),
                            severity: Severity::Medium,
                            file_path: String::new(),
                            line: i.span().start().line,
                            function_name: self.fn_name.clone(),
                            description: format!(
                                "Method `{}` stores a deadline/expiry parameter to storage without \
                                 first checking it against `env.ledger().timestamp()`. Callers can \
                                 set already-expired deadlines, bypassing time-lock logic. \
                                 Add a guard: `require!(expiry > env.ledger().timestamp())`.",
                                self.fn_name
                            ),
                        });
                        break;
                    }
                }
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

struct TimestampCompFinder<'a> {
    params: &'a [String],
    found: bool,
}

impl<'ast> Visit<'ast> for TimestampCompFinder<'ast> {
    fn visit_expr_binary(&mut self, i: &'ast ExprBinary) {
        if is_timestamp_comparison(i, self.params) {
            self.found = true;
        }
        visit::visit_expr_binary(self, i);
    }
}

pub struct ExpiredDeadlineCheck;

impl Check for ExpiredDeadlineCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let deadline_params = collect_deadline_params(&method.sig.inputs);
            if deadline_params.is_empty() {
                continue;
            }
            let fn_name = method.sig.ident.to_string();
            let mut v = DeadlineVisitor {
                fn_name,
                deadline_params,
                timestamp_checked: false,
                out: &mut out,
            };
            v.visit_block(&method.block);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    #[test]
    fn flags_expiry_stored_without_timestamp_check() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, symbol_short, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn set_expiry(env: Env, expiry: u64) {
        env.storage().persistent().set(&symbol_short!("exp"), &expiry);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = ExpiredDeadlineCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        Ok(())
    }

    #[test]
    fn flags_deadline_stored_without_timestamp_check() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, symbol_short, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn lock(env: Env, deadline: u64) {
        env.storage().persistent().set(&symbol_short!("dl"), &deadline);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = ExpiredDeadlineCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    fn no_finding_when_timestamp_checked() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, symbol_short, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn set_expiry(env: Env, expiry: u64) {
        assert!(expiry > env.ledger().timestamp());
        env.storage().persistent().set(&symbol_short!("exp"), &expiry);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = ExpiredDeadlineCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn no_finding_when_timestamp_checked_ge() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, symbol_short, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn set_expiry(env: Env, expiry: u64) {
        assert!(expiry >= env.ledger().timestamp());
        env.storage().persistent().set(&symbol_short!("exp"), &expiry);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = ExpiredDeadlineCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn no_finding_for_non_deadline_param() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, symbol_short, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn store(env: Env, amount: u64) {
        env.storage().persistent().set(&symbol_short!("amt"), &amount);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = ExpiredDeadlineCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
