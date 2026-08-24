//! Detects ledger timestamp used as expiry without minimum duration guard.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "timestamp-expiry-no-min";

pub struct TimestampExpiryNoMinCheck;

impl Check for TimestampExpiryNoMinCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = TimestampVisitor {
                timestamp_stored: false,
                storage_set_line: 0,
            };
            v.visit_block(&method.block);
            if v.timestamp_stored {
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Medium,
                    file_path: String::new(),
                    line: v.storage_set_line,
                    function_name: fn_name,
                    description: "Function stores `env.ledger().timestamp()` as an expiry without enforcing a minimum duration (e.g., `timestamp + MIN_DURATION`) or comparison guard. Callers can set an expiry in the past or an arbitrarily short window, bypassing time-lock protections.".to_string(),
                });
            }
        }
        out
    }
}

fn is_timestamp_call(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "timestamp" {
                if let Expr::MethodCall(ledger_call) = &*m.receiver {
                    if ledger_call.method == "ledger" {
                        if let Expr::Path(p) = &*ledger_call.receiver {
                            return p.path.is_ident("env");
                        }
                    }
                }
            }
            false
        }
        _ => false,
    }
}

fn expr_contains_timestamp(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => is_timestamp_call(expr) || expr_contains_timestamp(&m.receiver),
        Expr::Binary(b) => expr_contains_timestamp(&b.left) || expr_contains_timestamp(&b.right),
        Expr::Paren(p) => expr_contains_timestamp(&p.expr),
        Expr::Reference(r) => expr_contains_timestamp(&r.expr),
        _ => false,
    }
}

fn expr_contains_timestamp_addition(expr: &Expr) -> bool {
    match expr {
        Expr::Binary(b) => {
            if matches!(b.op, BinOp::Add(_)) {
                // Check if either side is timestamp
                if expr_contains_timestamp(&b.left) || expr_contains_timestamp(&b.right) {
                    return true;
                }
            }
            expr_contains_timestamp_addition(&b.left) || expr_contains_timestamp_addition(&b.right)
        }
        Expr::Paren(p) => expr_contains_timestamp_addition(&p.expr),
        Expr::Reference(r) => expr_contains_timestamp_addition(&r.expr),
        _ => false,
    }
}

fn is_storage_set_call(m: &ExprMethodCall) -> bool {
    m.method == "set" && receiver_chain_contains_storage(&m.receiver)
}

fn receiver_chain_contains_storage(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            m.method == "storage" || receiver_chain_contains_storage(&m.receiver)
        }
        Expr::Field(f) => receiver_chain_contains_storage(&f.base),
        _ => false,
    }
}

struct TimestampVisitor {
    timestamp_stored: bool,
    storage_set_line: usize,
}

impl Visit<'_> for TimestampVisitor {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if is_storage_set_call(i) {
            // Check if any argument contains timestamp
            for arg in &i.args {
                if expr_contains_timestamp(arg) && !expr_contains_timestamp_addition(arg) {
                    self.timestamp_stored = true;
                    self.storage_set_line = i.method.span().start().line;
                }
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_timestamp_stored_without_guard() {
        let code = r#"
#[contractimpl]
impl C {
    pub fn set_expiry(env: Env) {
        env.storage().instance().set(&"expiry", &env.ledger().timestamp());
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let findings = TimestampExpiryNoMinCheck.run(&file, code);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn passes_timestamp_with_addition() {
        let code = r#"
#[contractimpl]
impl C {
    pub fn set_expiry(env: Env) {
        let expiry = env.ledger().timestamp() + 3600;
        env.storage().instance().set(&"expiry", &expiry);
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let findings = TimestampExpiryNoMinCheck.run(&file, code);
        assert!(findings.is_empty());
    }

    #[test]
    fn passes_timestamp_with_comparison() {
        let code = r#"
#[contractimpl]
impl C {
    pub fn set_expiry(env: Env, duration: u64) {
        if duration >= 3600 {
            let expiry = env.ledger().timestamp();
            env.storage().instance().set(&"expiry", &expiry);
        }
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let findings = TimestampExpiryNoMinCheck.run(&file, code);
        assert!(findings.is_empty());
    }

    #[test]
    fn passes_no_timestamp_storage() {
        let code = r#"
#[contractimpl]
impl C {
    pub fn set_value(env: Env, value: u64) {
        env.storage().instance().set(&"value", &value);
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let findings = TimestampExpiryNoMinCheck.run(&file, code);
        assert!(findings.is_empty());
    }
}
