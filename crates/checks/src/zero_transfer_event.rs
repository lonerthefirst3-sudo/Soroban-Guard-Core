//! Detects `transfer` functions that emit events without first checking `amount > 0`.
//!
//! A zero-amount transfer serves no financial purpose but still emits an event,
//! spamming the event log and potentially confusing off-chain indexers.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, ExprBinary, ExprMethodCall, File, FnArg, Pat, PatType};

const CHECK_NAME: &str = "zero-transfer-event";

pub struct ZeroTransferEventCheck;

impl Check for ZeroTransferEventCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            if fn_name != "transfer" {
                continue;
            }

            // Must have an `amount` parameter.
            let has_amount = method.sig.inputs.iter().any(|arg| {
                if let FnArg::Typed(PatType { pat, .. }) = arg {
                    if let Pat::Ident(id) = &**pat {
                        return id.ident == "amount";
                    }
                }
                false
            });
            if !has_amount {
                continue;
            }

            let mut scan = TransferScan::default();
            scan.visit_block(&method.block);

            // Flag if events are emitted but amount is never checked against 0.
            if scan.emits_event && !scan.checks_amount_zero {
                let line = method.sig.fn_token.span().start().line;
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Low,
                    file_path: String::new(),
                    line,
                    function_name: fn_name.clone(),
                    description: format!(
                        "Function `{fn_name}` emits an event but does not check `amount > 0` \
                         before doing so. Zero-amount transfers spam the event log with \
                         economically meaningless entries."
                    ),
                });
            }
        }
        out
    }
}

#[derive(Default)]
struct TransferScan {
    emits_event: bool,
    checks_amount_zero: bool,
}

impl<'ast> Visit<'ast> for TransferScan {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        // Detect event emission: env.events().publish(...) or similar.
        let method = i.method.to_string();
        if matches!(method.as_str(), "publish" | "emit") {
            self.emits_event = true;
        }
        // Also detect chained: .events().publish(...)
        if method == "publish" || method == "emit" {
            self.emits_event = true;
        }
        visit::visit_expr_method_call(self, i);
    }

    fn visit_expr_binary(&mut self, i: &'ast ExprBinary) {
        let left_amount = expr_is_ident(&i.left, "amount");
        let right_zero = expr_is_zero(&i.right);
        let left_zero = expr_is_zero(&i.left);
        let right_amount = expr_is_ident(&i.right, "amount");

        if (left_amount && right_zero) || (left_zero && right_amount) {
            match i.op {
                BinOp::Gt(_)
                | BinOp::Ge(_)
                | BinOp::Lt(_)
                | BinOp::Le(_)
                | BinOp::Ne(_)
                | BinOp::Eq(_) => {
                    self.checks_amount_zero = true;
                }
                _ => {}
            }
        }
        visit::visit_expr_binary(self, i);
    }
}

fn expr_is_ident(expr: &Expr, name: &str) -> bool {
    if let Expr::Path(p) = expr {
        p.path.is_ident(name)
    } else {
        false
    }
}

fn expr_is_zero(expr: &Expr) -> bool {
    if let Expr::Lit(l) = expr {
        if let syn::Lit::Int(i) = &l.lit {
            return i.base10_parse::<i64>().map(|n| n == 0).unwrap_or(false);
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_transfer_with_event_no_zero_check() {
        let code = r#"
#[contractimpl]
impl Token {
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        env.events().publish((symbol_short!("transfer"),), (from, to, amount));
        env.storage().instance().set(&to, &amount);
    }
}
"#;
        let file = parse_file(code).unwrap();
        let findings = ZeroTransferEventCheck.run(&file, code);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check_name, CHECK_NAME);
    }

    #[test]
    fn passes_when_amount_checked_before_event() {
        let code = r#"
#[contractimpl]
impl Token {
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        if amount <= 0 { panic!("zero"); }
        env.events().publish((symbol_short!("transfer"),), (from, to, amount));
    }
}
"#;
        let file = parse_file(code).unwrap();
        let findings = ZeroTransferEventCheck.run(&file, code);
        assert!(findings.is_empty());
    }

    #[test]
    fn passes_when_no_event_emitted() {
        let code = r#"
#[contractimpl]
impl Token {
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        env.storage().instance().set(&to, &amount);
    }
}
"#;
        let file = parse_file(code).unwrap();
        let findings = ZeroTransferEventCheck.run(&file, code);
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_non_transfer_functions() {
        let code = r#"
#[contractimpl]
impl Token {
    pub fn mint(env: Env, to: Address, amount: i128) {
        env.events().publish((symbol_short!("mint"),), (to, amount));
    }
}
"#;
        let file = parse_file(code).unwrap();
        let findings = ZeroTransferEventCheck.run(&file, code);
        assert!(findings.is_empty());
    }
}
