//! Detects token transfers where the recipient is the contract's own address.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, ExprBinary, ExprMethodCall, File, Macro};

const CHECK_NAME: &str = "transfer-to-self";

/// Flags `transfer(from, to, amount)` calls where `to` is `env.current_contract_address()`
/// or where no `!=` check between `to` and `current_contract_address()` precedes the call.
pub struct TransferToSelfCheck;

impl Check for TransferToSelfCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut scan = TransferScan {
                fn_name: fn_name.clone(),
                has_self_check: false,
                out: &mut out,
            };
            scan.visit_block(&method.block);
        }
        out
    }
}

struct TransferScan<'a> {
    fn_name: String,
    has_self_check: bool,
    out: &'a mut Vec<Finding>,
}

impl<'a> Visit<'_> for TransferScan<'a> {
    fn visit_macro(&mut self, i: &Macro) {
        if let Ok(expr) = i.parse_body::<Expr>() {
            self.visit_expr(&expr);
        }
        visit::visit_macro(self, i);
    }

    fn visit_expr_binary(&mut self, i: &ExprBinary) {
        // Detect `to != env.current_contract_address()` or similar guards
        if matches!(i.op, BinOp::Ne(_)) {
            let left = expr_to_string(&i.left);
            let right = expr_to_string(&i.right);
            let combined = format!("{left} {right}");
            if combined.contains("current_contract_address") {
                self.has_self_check = true;
            }
        }
        visit::visit_expr_binary(self, i);
    }

    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if i.method == "transfer" && i.args.len() == 3 {
            let to_arg = &i.args[1];
            if is_current_contract_address(to_arg) {
                // Direct transfer to self
                self.out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Medium,
                    file_path: String::new(),
                    line: i.span().start().line,
                    function_name: self.fn_name.clone(),
                    description: format!(
                        "Function `{}` calls `transfer` with `env.current_contract_address()` \
                         as the recipient. Tokens sent to the contract itself may be permanently \
                         locked.",
                        self.fn_name
                    ),
                });
            } else if !self.has_self_check {
                // Recipient not checked against contract address
                self.out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Medium,
                    file_path: String::new(),
                    line: i.span().start().line,
                    function_name: self.fn_name.clone(),
                    description: format!(
                        "Function `{}` calls `transfer` without verifying the recipient is not \
                         `env.current_contract_address()`. Tokens may be permanently locked in \
                         the contract.",
                        self.fn_name
                    ),
                });
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

fn is_current_contract_address(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "current_contract_address" {
                return true;
            }
            false
        }
        Expr::Reference(r) => is_current_contract_address(&r.expr),
        _ => false,
    }
}

fn expr_to_string(expr: &Expr) -> String {
    match expr {
        Expr::Path(p) => p
            .path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect::<Vec<_>>()
            .join("::"),
        Expr::MethodCall(m) => {
            format!("{}.{}()", expr_to_string(&m.receiver), m.method)
        }
        Expr::Reference(r) => expr_to_string(&r.expr),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_transfer_to_current_contract() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Env, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn lock_tokens(env: Env, from: Address, amount: i128) {
        token_client.transfer(&from, &env.current_contract_address(), &amount);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = TransferToSelfCheck.run(&file, src);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        Ok(())
    }

    #[test]
    fn flags_transfer_without_self_check() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Env, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn send(env: Env, to: Address, amount: i128) {
        token_client.transfer(&env.current_contract_address(), &to, &amount);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = TransferToSelfCheck.run(&file, src);
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    fn passes_with_self_check() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Env, Address};
pub struct C;
#[contractimpl]
impl C {
    pub fn send(env: Env, to: Address, amount: i128) {
        assert!(to != env.current_contract_address());
        token_client.transfer(&env.current_contract_address(), &to, &amount);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = TransferToSelfCheck.run(&file, src);
        assert!(hits.is_empty());
        Ok(())
    }
}
