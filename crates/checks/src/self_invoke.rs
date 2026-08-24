//! Detects inefficient `env.invoke_contract()` calls to the same contract.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "self-invoke";

/// Flags `env.invoke_contract(addr, ...)` where `addr` is derived from
/// `env.current_contract_address()` or `env.current_contract_id()`.
/// Calling the contract itself via invoke_contract instead of directly
/// wastes compute and may cause unintended reentrancy behavior.
pub struct SelfInvokeCheck;

impl Check for SelfInvokeCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut checker = SelfInvokeChecker {
                fn_name,
                findings: &mut out,
            };
            checker.visit_block(&method.block);
        }
        out
    }
}

struct SelfInvokeChecker<'a> {
    fn_name: String,
    findings: &'a mut Vec<Finding>,
}

impl<'a> Visit<'_> for SelfInvokeChecker<'a> {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        // Check for invoke_contract calls
        if i.method == "invoke_contract" {
            // Get the first argument (the address)
            if let Some(arg) = i.args.first() {
                if is_current_contract_addr(arg) {
                    self.findings.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::Low,
                        file_path: String::new(),
                        line: i.span().start().line,
                        function_name: self.fn_name.clone(),
                        description: "Function calls `env.invoke_contract()` with the current \
                                      contract's address. This wastes compute and may cause \
                                      unintended reentrancy behavior. Call the function \
                                      directly instead."
                            .to_string(),
                    });
                }
            }
        }
        syn::visit::visit_expr_method_call(self, i);
    }
}

fn is_current_contract_addr(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if matches!(m.method.to_string().as_str(), "current_contract_address" | "current_contract_id") {
                // Check that the receiver is env
                if let Expr::Path(p) = &*m.receiver {
                    return p.path.is_ident("env");
                }
            }
            false
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        let file = parse_file(src).unwrap();
        SelfInvokeCheck.run(&file, src)
    }

    #[test]
    fn flags_invoke_contract_with_current_address() {
        let hits = run(
            r#"
use soroban_sdk::{contract, contractimpl, Env, Symbol};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn inefficient_call(env: Env) {
        env.invoke_contract::<()>(
            &env.current_contract_address(),
            &Symbol::new(&env, "internal_fn"),
            &(),
        );
    }
}
"#,
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Low);
    }

    #[test]
    fn ignores_invoke_contract_with_other_address() {
        let hits = run(
            r#"
use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn call_other(env: Env, other_contract: Address) {
        env.invoke_contract::<()>(
            &other_contract,
            &Symbol::new(&env, "fn_name"),
            &(),
        );
    }
}
"#,
        );
        assert_eq!(hits.len(), 0);
    }
}
