//! Detects `env.deployer().deploy()` calls where the return value is not stored.
//!
//! `env.deployer().deploy(...)` returns the address of the newly deployed contract.
//! If the return value is not stored in persistent or instance storage, the contract
//! loses track of the sub-contract address after the transaction.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File, Local, Stmt};

const CHECK_NAME: &str = "deploy-address-lost";

/// Flags `env.deployer().deploy(...)` calls whose return value is not stored.
pub struct DeployAddressLostCheck;

impl Check for DeployAddressLostCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut scan = DeployScan {
                fn_name,
                out: &mut out,
            };
            scan.visit_block(&method.block);
        }
        out
    }
}

struct DeployScan<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl<'ast> Visit<'ast> for DeployScan<'_> {
    fn visit_stmt(&mut self, i: &'ast Stmt) {
        // Check for standalone deploy call (not assigned)
        if let Stmt::Expr(Expr::MethodCall(m), _) = i {
            if is_deploy_call(m) {
                let line = m.span().start().line;
                self.out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Low,
                    file_path: String::new(),
                    line,
                    function_name: self.fn_name.clone(),
                    description: format!(
                        "Method `{}` calls `env.deployer().deploy()` but does not store the \
                         returned contract address. The sub-contract address will be lost after \
                         the transaction.",
                        self.fn_name
                    ),
                });
            }
        }
        visit::visit_stmt(self, i);
    }
}

fn is_deploy_call(m: &ExprMethodCall) -> bool {
    if m.method != "deploy" {
        return false;
    }
    // Check if receiver is deployer() call
    if let Expr::MethodCall(inner) = &*m.receiver {
        if inner.method == "deployer" {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_deploy_without_storage() {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn deploy_sub(env: Env) {
        env.deployer().deploy(wasm_ref, salt, init_fn, init_args);
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let check = DeployAddressLostCheck;
        let findings = check.run(&file, code);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check_name, CHECK_NAME);
        assert_eq!(findings[0].severity, Severity::Low);
    }

    #[test]
    fn allows_deploy_with_storage() {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn deploy_sub(env: Env) {
        let addr = env.deployer().deploy(wasm_ref, salt, init_fn, init_args);
        env.storage().instance().set(&Symbol::new(&env, "sub"), &addr);
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let check = DeployAddressLostCheck;
        let findings = check.run(&file, code);
        assert!(findings.is_empty());
    }
}
