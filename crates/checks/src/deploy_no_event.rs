//! Detects `env.deployer().deploy()` calls that don't emit an event.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{ExprMethodCall, File};

const CHECK_NAME: &str = "deploy-no-event";

/// Flags `env.deployer().deploy(...)` calls where no `env.events().publish(...)` 
/// is emitted in the same function body. This makes the deployment invisible to
/// off-chain indexers.
pub struct DeployNoEventCheck;

impl Check for DeployNoEventCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            // Scan the function body for deploy and event calls
            let mut checker = DeployEventChecker { 
                has_deploy: false,
                deploy_line: None,
                has_event: false,
            };
            checker.visit_block(&method.block);
            
            // If deploy exists but no event emitted, report it
            if checker.has_deploy && !checker.has_event {
                let line = checker.deploy_line.unwrap_or_else(|| method.sig.span().start().line);
                let fn_name = method.sig.ident.to_string();
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Low,
                    file_path: String::new(),
                    line,
                    function_name: fn_name.clone(),
                    description: format!(
                        "Function `{}` calls `env.deployer().deploy(...)` but does not emit \
                         an event. Sub-contract deployments are invisible to off-chain indexers \
                         without event emission.",
                        fn_name
                    ),
                });
            }
        }
        out
    }
}

struct DeployEventChecker {
    has_deploy: bool,
    deploy_line: Option<usize>,
    has_event: bool,
}

impl Visit<'_> for DeployEventChecker {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        // Check for deploy() call
        if i.method == "deploy" && receiver_contains_deployer(&i.receiver) {
            self.has_deploy = true;
            if self.deploy_line.is_none() {
                self.deploy_line = Some(i.span().start().line);
            }
        }
        // Check for events().publish() call
        if i.method == "publish" && receiver_contains_events(&i.receiver) {
            self.has_event = true;
        }
        syn::visit::visit_expr_method_call(self, i);
    }
}

fn receiver_contains_deployer(expr: &syn::Expr) -> bool {
    match expr {
        syn::Expr::MethodCall(m) => {
            if m.method == "deployer" {
                return true;
            }
            receiver_contains_deployer(&m.receiver)
        }
        _ => false,
    }
}

fn receiver_contains_events(expr: &syn::Expr) -> bool {
    match expr {
        syn::Expr::MethodCall(m) => {
            if m.method == "events" {
                return true;
            }
            receiver_contains_events(&m.receiver)
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
        DeployNoEventCheck.run(&file, src)
    }

    #[test]
    fn flags_deploy_without_event() {
        let hits = run(
            r#"
use soroban_sdk::{contract, contractimpl, Bytes, Env};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn deploy_sub(env: Env, wasm_hash: Bytes) {
        let addr = env.deployer().deploy(wasm_hash, ());
    }
}
"#,
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Low);
    }

    #[test]
    fn ignores_deploy_with_event() {
        let hits = run(
            r#"
use soroban_sdk::{contract, contractimpl, Bytes, Env, Symbol};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn deploy_sub(env: Env, wasm_hash: Bytes) {
        let addr = env.deployer().deploy(wasm_hash, ());
        env.events().publish((Symbol::new(&env, "deployed"),), addr);
    }
}
"#,
        );
        assert_eq!(hits.len(), 0);
    }
}
