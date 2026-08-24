//! Detects `env.deployer().deploy(...)` called without a preceding `require_auth` in the
//! same `#[contractimpl]` function, allowing any caller to deploy sub-contracts.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "deployer-no-auth";

pub struct DeployerNoAuthCheck;

impl Check for DeployerNoAuthCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut scan = DeployerScan::default();
            scan.visit_block(&method.block);
            if scan.deploy_found && !scan.require_auth_found {
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::High,
                    file_path: String::new(),
                    line: scan.deploy_line.unwrap_or_else(|| method.sig.ident.span().start().line),
                    function_name: fn_name.clone(),
                    description: format!(
                        "`{}` calls `env.deployer().deploy(...)` without a preceding \
                         `require_auth()`. Any caller can deploy new contract instances under \
                         this contract's authority.",
                        fn_name
                    ),
                });
            }
        }
        out
    }
}

fn is_require_auth(m: &ExprMethodCall) -> bool {
    (m.method == "require_auth" || m.method == "require_auth_for_args")
        && matches!(&*m.receiver, Expr::Path(p) if p.path.is_ident("env"))
}

fn is_deployer_deploy(m: &ExprMethodCall) -> bool {
    if m.method != "deploy" && m.method != "deploy_v2" {
        return false;
    }
    // receiver must be `env.deployer()` or a chain containing it
    receiver_contains_deployer(&m.receiver)
}

fn receiver_contains_deployer(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => m.method == "deployer" || receiver_contains_deployer(&m.receiver),
        _ => false,
    }
}

#[derive(Default)]
struct DeployerScan {
    require_auth_found: bool,
    deploy_found: bool,
    deploy_line: Option<usize>,
}

impl<'ast> Visit<'ast> for DeployerScan {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if is_require_auth(i) {
            self.require_auth_found = true;
        }
        if is_deployer_deploy(i) && !self.deploy_found {
            self.deploy_found = true;
            self.deploy_line = Some(i.span().start().line);
        }
        visit::visit_expr_method_call(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        let file = parse_file(src).unwrap();
        DeployerNoAuthCheck.run(&file, src)
    }

    #[test]
    fn flags_deploy_without_auth() {
        let hits = run(r#"
#[contractimpl]
impl C {
    pub fn spawn(env: Env, wasm_hash: BytesN<32>, salt: BytesN<32>) {
        env.deployer().deploy(wasm_hash, salt);
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        assert_eq!(hits[0].check_name, CHECK_NAME);
    }

    #[test]
    fn passes_with_require_auth() {
        let hits = run(r#"
#[contractimpl]
impl C {
    pub fn spawn(env: Env, wasm_hash: BytesN<32>, salt: BytesN<32>) {
        env.require_auth();
        env.deployer().deploy(wasm_hash, salt);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn passes_with_require_auth_for_args() {
        let hits = run(r#"
#[contractimpl]
impl C {
    pub fn spawn(env: Env, admin: Address, wasm_hash: BytesN<32>, salt: BytesN<32>) {
        env.require_auth_for_args((admin,));
        env.deployer().deploy(wasm_hash, salt);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn no_flag_without_deploy() {
        let hits = run(r#"
#[contractimpl]
impl C {
    pub fn noop(env: Env) {}
}
"#);
        assert!(hits.is_empty());
    }
}
