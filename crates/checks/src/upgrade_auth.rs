//! `upgrade` entrypoints that call `update_current_contract_wasm` without prior auth.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{ExprMethodCall, File, Stmt, Visibility};

const CHECK_NAME: &str = "upgrade-missing-auth";

pub struct UpgradeAuthCheck;

impl Check for UpgradeAuthCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            if !matches!(method.vis, Visibility::Public(_)) {
                continue;
            }
            if method.sig.ident != "upgrade" {
                continue;
            }
            // Walk statements in order; track whether auth appeared before wasm update.
            let mut auth_seen = false;
            let mut wasm_update_line: Option<usize> = None;
            for stmt in &method.block.stmts {
                let mut sv = StmtVisitor::default();
                sv.visit_stmt(stmt);
                if sv.has_auth {
                    auth_seen = true;
                }
                if sv.has_wasm_update && !auth_seen && wasm_update_line.is_none() {
                    wasm_update_line = sv.wasm_update_line;
                }
            }
            if let Some(line) = wasm_update_line {
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::High,
                    file_path: String::new(),
                    line,
                    function_name: "upgrade".to_string(),
                    description:
                        "Function `upgrade` calls `update_current_contract_wasm` without a \
                         preceding `require_auth()` or `require_auth_for_args()`. Any account \
                         on Stellar can replace the contract WASM."
                            .to_string(),
                });
            }
        }
        out
    }
}

#[derive(Default)]
struct StmtVisitor {
    has_auth: bool,
    has_wasm_update: bool,
    wasm_update_line: Option<usize>,
}

impl<'ast> Visit<'ast> for StmtVisitor {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        let m = i.method.to_string();
        if matches!(m.as_str(), "require_auth" | "require_auth_for_args") {
            self.has_auth = true;
        }
        if m == "update_current_contract_wasm" {
            self.has_wasm_update = true;
            self.wasm_update_line = Some(i.span().start().line);
        }
        visit::visit_expr_method_call(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    #[test]
    fn flags_upgrade_without_auth() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, BytesN, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn upgrade(env: Env, new_wasm: BytesN<32>) {
        env.deployer().update_current_contract_wasm(new_wasm);
    }
}
"#,
        )?;
        let hits = UpgradeAuthCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        assert_eq!(hits[0].function_name, "upgrade");
        Ok(())
    }

    #[test]
    fn passes_upgrade_with_require_auth_before() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, BytesN, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn upgrade(env: Env, new_wasm: BytesN<32>) {
        env.require_auth();
        env.deployer().update_current_contract_wasm(new_wasm);
    }
}
"#,
        )?;
        let hits = UpgradeAuthCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_upgrade_without_wasm_call() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn upgrade(env: Env) {
        let _ = env;
    }
}
"#,
        )?;
        let hits = UpgradeAuthCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
