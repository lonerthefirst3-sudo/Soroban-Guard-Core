//! Require_auth called with admin address from untrusted storage key.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File, Ident, Stmt};

const CHECK_NAME: &str = "auth-untrusted-storage";

/// Flags methods where `require_auth` is called with a value from storage.
pub struct AuthUntrustedStorageCheck;

impl Check for AuthUntrustedStorageCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut scan = StorageAuthScan::default();
            scan.visit_block(&method.block);
            for line in scan.storage_auth_lines {
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::High,
                    file_path: String::new(),
                    line,
                    function_name: fn_name.clone(),
                    description: format!(
                        "Method `{fn_name}` calls `require_auth` with a value from storage. \
                         If the storage key is user-controlled, this allows arbitrary caller \
                         impersonation."
                    ),
                });
            }
        }
        out
    }
}

#[derive(Default)]
struct StorageAuthScan {
    storage_auth_lines: Vec<usize>,
    storage_vars: Vec<String>,
}

impl<'ast> Visit<'ast> for StorageAuthScan {
    fn visit_stmt(&mut self, i: &'ast Stmt) {
        // Track variables assigned from storage
        if let Stmt::Local(local) = i {
            if let Some(init) = &local.init {
                if expr_reads_storage(&init.expr) {
                    if let syn::Pat::Ident(pat_ident) = &local.pat {
                        self.storage_vars.push(pat_ident.ident.to_string());
                    }
                }
            }
        }
        visit::visit_stmt(self, i);
    }

    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if i.method == "require_auth" {
            if let Expr::Path(p) = &*i.receiver {
                if let Some(ident) = p.path.get_ident() {
                    let name = ident.to_string();
                    if self.storage_vars.contains(&name) {
                        self.storage_auth_lines.push(i.span().start().line);
                    }
                }
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

fn expr_reads_storage(expr: &Expr) -> bool {
    let mut v = StorageReadScan::default();
    v.visit_expr(expr);
    v.found
}

#[derive(Default)]
struct StorageReadScan {
    found: bool,
}

impl<'ast> Visit<'ast> for StorageReadScan {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        let m = i.method.to_string();
        if matches!(m.as_str(), "get" | "instance" | "persistent" | "temporary") {
            if receiver_chain_contains_storage(&i.receiver) {
                self.found = true;
            }
        }
        visit::visit_expr_method_call(self, i);
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run_on_src(src: &str) -> Result<Vec<Finding>, syn::Error> {
        let file = parse_file(src)?;
        Ok(AuthUntrustedStorageCheck.run(&file, src))
    }

    #[test]
    fn flags_require_auth_with_storage_value() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Address, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn check_admin(env: Env) {
        let admin: Address = env.storage().instance().get(&Symbol::new(&env, "admin")).unwrap();
        admin.require_auth();
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        Ok(())
    }

    #[test]
    fn passes_when_require_auth_with_parameter() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn check_admin(env: Env, admin: Address) {
        admin.require_auth();
        let _ = env;
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_when_storage_read_but_no_auth() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Address, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn get_admin(env: Env) -> Address {
        env.storage().instance().get(&Symbol::new(&env, "admin")).unwrap()
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }
}
