//! env.deployer().upload_contract_wasm() called without authorization.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Block, Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "upload-wasm-auth";

/// Flags `#[contractimpl]` functions that call `env.deployer().upload_contract_wasm(...)`
/// without a preceding `require_auth` or `require_auth_for_args` call.
pub struct UploadWasmAuthCheck;

impl Check for UploadWasmAuthCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let mut scan = FuncBodyScan::default();
            scan.visit_block(&method.block);
            if !scan.upload_wasm || scan.env_require_auth {
                continue;
            }
            let line = first_upload_wasm_line(&method.block)
                .unwrap_or_else(|| method.sig.ident.span().start().line);
            let fn_name = method.sig.ident.to_string();
            out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::High,
                file_path: String::new(),
                line,
                function_name: fn_name.clone(),
                description: format!(
                    "Method `{fn_name}` calls `env.deployer().upload_contract_wasm()` but does \
                     not call `env.require_auth()` or `env.require_auth_for_args()`. Any caller \
                     can upload arbitrary WASM under the contract's deployer identity."
                ),
            });
        }
        out
    }
}

fn receiver_chain_contains_deployer(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "deployer" {
                return true;
            }
            receiver_chain_contains_deployer(&m.receiver)
        }
        Expr::Field(f) => receiver_chain_contains_deployer(&f.base),
        _ => false,
    }
}

fn is_upload_contract_wasm_call(m: &ExprMethodCall) -> bool {
    m.method == "upload_contract_wasm" && receiver_chain_contains_deployer(&m.receiver)
}

fn is_env_require_auth(m: &ExprMethodCall) -> bool {
    if m.method != "require_auth" {
        return false;
    }
    match &*m.receiver {
        Expr::Path(p) => p.path.is_ident("env"),
        _ => false,
    }
}

fn is_env_require_auth_for_args(m: &ExprMethodCall) -> bool {
    if m.method != "require_auth_for_args" {
        return false;
    }
    match &*m.receiver {
        Expr::Path(p) => p.path.is_ident("env"),
        _ => false,
    }
}

#[derive(Default)]
struct FuncBodyScan {
    upload_wasm: bool,
    env_require_auth: bool,
}

impl<'ast> Visit<'ast> for FuncBodyScan {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if is_upload_contract_wasm_call(i) {
            self.upload_wasm = true;
        }
        if is_env_require_auth(i) || is_env_require_auth_for_args(i) {
            self.env_require_auth = true;
        }
        visit::visit_expr_method_call(self, i);
    }
}

struct FirstUploadWasmLine {
    line: Option<usize>,
}

impl<'ast> Visit<'ast> for FirstUploadWasmLine {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if self.line.is_none() && is_upload_contract_wasm_call(i) {
            self.line = Some(i.span().start().line);
        }
        visit::visit_expr_method_call(self, i);
    }
}

fn first_upload_wasm_line(block: &Block) -> Option<usize> {
    let mut v = FirstUploadWasmLine { line: None };
    v.visit_block(block);
    v.line
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    #[test]
    fn flags_upload_wasm_without_auth() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn upload(env: Env, wasm: soroban_sdk::Bytes) {
        env.deployer().upload_contract_wasm(wasm);
    }
}
"#,
        )?;
        let hits = UploadWasmAuthCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        assert_eq!(hits[0].function_name, "upload");
        Ok(())
    }

    #[test]
    fn passes_when_env_require_auth_present() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn upload(env: Env, wasm: soroban_sdk::Bytes) {
        env.require_auth();
        env.deployer().upload_contract_wasm(wasm);
    }
}
"#,
        )?;
        let hits = UploadWasmAuthCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_when_env_require_auth_for_args_present() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn upload(env: Env, wasm: soroban_sdk::Bytes) {
        env.require_auth_for_args((wasm.clone(),));
        env.deployer().upload_contract_wasm(wasm);
    }
}
"#,
        )?;
        let hits = UploadWasmAuthCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_non_contractimpl() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::Env;

pub struct C;

impl C {
    pub fn upload(env: Env, wasm: soroban_sdk::Bytes) {
        env.deployer().upload_contract_wasm(wasm);
    }
}
"#,
        )?;
        let hits = UploadWasmAuthCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
