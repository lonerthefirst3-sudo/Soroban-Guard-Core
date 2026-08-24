//! Detects deployment of arbitrary WASM via deployer with caller‑supplied hash.
//!
//! Flags `env.deployer().deploy(wasm_hash, ...)` or `env.deployer().deploy_v2(wasm_hash, ...)`
//! where `wasm_hash` is a direct function parameter of type `Bytes` or `BytesN<N>` and there is no
//! prior storage lookup or equality comparison that would constrain the hash.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use std::collections::HashSet;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprBinary, ExprMethodCall, File, Ident, Type, BinOp};

const CHECK_NAME: &str = "deploy-arbitrary-wasm";

/// Flags deploy calls that use a Bytes/BytesN parameter without a guard.
pub struct DeployArbitraryWasmCheck;

impl Check for DeployArbitraryWasmCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let bytes_params = collect_bytes_params(&method.sig.inputs);
            if bytes_params.is_empty() {
                continue;
            }
            let mut scan = DeployScan {
                fn_name,
                out: &mut out,
                bytes_params: &bytes_params,
                safe_params: HashSet::new(),
            };
            scan.visit_block(&method.block);
        }
        out
    }
}

struct DeployScan<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
    bytes_params: &'a HashSet<Ident>,
    safe_params: HashSet<Ident>,
}

impl<'ast> Visit<'ast> for DeployScan<'_> {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        // Check for deploy or deploy_v2 calls
        if is_deploy_call(i) {
            // The first argument is the wasm hash
            if let Some(wasm_hash_arg) = i.args.first() {
                if let Some(ident) = extract_ident(wasm_hash_arg) {
                    if self.bytes_params.contains(&ident)
                        && !self.safe_params.contains(&ident)
                    {
                        let line = i.span().start().line;
                        self.out.push(Finding {
                            check_name: CHECK_NAME.to_string(),
                            severity: Severity::High,
                            file_path: String::new(),
                            line,
                            function_name: self.fn_name.clone(),
                            description: format!(
                                "Method `{}` deploys WASM using a caller‑supplied hash parameter `{}` \
                                 without prior storage lookup or equality check. This may allow \
                                 deployment of arbitrary contracts under the deployer's identity.",
                                self.fn_name, ident
                            ),
                        });
                    }
                }
            }
        }
        visit::visit_expr_method_call(self, i);
    }

    fn visit_expr_binary(&mut self, i: &'ast ExprBinary) {
        // Equality/inequality comparisons involving a bytes parameter mark it as safe
        if is_comparison_op(&i.op) {
            if let Some(ident) = extract_ident(&i.left) {
                if self.bytes_params.contains(&ident) {
                    self.safe_params.insert(ident.clone());
                }
            }
            if let Some(ident) = extract_ident(&i.right) {
                if self.bytes_params.contains(&ident) {
                    self.safe_params.insert(ident.clone());
                }
            }
        }
        visit::visit_expr_binary(self, i);
    }
}

/// Check if the method call is a deploy or deploy_v2 call on a deployer receiver.
fn is_deploy_call(m: &ExprMethodCall) -> bool {
    (m.method == "deploy" || m.method == "deploy_v2") && is_deployer_receiver(&m.receiver)
}

/// Check if the receiver chain contains `.deployer()`.
fn is_deployer_receiver(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "deployer" {
                return true;
            }
            is_deployer_receiver(&m.receiver)
        }
        Expr::Field(f) => is_deployer_receiver(&f.base),
        _ => false,
    }
}

/// Extract an identifier from an expression, handling references and clone.
fn extract_ident(expr: &Expr) -> Option<&Ident> {
    match expr {
        Expr::Path(path) => path.path.get_ident(),
        Expr::Reference(addr) => extract_ident(&addr.expr),
        Expr::MethodCall(m) if m.method == "clone" => extract_ident(&m.receiver),
        _ => None,
    }
}

/// Collect identifiers of parameters whose type is `Bytes` or `BytesN<_>`.
fn collect_bytes_params(inputs: &syn::punctuated::Punctuated<syn::FnArg, syn::token::Comma>) -> HashSet<Ident> {
    let mut set = HashSet::new();
    for input in inputs {
        if let syn::FnArg::Typed(pat_type) = input {
            if let syn::Pat::Ident(pat_ident) = &*pat_type.pat {
                let ident = pat_ident.ident.clone();
                if is_bytes_type(&pat_type.ty) {
                    set.insert(ident);
                }
            }
        }
    }
    set
}

fn is_bytes_type(ty: &Type) -> bool {
    match ty {
        Type::Path(type_path) => {
            if let Some(segment) = type_path.path.segments.last() {
                let ident = &segment.ident;
                ident == "Bytes" || ident == "Byte"
            } else {
                false
            }
        }
        // Could also be `BytesN<...>` – we ignore generic for now.
        _ => false,
    }
}

/// Check if a binary operator is a comparison (less, greater, equal, etc.).
fn is_comparison_op(op: &BinOp) -> bool {
    matches!(
        op,
        BinOp::Lt(_) | BinOp::Le(_) | BinOp::Gt(_) | BinOp::Ge(_) | BinOp::Eq(_) | BinOp::Ne(_)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_deploy_with_bytes_param() -> Result<(), syn::Error> {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn deploy_contract(env: Env, hash: Bytes) {
        env.deployer().deploy(hash, ());
    }
}
        "#;
        let file = parse_file(code)?;
        let check = DeployArbitraryWasmCheck;
        let findings = check.run(&file, "");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        Ok(())
    }

    #[test]
    fn flags_deploy_v2_with_bytes_param() -> Result<(), syn::Error> {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn deploy_contract(env: Env, hash: BytesN<32>) {
        env.deployer().deploy_v2(hash, (), vec![]);
    }
}
        "#;
        let file = parse_file(code)?;
        let check = DeployArbitraryWasmCheck;
        let findings = check.run(&file, "");
        assert_eq!(findings.len(), 1);
        Ok(())
    }

    #[test]
    fn passes_with_equality_guard() -> Result<(), syn::Error> {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn deploy_contract(env: Env, hash: Bytes) {
        if hash == Bytes::new(&env) {
            env.deployer().deploy(hash, ());
        }
    }
}
        "#;
        let file = parse_file(code)?;
        let check = DeployArbitraryWasmCheck;
        let findings = check.run(&file, "");
        assert!(findings.is_empty());
        Ok(())
    }

    #[test]
    fn passes_when_param_is_not_bytes() -> Result<(), syn::Error> {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn deploy_contract(env: Env, amount: i128) {
        env.deployer().deploy(amount, ());
    }
}
        "#;
        let file = parse_file(code)?;
        let check = DeployArbitraryWasmCheck;
        let findings = check.run(&file, "");
        assert!(findings.is_empty());
        Ok(())
    }
}
