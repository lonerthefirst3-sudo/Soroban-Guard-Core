//! Flags cross-contract calls whose target address comes directly from an `Address` parameter.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, ExprBinary, ExprMethodCall, File, FnArg, Pat, PatType, Type, TypePath};

const CHECK_NAME: &str = "unvalidated-invoke-target";

pub struct UnvalidatedInvokeTargetCheck;

impl Check for UnvalidatedInvokeTargetCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let address_params = address_param_names(&method.sig.inputs);
            if address_params.is_empty() {
                continue;
            }
            let mut v = UnvalidatedInvokeTargetVisitor {
                fn_name: fn_name.clone(),
                address_params,
                safe_guard_found: false,
                out: &mut out,
            };
            v.visit_block(&method.block);
        }
        out
    }
}

fn address_param_names(
    inputs: &syn::punctuated::Punctuated<FnArg, syn::token::Comma>,
) -> Vec<String> {
    inputs
        .iter()
        .filter_map(|arg| {
            let FnArg::Typed(PatType { pat, ty, .. }) = arg else {
                return None;
            };
            if !is_address_type(ty) {
                return None;
            }
            if let Pat::Ident(pi) = pat.as_ref() {
                Some(pi.ident.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn is_address_type(ty: &Type) -> bool {
    if let Type::Path(TypePath { path, .. }) = ty {
        path.segments.last().is_some_and(|s| s.ident == "Address")
    } else {
        false
    }
}

fn expr_ident_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Path(path) => path.path.get_ident().map(|id| id.to_string()),
        Expr::Reference(reference) => expr_ident_name(&reference.expr),
        Expr::Paren(paren) => expr_ident_name(&paren.expr),
        _ => None,
    }
}

fn is_invoke_contract_call(m: &ExprMethodCall) -> bool {
    if m.method != "invoke_contract" {
        return false;
    }
    matches!(&*m.receiver, Expr::Path(p) if p.path.is_ident("env"))
}

fn is_storage_get_call(m: &ExprMethodCall) -> bool {
    if m.method != "get" {
        return false;
    }
    receiver_chain_contains_storage(&m.receiver)
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

struct UnvalidatedInvokeTargetVisitor<'a> {
    fn_name: String,
    address_params: Vec<String>,
    safe_guard_found: bool,
    out: &'a mut Vec<Finding>,
}

impl<'ast> Visit<'ast> for UnvalidatedInvokeTargetVisitor<'_> {
    fn visit_expr_binary(&mut self, i: &'ast ExprBinary) {
        if matches!(i.op, BinOp::Eq(_) | BinOp::Ne(_)) {
            let left_name = expr_ident_name(&i.left);
            let right_name = expr_ident_name(&i.right);
            if left_name
                .as_ref()
                .is_some_and(|name| self.address_params.contains(name))
                || right_name
                    .as_ref()
                    .is_some_and(|name| self.address_params.contains(name))
            {
                self.safe_guard_found = true;
            }
        }
        visit::visit_expr_binary(self, i);
    }

    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if is_storage_get_call(i) {
            self.safe_guard_found = true;
        }
        if is_invoke_contract_call(i) {
            if let Some(arg) = i.args.first() {
                if let Some(name) = expr_ident_name(arg) {
                    if self.address_params.contains(&name) && !self.safe_guard_found {
                        self.out.push(Finding {
                            check_name: CHECK_NAME.to_string(),
                            severity: Severity::High,
                            file_path: String::new(),
                            line: i.span().start().line,
                            function_name: self.fn_name.clone(),
                            description: format!(
                                "Method `{}` invokes a contract with an `Address` parameter \"{}\" directly passed to `env.invoke_contract()`. Validate or restrict caller-supplied targets before invoking external contracts.",
                                self.fn_name, name
                            ),
                        });
                    }
                }
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        UnvalidatedInvokeTargetCheck.run(&parse_file(src).unwrap(), src)
    }

    #[test]
    fn flags_unvalidated_invoke_target() {
        let hits = run(r#"
use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn call(env: Env, callee: Address) {
        env.invoke_contract(&callee, &Symbol::new(&env, "method"), &());
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        assert_eq!(hits[0].check_name, CHECK_NAME);
    }

    #[test]
    fn passes_when_target_validated_with_storage_get_and_eq() {
        let hits = run(r#"
use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

const KEY: u32 = 0;

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn call(env: Env, callee: Address) {
        let admin = env.storage().persistent().get(&KEY).unwrap();
        if admin == callee {
            env.invoke_contract(&callee, &Symbol::new(&env, "method"), &());
        }
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn ignores_non_contractimpl() {
        let hits = run(r#"
use soroban_sdk::{Address, Env};

pub struct C;

impl C {
    pub fn call(env: Env, callee: Address) {
        env.invoke_contract(&callee, &Symbol::new(&env, "method"), &());
    }
}
"#);
        assert!(hits.is_empty());
    }
}
