//! Per-user data stored in instance storage instead of persistent.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File, FnArg, Pat};

const CHECK_NAME: &str = "instance-per-user-data";

pub struct InstancePerUserCheck;

impl Check for InstancePerUserCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let address_params = extract_address_params(&method.sig.inputs);
            if address_params.is_empty() {
                continue;
            }
            let mut scan = InstancePerUserScan {
                address_params: &address_params,
                findings: Vec::new(),
            };
            scan.visit_block(&method.block);
            out.extend(scan.findings.into_iter().map(|line| Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::Medium,
                file_path: String::new(),
                line,
                function_name: method.sig.ident.to_string(),
                description: "Per-user data stored in instance storage instead of persistent. \
                              All user data shares one TTL and storage slot limit, leading to data loss."
                    .to_string(),
            }));
        }
        out
    }
}

fn extract_address_params(inputs: &syn::punctuated::Punctuated<FnArg, syn::token::Comma>) -> Vec<String> {
    let mut params = Vec::new();
    for arg in inputs {
        if let FnArg::Typed(pat_type) = arg {
            if let Pat::Ident(pat_ident) = &*pat_type.pat {
                if is_address_type(&pat_type.ty) {
                    params.push(pat_ident.ident.to_string());
                }
            }
        }
    }
    params
}

fn is_address_type(ty: &syn::Type) -> bool {
    match ty {
        syn::Type::Path(p) => {
            p.path.segments.last().is_some_and(|s| s.ident == "Address")
        }
        _ => false,
    }
}

fn receiver_chain_contains_instance(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "instance" {
                return true;
            }
            receiver_chain_contains_instance(&m.receiver)
        }
        Expr::Field(f) => receiver_chain_contains_instance(&f.base),
        _ => false,
    }
}

fn key_contains_param(expr: &Expr, params: &[String]) -> bool {
    match expr {
        Expr::Path(p) => {
            p.path.segments.last().is_some_and(|s| params.contains(&s.ident.to_string()))
        }
        Expr::Reference(r) => key_contains_param(&r.expr, params),
        Expr::Tuple(t) => t.elems.iter().any(|e| key_contains_param(e, params)),
        _ => false,
    }
}

fn is_instance_set_with_param(m: &ExprMethodCall, params: &[String]) -> bool {
    if m.method != "set" {
        return false;
    }
    if !receiver_chain_contains_instance(&m.receiver) {
        return false;
    }
    m.args.iter().any(|arg| key_contains_param(arg, params))
}

struct InstancePerUserScan<'a> {
    address_params: &'a [String],
    findings: Vec<usize>,
}

impl<'ast> Visit<'ast> for InstancePerUserScan<'ast> {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if is_instance_set_with_param(i, self.address_params) {
            self.findings.push(i.span().start().line);
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
    fn flags_instance_set_with_address_param() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn set_user_data(env: Env, user: Address, data: u32) {
        env.storage().instance().set(&user, &data);
    }
}
"#,
        )?;
        let hits = InstancePerUserCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        Ok(())
    }

    #[test]
    fn passes_when_using_persistent() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn set_user_data(env: Env, user: Address, data: u32) {
        env.storage().persistent().set(&user, &data);
    }
}
"#,
        )?;
        let hits = InstancePerUserCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_instance_set_without_address_param() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn set_data(env: Env, data: u32) {
        env.storage().instance().set(&"key", &data);
    }
}
"#,
        )?;
        let hits = InstancePerUserCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
