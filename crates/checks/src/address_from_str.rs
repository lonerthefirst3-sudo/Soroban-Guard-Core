//! `Address::from_str` called with a user-supplied parameter (panic risk / DoS).
//!
//! `Address::from_str(&env, input)` panics if `input` is not a valid Stellar address.
//! Calling it on unvalidated user input allows any caller to trigger a contract panic
//! by passing an invalid string, causing a denial of service.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprCall, File, Pat, PatIdent};

const CHECK_NAME: &str = "address-from-str";

fn param_names(method: &syn::ImplItemFn) -> Vec<String> {
    method
        .sig
        .inputs
        .iter()
        .filter_map(|arg| {
            if let syn::FnArg::Typed(pt) = arg {
                if let Pat::Ident(PatIdent { ident, .. }) = &*pt.pat {
                    return Some(ident.to_string());
                }
            }
            None
        })
        .collect()
}

fn expr_is_param(expr: &Expr, params: &[String]) -> bool {
    let inner = match expr {
        Expr::Reference(r) => &*r.expr,
        other => other,
    };
    match inner {
        Expr::Path(p) => p
            .path
            .get_ident()
            .is_some_and(|id| params.contains(&id.to_string())),
        _ => false,
    }
}

/// True if the call is `Address::from_str(&env, <param>)` where `<param>` is a
/// function parameter (i.e., user-controlled input).
fn is_address_from_str_with_param(call: &ExprCall, params: &[String]) -> bool {
    let Expr::Path(p) = &*call.func else {
        return false;
    };
    let segs = &p.path.segments;
    if !(segs.len() == 2 && segs[0].ident == "Address" && segs[1].ident == "from_str") {
        return false;
    }
    if call.args.len() < 2 {
        return false;
    }
    expr_is_param(&call.args[1], params)
}

struct Visitor<'a> {
    fn_name: String,
    params: Vec<String>,
    out: &'a mut Vec<Finding>,
}

impl Visit<'_> for Visitor<'_> {
    fn visit_expr_call(&mut self, i: &ExprCall) {
        if is_address_from_str_with_param(i, &self.params) {
            self.out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::Medium,
                file_path: String::new(),
                line: i.span().start().line,
                function_name: self.fn_name.clone(),
                description: format!(
                    "`Address::from_str` in `{}` is called with a user-supplied parameter. \
                     Passing an invalid Stellar address string causes a panic, enabling \
                     denial-of-service. Validate the input or accept an `Address` parameter \
                     directly instead of a raw string.",
                    self.fn_name
                ),
            });
        }
        visit::visit_expr_call(self, i);
    }
}

pub struct AddressFromStrCheck;

impl Check for AddressFromStrCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let params = param_names(method);
            let mut v = Visitor {
                fn_name,
                params,
                out: &mut out,
            };
            v.visit_block(&method.block);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    #[test]
    fn flags_address_from_str_with_param() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Address, Env, String};
pub struct C;
#[contractimpl]
impl C {
    pub fn resolve(env: Env, input: String) -> Address {
        Address::from_str(&env, &input)
    }
}
"#;
        let file = parse_file(src)?;
        let hits = AddressFromStrCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        Ok(())
    }

    #[test]
    fn no_finding_for_literal_string() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn resolve(env: Env) -> Address {
        Address::from_str(&env, "GABC...")
    }
}
"#;
        let file = parse_file(src)?;
        let hits = AddressFromStrCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn no_finding_for_address_param() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn resolve(_env: Env, addr: Address) -> Address {
        addr
    }
}
"#;
        let file = parse_file(src)?;
        let hits = AddressFromStrCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn no_finding_outside_contractimpl() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{Address, Env, String};
pub struct C;
impl C {
    pub fn resolve(env: Env, input: String) -> Address {
        Address::from_str(&env, &input)
    }
}
"#;
        let file = parse_file(src)?;
        let hits = AddressFromStrCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
