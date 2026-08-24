//! `Bytes::from_slice` called with a user-controlled slice whose length is not validated.
//!
//! If `data` comes from a function parameter without a prior length check, callers can
//! pass arbitrarily large buffers, exceeding ledger entry size limits or corrupting
//! fixed-size slot layouts.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprCall, ExprMethodCall, File, Pat, PatIdent};

const CHECK_NAME: &str = "bytes-oversized";

/// Collect the names of all parameters in the function signature.
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

/// True if the expression (or a reference to it) is one of the tracked parameter names.
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

/// True if the call is `Bytes::from_slice(&env, <param>)` where `<param>` is a
/// function parameter (i.e., user-controlled).
fn is_bytes_from_slice_with_param(call: &ExprCall, params: &[String]) -> bool {
    let Expr::Path(p) = &*call.func else {
        return false;
    };
    let segs = &p.path.segments;
    if !(segs.len() == 2 && segs[0].ident == "Bytes" && segs[1].ident == "from_slice") {
        return false;
    }
    // args: (&env, data)
    if call.args.len() < 2 {
        return false;
    }
    expr_is_param(&call.args[1], params)
}

/// Also catch the method-call form: `Bytes::from_slice` is sometimes written as
/// a free function, but also check `.from_slice(...)` on a path receiver.
fn is_method_from_slice_with_param(call: &ExprMethodCall, params: &[String]) -> bool {
    if call.method != "from_slice" {
        return false;
    }
    // receiver should be `Bytes` path
    let Expr::Path(p) = &*call.receiver else {
        return false;
    };
    if p.path.get_ident().is_none_or(|id| id != "Bytes") {
        return false;
    }
    call.args.iter().any(|a| expr_is_param(a, params))
}

struct Visitor<'a> {
    fn_name: String,
    params: Vec<String>,
    out: &'a mut Vec<Finding>,
}

impl Visit<'_> for Visitor<'_> {
    fn visit_expr_call(&mut self, i: &ExprCall) {
        if is_bytes_from_slice_with_param(i, &self.params) {
            self.out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::Medium,
                file_path: String::new(),
                line: i.span().start().line,
                function_name: self.fn_name.clone(),
                description: format!(
                    "`Bytes::from_slice` in `{}` receives a user-controlled slice without \
                     a prior length check. Callers can supply oversized buffers that exceed \
                     ledger entry limits or corrupt fixed-size slot layouts. Validate \
                     `data.len()` before constructing the `Bytes` value.",
                    self.fn_name
                ),
            });
        }
        visit::visit_expr_call(self, i);
    }

    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if is_method_from_slice_with_param(i, &self.params) {
            self.out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::Medium,
                file_path: String::new(),
                line: i.span().start().line,
                function_name: self.fn_name.clone(),
                description: format!(
                    "`Bytes::from_slice` in `{}` receives a user-controlled slice without \
                     a prior length check. Callers can supply oversized buffers that exceed \
                     ledger entry limits or corrupt fixed-size slot layouts. Validate \
                     `data.len()` before constructing the `Bytes` value.",
                    self.fn_name
                ),
            });
        }
        visit::visit_expr_method_call(self, i);
    }
}

pub struct BytesOversizedCheck;

impl Check for BytesOversizedCheck {
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
    fn flags_bytes_from_slice_with_param() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Bytes, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn store(env: Env, data: &[u8]) {
        let b = Bytes::from_slice(&env, data);
        env.storage().instance().set(&1u32, &b);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = BytesOversizedCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        Ok(())
    }

    #[test]
    fn no_finding_for_literal_slice() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Bytes, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn store(env: Env) {
        let b = Bytes::from_slice(&env, &[1u8, 2, 3]);
        env.storage().instance().set(&1u32, &b);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = BytesOversizedCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn no_finding_outside_contractimpl() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{Bytes, Env};
pub struct C;
impl C {
    pub fn store(env: Env, data: &[u8]) {
        let _ = Bytes::from_slice(&env, data);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = BytesOversizedCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
