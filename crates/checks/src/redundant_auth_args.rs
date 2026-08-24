//! require_auth_for_args where all args are derivable from storage or constants.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Block, Expr, ExprMethodCall, File, FnArg, Pat, PatType};

const CHECK_NAME: &str = "redundant-auth-args";

pub struct RedundantAuthArgsCheck;

impl Check for RedundantAuthArgsCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let param_names = extract_param_names(&method.sig.inputs);
            let storage_keys = extract_storage_keys(&method.block);

            let mut v = RedundantAuthArgsVisitor {
                fn_name: fn_name.clone(),
                param_names: param_names.clone(),
                storage_keys: storage_keys.clone(),
                out: &mut out,
            };
            v.visit_block(&method.block);
        }
        out
    }
}

fn extract_param_names(
    inputs: &syn::punctuated::Punctuated<FnArg, syn::token::Comma>,
) -> Vec<String> {
    let mut names = Vec::new();
    for arg in inputs {
        if let FnArg::Typed(PatType { pat, .. }) = arg {
            if let Pat::Ident(ident) = &**pat {
                names.push(ident.ident.to_string());
            }
        }
    }
    names
}

fn extract_storage_keys(block: &Block) -> Vec<String> {
    let mut keys = Vec::new();
    let mut v = StorageKeyExtractor { keys: &mut keys };
    v.visit_block(block);
    keys
}

struct StorageKeyExtractor<'a> {
    keys: &'a mut Vec<String>,
}

impl Visit<'_> for StorageKeyExtractor<'_> {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if i.method == "get" {
            if let Some(key) = extract_key_name(&i.args.first()) {
                self.keys.push(key);
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

fn extract_key_name(arg: &Option<&syn::Expr>) -> Option<String> {
    let arg = arg.as_ref()?;
    match *arg {
        Expr::Reference(r) => extract_key_name_from_expr(&r.expr),
        other => extract_key_name_from_expr(other),
    }
}

fn extract_key_name_from_expr(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Path(p) => p.path.segments.last().map(|s| s.ident.to_string()),
        Expr::Lit(l) => match &l.lit {
            syn::Lit::Str(s) => Some(s.value()),
            _ => None,
        },
        _ => None,
    }
}

fn is_string_literal(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(_),
            ..
        })
    )
}

fn is_storage_read(expr: &Expr, storage_keys: &[String]) -> bool {
    if let Expr::MethodCall(m) = expr {
        if m.method == "get" {
            if let Some(key) = extract_key_name(&m.args.first()) {
                return storage_keys.contains(&key);
            }
        }
    }
    false
}

struct RedundantAuthArgsVisitor<'a> {
    fn_name: String,
    param_names: Vec<String>,
    storage_keys: Vec<String>,
    out: &'a mut Vec<Finding>,
}

impl Visit<'_> for RedundantAuthArgsVisitor<'_> {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if i.method == "require_auth_for_args" {
            if let Some(Expr::Tuple(tuple)) = i.args.first() {
                if all_args_derivable(&tuple.elems, &self.param_names, &self.storage_keys) {
                    self.out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::Low,
                        file_path: String::new(),
                        line: i.span().start().line,
                        function_name: self.fn_name.clone(),
                        description: format!(
                            "Method `{}` calls `require_auth_for_args()` where all arguments \
                             are string literals or values freshly read from storage. This \
                             defeats the purpose of binding auth to call-specific arguments.",
                            self.fn_name
                        ),
                    });
                }
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

fn all_args_derivable(
    elems: &syn::punctuated::Punctuated<Expr, syn::token::Comma>,
    _param_names: &[String],
    storage_keys: &[String],
) -> bool {
    elems
        .iter()
        .all(|e| is_string_literal(e) || is_storage_read(e, storage_keys))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    #[test]
    fn flags_redundant_auth_args_with_literals() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn bad(env: Env) {
        env.require_auth_for_args(("literal", "args"));
    }
}
"#,
        )?;
        let hits = RedundantAuthArgsCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Low);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        Ok(())
    }

    #[test]
    fn no_finding_when_args_include_params() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn good(env: Env, user: Address) {
        env.require_auth_for_args((user,));
    }
}
"#,
        )?;
        let hits = RedundantAuthArgsCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
