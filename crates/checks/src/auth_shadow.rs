//! require_auth called on a parameter that shadows a storage variable.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Block, Expr, ExprMethodCall, File, FnArg, Pat, PatType};

const CHECK_NAME: &str = "auth-shadow";

pub struct AuthShadowCheck;

impl Check for AuthShadowCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let param_names = extract_address_params(&method.sig.inputs);
            let storage_keys = extract_storage_keys(&method.block);

            let mut v = AuthShadowVisitor {
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

fn extract_address_params(
    inputs: &syn::punctuated::Punctuated<FnArg, syn::token::Comma>,
) -> Vec<String> {
    let mut names = Vec::new();
    for arg in inputs {
        if let FnArg::Typed(PatType { pat, ty, .. }) = arg {
            if let Pat::Ident(ident) = &**pat {
                if is_address_type(ty) {
                    names.push(ident.ident.to_string());
                }
            }
        }
    }
    names
}

fn is_address_type(ty: &syn::Type) -> bool {
    match ty {
        syn::Type::Path(p) => p.path.segments.last().is_some_and(|s| s.ident == "Address"),
        _ => false,
    }
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
        if matches!(
            i.method.to_string().as_str(),
            "get" | "has" | "remove" | "set"
        ) {
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
        Expr::Call(c) => {
            // Symbol::new(&env, "admin") — extract last string arg
            c.args.last().and_then(extract_key_name_from_expr)
        }
        _ => None,
    }
}

struct AuthShadowVisitor<'a> {
    fn_name: String,
    param_names: Vec<String>,
    storage_keys: Vec<String>,
    out: &'a mut Vec<Finding>,
}

impl Visit<'_> for AuthShadowVisitor<'_> {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if i.method == "require_auth" {
            if let Expr::Path(p) = &*i.receiver {
                if let Some(ident) = p.path.segments.last() {
                    let param_name = ident.ident.to_string();
                    if self.param_names.contains(&param_name)
                        && self.storage_keys.contains(&param_name)
                    {
                        self.out.push(Finding {
                            check_name: CHECK_NAME.to_string(),
                            severity: Severity::High,
                            file_path: String::new(),
                            line: i.span().start().line,
                            function_name: self.fn_name.clone(),
                            description: format!(
                                "Method `{}` calls `require_auth()` on parameter `{}` which \
                                 shadows a storage key with the same name. This authenticates the \
                                 parameter value instead of the stored value, potentially allowing \
                                 unauthorized access.",
                                self.fn_name, param_name
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

    #[test]
    fn flags_auth_on_shadowing_param() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env, Symbol};
pub struct C;
#[contractimpl]
impl C {
    pub fn transfer(env: Env, admin: Address, amount: i128) {
        admin.require_auth();
        let stored_admin: Address = env.storage().persistent().get(&Symbol::new(&env, "admin")).unwrap();
        let _ = (amount, stored_admin);
    }
}
"#,
        )?;
        let hits = AuthShadowCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        Ok(())
    }

    #[test]
    fn no_finding_when_no_shadow() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env, Symbol};
pub struct C;
#[contractimpl]
impl C {
    pub fn transfer(env: Env, caller: Address, amount: i128) {
        caller.require_auth();
        let stored_admin: Address = env.storage().persistent().get(&Symbol::new(&env, "admin")).unwrap();
        let _ = (amount, stored_admin);
    }
}
"#,
        )?;
        let hits = AuthShadowCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn no_finding_for_env_require_auth() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env, Symbol};
pub struct C;
#[contractimpl]
impl C {
    pub fn transfer(env: Env, admin: Address, amount: i128) {
        env.require_auth();
        let stored_admin: Address = env.storage().persistent().get(&Symbol::new(&env, "admin")).unwrap();
        let _ = (amount, stored_admin, admin);
    }
}
"#,
        )?;
        let hits = AuthShadowCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
