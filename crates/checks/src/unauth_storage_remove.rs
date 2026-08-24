//! Unauthorised storage remove: `env.storage()…remove(key)` where `key` is derived
//! from an `Address`-typed parameter and no `<param>.require_auth()` precedes it.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{Expr, ExprMethodCall, File, FnArg, Pat, Stmt, Type};

const CHECK_NAME: &str = "unauth-storage-remove";

/// Flags `#[contractimpl]` functions that call `env.storage()…remove(key)` where
/// `key` references an `Address`-typed parameter and no `<param>.require_auth()`
/// (or `env.require_auth()`) appears before the remove call in statement order.
pub struct UnauthStorageRemoveCheck;

impl Check for UnauthStorageRemoveCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();

            // Collect names of Address-typed parameters.
            let addr_params = address_params(&method.sig.inputs);
            if addr_params.is_empty() {
                continue;
            }

            let stmts = &method.block.stmts;

            for (idx, stmt) in stmts.iter().enumerate() {
                // Find a storage remove call in this statement.
                let Some((remove_line, key_idents)) = storage_remove_info(stmt) else {
                    continue;
                };

                // Check if any key ident is an Address param.
                let addr_param = addr_params
                    .iter()
                    .find(|p| key_idents.iter().any(|k| k == *p));
                let Some(addr_param) = addr_param else {
                    continue;
                };

                // Check whether require_auth on this param (or env) precedes this stmt.
                let guarded = stmts[..idx].iter().any(|s| {
                    stmt_has_require_auth(s, addr_param) || stmt_has_env_require_auth(s)
                });

                if !guarded {
                    out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::High,
                        file_path: String::new(),
                        line: remove_line,
                        function_name: fn_name.clone(),
                        description: format!(
                            "`{}` calls `env.storage()…remove(…)` using Address parameter \
                             `{}` as part of the key without a preceding \
                             `{}.require_auth()` or `env.require_auth()`. Any caller can \
                             delete another user's storage entry, effectively zeroing their \
                             balance.",
                            fn_name, addr_param, addr_param
                        ),
                    });
                    break; // one finding per function
                }
            }
        }
        out
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Collect names of parameters whose type is `Address` (or `soroban_sdk::Address`).
fn address_params(
    inputs: &syn::punctuated::Punctuated<FnArg, syn::token::Comma>,
) -> Vec<String> {
    inputs
        .iter()
        .filter_map(|arg| {
            let FnArg::Typed(pt) = arg else { return None };
            if !is_address_type(&pt.ty) {
                return None;
            }
            if let Pat::Ident(pi) = &*pt.pat {
                Some(pi.ident.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn is_address_type(ty: &Type) -> bool {
    match ty {
        Type::Path(tp) => tp
            .path
            .segments
            .last()
            .is_some_and(|s| s.ident == "Address"),
        _ => false,
    }
}

/// If `stmt` contains a `storage()…remove(key)` call, return
/// `(line, idents_in_key_arg)`.
fn storage_remove_info(stmt: &Stmt) -> Option<(usize, Vec<String>)> {
    let mut finder = RemoveFinder { result: None };
    finder.visit_stmt(stmt);
    finder.result
}

struct RemoveFinder {
    result: Option<(usize, Vec<String>)>,
}

impl<'ast> Visit<'ast> for RemoveFinder {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if self.result.is_none()
            && i.method == "remove"
            && receiver_chain_contains(&i.receiver, "storage")
        {
            let key_idents = i
                .args
                .iter()
                .flat_map(collect_idents_from_expr)
                .collect::<Vec<_>>();
            self.result = Some((i.span().start().line, key_idents));
            return;
        }
        syn::visit::visit_expr_method_call(self, i);
    }
}

/// Recursively collect all identifier names referenced in an expression.
fn collect_idents_from_expr(expr: &Expr) -> Vec<String> {
    match expr {
        Expr::Path(p) => p
            .path
            .get_ident()
            .map(|id| vec![id.to_string()])
            .unwrap_or_default(),
        Expr::Reference(r) => collect_idents_from_expr(&r.expr),
        Expr::MethodCall(m) => {
            let mut v = collect_idents_from_expr(&m.receiver);
            v.extend(m.args.iter().flat_map(collect_idents_from_expr));
            v
        }
        Expr::Tuple(t) => t.elems.iter().flat_map(collect_idents_from_expr).collect(),
        Expr::Call(c) => c.args.iter().flat_map(collect_idents_from_expr).collect(),
        _ => vec![],
    }
}

fn receiver_chain_contains(expr: &Expr, name: &str) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == name {
                return true;
            }
            receiver_chain_contains(&m.receiver, name)
        }
        _ => false,
    }
}

/// Returns true if `stmt` contains `<param>.require_auth()`.
fn stmt_has_require_auth(stmt: &Stmt, param: &str) -> bool {
    let mut v = RequireAuthFinder {
        param,
        found: false,
    };
    v.visit_stmt(stmt);
    v.found
}

struct RequireAuthFinder<'a> {
    param: &'a str,
    found: bool,
}

impl<'ast> Visit<'ast> for RequireAuthFinder<'_> {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if i.method == "require_auth" || i.method == "require_auth_for_args" {
            if let Expr::Path(p) = &*i.receiver {
                if p.path.is_ident(self.param) {
                    self.found = true;
                    return;
                }
            }
        }
        syn::visit::visit_expr_method_call(self, i);
    }
}

/// Returns true if `stmt` contains `env.require_auth()`.
fn stmt_has_env_require_auth(stmt: &Stmt) -> bool {
    let mut v = EnvRequireAuthFinder { found: false };
    v.visit_stmt(stmt);
    v.found
}

struct EnvRequireAuthFinder {
    found: bool,
}

impl<'ast> Visit<'ast> for EnvRequireAuthFinder {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if i.method == "require_auth" || i.method == "require_auth_for_args" {
            if let Expr::Path(p) = &*i.receiver {
                if p.path.is_ident("env") {
                    self.found = true;
                    return;
                }
            }
        }
        syn::visit::visit_expr_method_call(self, i);
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    const VULNERABLE: &str = r#"
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn clear_balance(env: Env, user: Address) {
        env.storage().persistent().remove(&user);
    }
}
"#;

    const SAFE_PARAM_AUTH: &str = r#"
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn clear_balance(env: Env, user: Address) {
        user.require_auth();
        env.storage().persistent().remove(&user);
    }
}
"#;

    const SAFE_ENV_AUTH: &str = r#"
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn clear_balance(env: Env, user: Address) {
        env.require_auth();
        env.storage().persistent().remove(&user);
    }
}
"#;

    #[test]
    fn flags_remove_without_auth() -> Result<(), syn::Error> {
        let file = parse_file(VULNERABLE)?;
        let hits = UnauthStorageRemoveCheck.run(&file, "");
        assert_eq!(hits.len(), 1, "expected one finding, got: {hits:?}");
        assert_eq!(hits[0].severity, Severity::High);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        assert!(hits[0].description.contains("user"));
        Ok(())
    }

    #[test]
    fn passes_with_param_require_auth() -> Result<(), syn::Error> {
        let file = parse_file(SAFE_PARAM_AUTH)?;
        let hits = UnauthStorageRemoveCheck.run(&file, "");
        assert!(hits.is_empty(), "got: {hits:?}");
        Ok(())
    }

    #[test]
    fn passes_with_env_require_auth() -> Result<(), syn::Error> {
        let file = parse_file(SAFE_ENV_AUTH)?;
        let hits = UnauthStorageRemoveCheck.run(&file, "");
        assert!(hits.is_empty(), "got: {hits:?}");
        Ok(())
    }

    #[test]
    fn ignores_remove_with_non_address_key() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contract, contractimpl, symbol_short, Env, Symbol};
#[contract] pub struct C;
const K: Symbol = symbol_short!("bal");
#[contractimpl]
impl C {
    pub fn reset(env: Env) {
        env.storage().persistent().remove(&K);
    }
}
"#,
        )?;
        let hits = UnauthStorageRemoveCheck.run(&file, "");
        assert!(hits.is_empty(), "got: {hits:?}");
        Ok(())
    }

    #[test]
    fn ignores_non_contractimpl() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{Address, Env};
pub struct C;
impl C {
    pub fn clear_balance(env: Env, user: Address) {
        env.storage().persistent().remove(&user);
    }
}
"#,
        )?;
        let hits = UnauthStorageRemoveCheck.run(&file, "");
        assert!(hits.is_empty(), "got: {hits:?}");
        Ok(())
    }

    #[test]
    fn flags_tuple_key_containing_address() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};
#[contract] pub struct C;
#[contractimpl]
impl C {
    pub fn clear(env: Env, owner: Address, spender: Address) {
        let key = (symbol_short!("allow"), owner.clone(), spender.clone());
        env.storage().persistent().remove(&key);
    }
}
"#,
        )?;
        let hits = UnauthStorageRemoveCheck.run(&file, "");
        // No require_auth on owner or spender → should flag
        assert_eq!(hits.len(), 1, "got: {hits:?}");
        Ok(())
    }
}
