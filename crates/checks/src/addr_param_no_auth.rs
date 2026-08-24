//! Address parameter without `require_auth` before storage write or token call.
//!
//! A `#[contractimpl]` function that receives an `Address` parameter and writes to
//! storage or calls a token client must call `addr.require_auth()` (or
//! `env.require_auth_for_address(addr, ...)`) on that parameter. Omitting this lets
//! any caller impersonate any address.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File, FnArg, Pat, Type};

const CHECK_NAME: &str = "addr-param-no-auth";

/// Token-client method names that constitute a privileged operation.
const TOKEN_METHODS: &[&str] = &["transfer", "mint", "burn", "transfer_from", "burn_from"];

pub struct AddrParamNoAuthCheck;

impl Check for AddrParamNoAuthCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            // Collect Address-typed parameter names.
            let addr_params: Vec<String> = method
                .sig
                .inputs
                .iter()
                .filter_map(|arg| {
                    let FnArg::Typed(pt) = arg else { return None };
                    if !type_is_address(&pt.ty) {
                        return None;
                    }
                    if let Pat::Ident(pi) = &*pt.pat {
                        Some(pi.ident.to_string())
                    } else {
                        None
                    }
                })
                .collect();

            if addr_params.is_empty() {
                continue;
            }

            let mut scan = BodyScan::new(addr_params.clone());
            scan.visit_block(&method.block);

            if !scan.has_storage_write && !scan.has_token_call {
                continue;
            }

            // Report each Address param that is never authenticated.
            for param in &addr_params {
                if !scan.authed_params.contains(param) {
                    let fn_name = method.sig.ident.to_string();
                    out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::High,
                        file_path: String::new(),
                        line: scan
                            .write_line
                            .unwrap_or_else(|| method.sig.ident.span().start().line),
                        function_name: fn_name.clone(),
                        description: format!(
                            "Method `{fn_name}` has an `Address` parameter `{param}` but \
                             never calls `{param}.require_auth()` or \
                             `env.require_auth_for_address({param}, ...)` before writing to \
                             storage or calling a token client. Any caller can impersonate \
                             this address."
                        ),
                    });
                    break; // one finding per function is enough
                }
            }
        }
        out
    }
}

fn type_is_address(ty: &Type) -> bool {
    match ty {
        Type::Path(tp) => tp
            .path
            .segments
            .last()
            .is_some_and(|s| s.ident == "Address"),
        _ => false,
    }
}

struct BodyScan {
    addr_params: Vec<String>,
    authed_params: Vec<String>,
    has_storage_write: bool,
    has_token_call: bool,
    write_line: Option<usize>,
}

impl BodyScan {
    fn new(addr_params: Vec<String>) -> Self {
        Self {
            addr_params,
            authed_params: Vec::new(),
            has_storage_write: false,
            has_token_call: false,
            write_line: None,
        }
    }
}

impl<'ast> Visit<'ast> for BodyScan {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        let method = i.method.to_string();

        // addr.require_auth()
        if method == "require_auth" {
            if let Expr::Path(p) = &*i.receiver {
                let name = p.path.segments.last().map(|s| s.ident.to_string()).unwrap_or_default();
                if self.addr_params.contains(&name) && !self.authed_params.contains(&name) {
                    self.authed_params.push(name);
                }
            }
        }

        // env.require_auth_for_address(addr, ...)
        if method == "require_auth_for_address" {
            if let Some(first_arg) = i.args.first() {
                if let Expr::Path(p) = first_arg {
                    let name = p.path.segments.last().map(|s| s.ident.to_string()).unwrap_or_default();
                    if self.addr_params.contains(&name) && !self.authed_params.contains(&name) {
                        self.authed_params.push(name);
                    }
                }
            }
        }

        // Storage write
        if matches!(method.as_str(), "set" | "remove") && receiver_chain_contains_storage(&i.receiver) {
            self.has_storage_write = true;
            if self.write_line.is_none() {
                self.write_line = Some(i.span().start().line);
            }
        }

        // Token client call
        if TOKEN_METHODS.contains(&method.as_str()) {
            self.has_token_call = true;
            if self.write_line.is_none() {
                self.write_line = Some(i.span().start().line);
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
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        let file = parse_file(src).unwrap();
        AddrParamNoAuthCheck.run(&file, src)
    }

    #[test]
    fn flags_address_param_without_require_auth() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, symbol_short, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn deposit(env: Env, user: Address, amount: i128) {
        env.storage().persistent().set(&symbol_short!("bal"), &amount);
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "deposit");
        assert_eq!(hits[0].severity, Severity::High);
    }

    #[test]
    fn passes_when_require_auth_called_on_param() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, symbol_short, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn deposit(env: Env, user: Address, amount: i128) {
        user.require_auth();
        env.storage().persistent().set(&symbol_short!("bal"), &amount);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn passes_when_require_auth_for_address_called() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, symbol_short, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn deposit(env: Env, user: Address, amount: i128) {
        env.require_auth_for_address(user, ());
        env.storage().persistent().set(&symbol_short!("bal"), &amount);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn ignores_function_without_storage_write_or_token_call() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn get_info(env: Env, user: Address) -> bool {
        true
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn ignores_function_without_address_params() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, symbol_short, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn bump(env: Env, amount: i128) {
        env.storage().persistent().set(&symbol_short!("k"), &amount);
    }
}
"#);
        assert!(hits.is_empty());
    }
}
