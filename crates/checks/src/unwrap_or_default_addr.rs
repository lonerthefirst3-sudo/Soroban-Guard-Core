//! Flags `.unwrap_or_default()` on `Option<Address>` storage reads.
//!
//! `Address::default()` produces the zero-address, which is not a valid Stellar
//! account. Using it as a fallback silently creates a broken admin or recipient.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File, GenericArgument, PathArguments, Type};

const CHECK_NAME: &str = "unwrap-or-default-addr";

pub struct UnwrapOrDefaultAddrCheck;

impl Check for UnwrapOrDefaultAddrCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = Visitor {
                fn_name: fn_name.clone(),
                out: &mut out,
            };
            v.visit_block(&method.block);
        }
        out
    }
}

/// Returns true if the path segment's last ident is `Address`.
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

/// Returns true if any generic argument in a `get` turbofish is `Address`.
fn get_turbofish_is_address(m: &ExprMethodCall) -> bool {
    if m.method != "get" {
        return false;
    }
    let Some(turbofish) = &m.turbofish else {
        return false;
    };
    turbofish.args.iter().any(|arg| {
        if let GenericArgument::Type(ty) = arg {
            type_is_address(ty)
        } else {
            false
        }
    })
}

/// Returns true if the receiver chain contains `.storage()...get(...)` where
/// the get call has an `Address` turbofish, or the chain contains a `.get(...)`
/// on storage at all (for the let-binding heuristic path).
fn receiver_has_storage_get(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "get" && receiver_chain_has_storage(&m.receiver) {
                return true;
            }
            receiver_has_storage_get(&m.receiver)
        }
        _ => false,
    }
}

fn receiver_chain_has_storage(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "storage" {
                return true;
            }
            receiver_chain_has_storage(&m.receiver)
        }
        Expr::Field(f) => receiver_chain_has_storage(&f.base),
        _ => false,
    }
}

/// Walk the receiver chain and find the innermost `.get(...)` call; return it
/// if it sits on a storage chain.
fn find_storage_get<'a>(expr: &'a Expr) -> Option<&'a ExprMethodCall> {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "get" && receiver_chain_has_storage(&m.receiver) {
                return Some(m);
            }
            find_storage_get(&m.receiver)
        }
        _ => None,
    }
}

struct Visitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl Visit<'_> for Visitor<'_> {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if i.method == "unwrap_or_default" && receiver_has_storage_get(&i.receiver) {
            // Check if the get() call has an Address turbofish.
            if let Some(get_call) = find_storage_get(&i.receiver) {
                if get_turbofish_is_address(get_call) {
                    self.emit(i);
                    visit::visit_expr_method_call(self, i);
                    return;
                }
            }
        }
        visit::visit_expr_method_call(self, i);
    }

    /// Also catch `let addr: Address = expr.unwrap_or_default()` and
    /// `let addr: Option<Address> = ...; addr.unwrap_or_default()`.
    fn visit_local(&mut self, i: &syn::Local) {
        // Check if the binding type is Address or Option<Address>.
        let binding_is_addr = if let syn::Pat::Type(pt) = &i.pat {
            type_is_address(&pt.ty) || option_inner_is_address(&pt.ty)
        } else {
            false
        };

        if binding_is_addr {
            if let Some(init) = &i.init {
                if let Expr::MethodCall(m) = init.expr.as_ref() {
                    if m.method == "unwrap_or_default" && receiver_has_storage_get(&m.receiver) {
                        self.emit(m);
                    }
                }
            }
        }

        visit::visit_local(self, i);
    }
}

fn option_inner_is_address(ty: &Type) -> bool {
    let Type::Path(tp) = ty else { return false };
    let Some(seg) = tp.path.segments.last() else {
        return false;
    };
    if seg.ident != "Option" {
        return false;
    }
    let PathArguments::AngleBracketed(ab) = &seg.arguments else {
        return false;
    };
    ab.args.iter().any(|a| {
        if let GenericArgument::Type(inner) = a {
            type_is_address(inner)
        } else {
            false
        }
    })
}

impl Visitor<'_> {
    fn emit(&mut self, call: &ExprMethodCall) {
        self.out.push(Finding {
            check_name: CHECK_NAME.to_string(),
            severity: Severity::Medium,
            file_path: String::new(),
            line: call.span().start().line,
            function_name: self.fn_name.clone(),
            description: format!(
                "Function `{}` calls `.unwrap_or_default()` on an `Option<Address>` storage read. \
                 `Address::default()` is the zero-address and not a valid Stellar account — \
                 use an explicit fallback or return an error instead.",
                self.fn_name
            ),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        let file = parse_file(src).expect("parse");
        UnwrapOrDefaultAddrCheck.run(&file, src)
    }

    #[test]
    fn flags_get_turbofish_address() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn get_admin(env: Env) -> Address {
        env.storage().instance().get::<_, Address>(&"admin").unwrap_or_default()
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        assert_eq!(hits[0].severity, Severity::Medium);
        assert_eq!(hits[0].function_name, "get_admin");
    }

    #[test]
    fn flags_let_binding_address_type() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn get_admin(env: Env) -> Address {
        let admin: Address = env.storage().instance().get(&"admin").unwrap_or_default();
        admin
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "get_admin");
    }

    #[test]
    fn does_not_flag_non_address_unwrap_or_default() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn get_count(env: Env) -> u32 {
        env.storage().instance().get::<_, u32>(&"count").unwrap_or_default()
    }
}
"#);
        assert_eq!(hits.len(), 0);
    }

    #[test]
    fn does_not_flag_unwrap_or_with_explicit_value() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn get_admin(env: Env, fallback: Address) -> Address {
        env.storage().instance().get::<_, Address>(&"admin").unwrap_or(fallback)
    }
}
"#);
        assert_eq!(hits.len(), 0);
    }

    #[test]
    fn does_not_flag_outside_contractimpl() {
        let hits = run(r#"
use soroban_sdk::{Address, Env};
fn helper(env: &Env) -> Address {
    env.storage().instance().get::<_, Address>(&"admin").unwrap_or_default()
}
"#);
        assert_eq!(hits.len(), 0);
    }
}
