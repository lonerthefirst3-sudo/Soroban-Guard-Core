//! Detects symbol_short! used as storage key for per-user data (key collision).

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File, FnArg, Pat, PatType, Type};

const CHECK_NAME: &str = "symbol-as-user-key";

/// Flags env.storage()...set(symbol_short!(...), value) calls inside functions that have an Address-typed parameter,
/// where the key is a bare symbol_short! macro (not combined with the address in a tuple or struct).
pub struct SymbolAsUserKeyCheck;

impl Check for SymbolAsUserKeyCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let has_address_param = has_address_parameter(&method.sig.inputs);
            if has_address_param {
                let mut v = StorageVisitor {
                    fn_name: fn_name.clone(),
                    out: &mut out,
                };
                v.visit_block(&method.block);
            }
        }
        out
    }
}

fn has_address_parameter(inputs: &syn::punctuated::Punctuated<FnArg, syn::token::Comma>) -> bool {
    for arg in inputs {
        if let FnArg::Typed(PatType { ty, .. }) = arg {
            if is_address_type(ty) {
                return true;
            }
        }
    }
    false
}

fn is_address_type(ty: &Type) -> bool {
    match ty {
        Type::Path(tp) => {
            if let Some(ident) = tp.path.get_ident() {
                ident == "Address"
            } else {
                false
            }
        }
        _ => false,
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

fn is_storage_set_call(m: &ExprMethodCall) -> bool {
    m.method == "set" && receiver_chain_contains_storage(&m.receiver)
}

fn is_bare_symbol_short(expr: &Expr) -> bool {
    match expr {
        Expr::Macro(m) => {
            if let Some(last_seg) = m.mac.path.segments.last() {
                last_seg.ident == "symbol_short"
            } else {
                false
            }
        }
        _ => false,
    }
}

struct StorageVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl Visit<'_> for StorageVisitor<'_> {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if is_storage_set_call(i) {
            if let Some(first_arg) = i.args.first() {
                if is_bare_symbol_short(first_arg) {
                    self.out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::High,
                        file_path: String::new(),
                        line: i.span().start().line,
                        function_name: self.fn_name.clone(),
                        description: format!(
                            "Method `{}` uses `symbol_short!` as a bare storage key in a function with an Address parameter. \
                             This causes key collisions across all users—use a tuple like `(&user, symbol_short!(...))` instead.",
                            self.fn_name
                        ),
                    });
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

    fn run_on_src(src: &str) -> Result<Vec<Finding>, syn::Error> {
        let file = parse_file(src)?;
        Ok(SymbolAsUserKeyCheck.run(&file, src))
    }

    #[test]
    fn flags_bare_symbol_short_as_key_with_address_param() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set_balance(env: Env, user: Address, amount: i128) {
        env.storage().persistent().set(symbol_short!("balance"), &amount);
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "set_balance");
        assert_eq!(hits[0].severity, Severity::High);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        Ok(())
    }

    #[test]
    fn passes_when_symbol_short_combined_with_address() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set_balance(env: Env, user: Address, amount: i128) {
        env.storage().persistent().set((&user, symbol_short!("balance")), &amount);
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_when_no_address_param() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contract, contractimpl, symbol_short, Env};

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set_global(env: Env, amount: i128) {
        env.storage().persistent().set(symbol_short!("total"), &amount);
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }
}