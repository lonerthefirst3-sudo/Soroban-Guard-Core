//! Unsafe unwrap/expect on storage reads in `#[contractimpl]` methods.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "storage-unwrap";

/// Flags method chains that end in `.unwrap()` or `.expect(...)` where the receiver
/// chain contains `.storage().get(...)` calls, which can panic if keys are absent.
pub struct StorageUnwrapCheck;

impl Check for StorageUnwrapCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = StorageVisitor {
                fn_name: fn_name.clone(),
                out: &mut out,
            };
            v.visit_block(&method.block);
        }
        out
    }
}

fn receiver_chain_contains_storage_get(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "get" && receiver_chain_contains_storage(&m.receiver) {
                return true;
            }
            receiver_chain_contains_storage_get(&m.receiver)
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

fn is_storage_unwrap_or_expect(m: &ExprMethodCall) -> bool {
    let method_name = m.method.to_string();
    if !matches!(method_name.as_str(), "unwrap" | "expect") {
        return false;
    }
    receiver_chain_contains_storage_get(&m.receiver)
}

struct StorageVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl Visit<'_> for StorageVisitor<'_> {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if is_storage_unwrap_or_expect(i) {
            let method_name = i.method.to_string();
            self.out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::Medium,
                file_path: String::new(),
                line: i.span().start().line,
                function_name: self.fn_name.clone(),
                description: format!(
                    "Method `{}` calls `.{method_name}()` on a storage read. \
                     Storage keys may be absent—use `unwrap_or`, `unwrap_or_else`, \
                     or `unwrap_or_default` to handle missing data gracefully.",
                    self.fn_name
                ),
            });
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
        Ok(StorageUnwrapCheck.run(&file, src))
    }

    #[test]
    fn flags_storage_unwrap() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn get_balance(env: Env, key: Symbol) -> i128 {
        env.storage().persistent().get(&key).unwrap()
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "get_balance");
        assert_eq!(hits[0].severity, Severity::Medium);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        Ok(())
    }

    #[test]
    fn flags_storage_expect() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn get_balance(env: Env, key: Symbol) -> i128 {
        env.storage().persistent().get(&key).expect("balance not found")
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert!(hits[0].description.contains("expect"));
        Ok(())
    }

    #[test]
    fn does_not_flag_unwrap_or() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn get_balance(env: Env, key: Symbol) -> i128 {
        env.storage().persistent().get(&key).unwrap_or(0)
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 0);
        Ok(())
    }

    #[test]
    fn does_not_flag_unwrap_or_default() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn get_balance(env: Env, key: Symbol) -> i128 {
        env.storage().persistent().get(&key).unwrap_or_default()
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 0);
        Ok(())
    }

    #[test]
    fn does_not_flag_non_storage_unwrap() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn some_calculation(env: Env) -> i128 {
        let result = 10i128.checked_div(2).unwrap();
        result
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 0);
        Ok(())
    }
}