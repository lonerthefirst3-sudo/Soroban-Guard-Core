//! Flags incorrect `.unwrap()` calls on `env.current_contract_address()` result.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "current-contract-unwrap";

/// Flags `env.current_contract_address().unwrap()` calls in `#[contractimpl]` methods.
/// `env.current_contract_address()` returns an `Address` directly, not an `Option`.
pub struct CurrentContractUnwrapCheck;

impl Check for CurrentContractUnwrapCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = CurrentContractVisitor {
                fn_name: fn_name.clone(),
                out: &mut out,
            };
            v.visit_block(&method.block);
        }
        out
    }
}

fn is_current_contract_unwrap(m: &ExprMethodCall) -> bool {
    if m.method != "unwrap" {
        return false;
    }
    match &*m.receiver {
        Expr::MethodCall(inner) => {
            if inner.method != "current_contract_address" {
                return false;
            }
            // Check that the receiver of current_contract_address is env
            match &*inner.receiver {
                Expr::Path(p) => p.path.is_ident("env"),
                _ => false,
            }
        }
        _ => false,
    }
}

struct CurrentContractVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl Visit<'_> for CurrentContractVisitor<'_> {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if is_current_contract_unwrap(i) {
            self.out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::Low,
                file_path: String::new(),
                line: i.span().start().line,
                function_name: self.fn_name.clone(),
                description: format!(
                    "`env.current_contract_address().unwrap()` in `{}` is incorrect. \
                     `current_contract_address()` returns an `Address` directly, not an `Option`. \
                     Remove the `.unwrap()` call.",
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

    fn run(src: &str) -> Vec<Finding> {
        CurrentContractUnwrapCheck.run(&parse_file(src).unwrap(), src)
    }

    #[test]
    fn flags_current_contract_unwrap() {
        let hits = run(r#"
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn bad(env: Env) {
        let addr = env.current_contract_address().unwrap();
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Low);
        assert_eq!(hits[0].check_name, CHECK_NAME);
    }

    #[test]
    fn passes_without_unwrap() {
        let hits = run(r#"
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn good(env: Env) {
        let addr = env.current_contract_address();
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn ignores_non_env_current_contract() {
        let hits = run(r#"
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn other(env: Env) {
        let addr = some_other.current_contract_address().unwrap();
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn ignores_non_contractimpl() {
        let hits = run(r#"
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct C;

impl C {
    pub fn other(env: Env) {
        let addr = env.current_contract_address().unwrap();
    }
}
"#);
        assert!(hits.is_empty());
    }
}
