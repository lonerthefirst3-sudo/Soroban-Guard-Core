//! Flags `extend_ttl(a, b)` calls where both arguments are integer literals and `a > b`.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File, Lit};

const CHECK_NAME: &str = "ttl-arg-order";

/// Flags `extend_ttl(min_ttl, max_ttl)` calls where both arguments are integer literals
/// and the first argument is greater than the second (swapped arguments).
pub struct TtlArgOrderCheck;

impl Check for TtlArgOrderCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = TtlVisitor {
                fn_name: fn_name.clone(),
                out: &mut out,
            };
            v.visit_block(&method.block);
        }
        out
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

fn is_extend_ttl_call(m: &ExprMethodCall) -> bool {
    m.method == "extend_ttl" && receiver_chain_contains_storage(&m.receiver)
}

fn extract_int_literal(expr: &Expr) -> Option<u64> {
    match expr {
        Expr::Lit(syn::ExprLit {
            lit: Lit::Int(lit_int),
            ..
        }) => lit_int.base10_parse().ok(),
        _ => None,
    }
}

struct TtlVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl<'a> Visit<'a> for TtlVisitor<'a> {
    fn visit_expr_method_call(&mut self, i: &'a ExprMethodCall) {
        if is_extend_ttl_call(i) && i.args.len() == 2 {
            if let (Some(first), Some(second)) = (
                extract_int_literal(&i.args[0]),
                extract_int_literal(&i.args[1]),
            ) {
                if first > second {
                    self.out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::Low,
                        file_path: String::new(),
                        line: i.span().start().line,
                        function_name: self.fn_name.clone(),
                        description: format!(
                            "extend_ttl called with min_ttl ({}) > max_ttl ({}). \
                             Arguments may be swapped; max_ttl must be >= min_ttl.",
                            first, second
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
        Ok(TtlArgOrderCheck.run(&file, src))
    }

    #[test]
    fn flags_extend_ttl_with_swapped_args() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn extend_ttl_bad(env: Env) {
        env.storage().instance().extend_ttl(1000, 100);
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "extend_ttl_bad");
        assert_eq!(hits[0].severity, Severity::Low);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        Ok(())
    }

    #[test]
    fn passes_when_args_in_correct_order() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn extend_ttl_good(env: Env) {
        env.storage().instance().extend_ttl(100, 1000);
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_when_args_equal() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn extend_ttl_equal(env: Env) {
        env.storage().instance().extend_ttl(100, 100);
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_non_literal_args() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn extend_ttl_vars(env: Env, min: u32, max: u32) {
        env.storage().instance().extend_ttl(min, max);
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_non_contractimpl_impl() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{Env};

pub struct Contract;

impl Contract {
    pub fn helper(env: Env) {
        env.storage().instance().extend_ttl(1000, 100);
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }
}
