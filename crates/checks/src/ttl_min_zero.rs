//! Flags `extend_ttl(0, max_ttl)` calls where the minimum TTL argument is the
//! literal `0`.
//!
//! `extend_ttl(min, max)` only extends the TTL when the remaining TTL is below
//! `min`. Passing `0` as `min` means the extension is effectively a no-op for
//! any entry that still has *any* TTL remaining — the entry will never be
//! extended until it has already expired.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File, Lit};

const CHECK_NAME: &str = "ttl-min-zero";

pub struct TtlMinZeroCheck;

impl Check for TtlMinZeroCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = TtlMinZeroVisitor {
                fn_name,
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
            m.method == "storage" || receiver_chain_contains_storage(&m.receiver)
        }
        Expr::Field(f) => receiver_chain_contains_storage(&f.base),
        _ => false,
    }
}

fn is_extend_ttl_call(m: &ExprMethodCall) -> bool {
    m.method == "extend_ttl" && receiver_chain_contains_storage(&m.receiver)
}

fn is_literal_zero(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::Lit(syn::ExprLit {
            lit: Lit::Int(i),
            ..
        }) if i.base10_digits() == "0"
    )
}

struct TtlMinZeroVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl<'a> Visit<'a> for TtlMinZeroVisitor<'a> {
    fn visit_expr_method_call(&mut self, i: &'a ExprMethodCall) {
        if is_extend_ttl_call(i) && i.args.len() == 2 && is_literal_zero(&i.args[0]) {
            self.out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::Low,
                file_path: String::new(),
                line: i.span().start().line,
                function_name: self.fn_name.clone(),
                description: format!(
                    "`extend_ttl(0, max_ttl)` in `{}` provides no minimum TTL threshold. \
                     The extension only fires when remaining TTL is below `min`; with \
                     `min = 0` the call is a no-op for any entry that still has TTL \
                     remaining. Use a meaningful minimum (e.g. half of `max_ttl`) to \
                     ensure the entry is refreshed before it expires.",
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

    fn run(src: &str) -> Result<Vec<Finding>, syn::Error> {
        let file = parse_file(src)?;
        Ok(TtlMinZeroCheck.run(&file, src))
    }

    #[test]
    fn flags_extend_ttl_min_zero_persistent() -> Result<(), syn::Error> {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn refresh(env: Env) {
        env.storage().persistent().extend_ttl(0, 10000);
    }
}
"#)?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Low);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        assert_eq!(hits[0].function_name, "refresh");
        Ok(())
    }

    #[test]
    fn flags_extend_ttl_min_zero_instance() -> Result<(), syn::Error> {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn bump(env: Env) {
        env.storage().instance().extend_ttl(0, 5000);
    }
}
"#)?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "bump");
        Ok(())
    }

    #[test]
    fn flags_extend_ttl_min_zero_temporary() -> Result<(), syn::Error> {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn keep_alive(env: Env) {
        env.storage().temporary().extend_ttl(0, 200);
    }
}
"#)?;
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    fn passes_nonzero_min() -> Result<(), syn::Error> {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn refresh(env: Env) {
        env.storage().persistent().extend_ttl(5000, 10000);
    }
}
"#)?;
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_variable_min() -> Result<(), syn::Error> {
        // Non-literal first arg — cannot statically determine value, skip.
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn refresh(env: Env, min: u32) {
        env.storage().persistent().extend_ttl(min, 10000);
    }
}
"#)?;
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_outside_contractimpl() -> Result<(), syn::Error> {
        // Plain impl block — not scanned.
        let hits = run(r#"
pub struct C;
impl C {
    pub fn helper(env: soroban_sdk::Env) {
        env.storage().persistent().extend_ttl(0, 10000);
    }
}
"#)?;
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn flags_multiple_calls_in_same_function() -> Result<(), syn::Error> {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn refresh_all(env: Env) {
        env.storage().persistent().extend_ttl(0, 10000);
        env.storage().instance().extend_ttl(0, 5000);
    }
}
"#)?;
        assert_eq!(hits.len(), 2);
        assert!(hits.iter().all(|f| f.function_name == "refresh_all"));
        Ok(())
    }
}
