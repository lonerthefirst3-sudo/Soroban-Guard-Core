//! `i128` (or `u128`) cast to `u64` without overflow/range checking.
//!
//! `value as u64` silently truncates if `value > u64::MAX` or is negative.
//! In token contracts this can cause amounts to wrap to unexpected values.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprCast, File, Type};

const CHECK_NAME: &str = "i128-to-u64-cast";

fn type_is_u64(ty: &Type) -> bool {
    matches!(ty, Type::Path(p) if p.path.is_ident("u64"))
}

fn expr_type_is_wide_int(expr: &Expr) -> bool {
    // We can't resolve types statically, so we look for common patterns:
    // casts from i128/u128 literals or from expressions typed as i128/u128.
    // The most reliable signal is a nested cast: `(x as i128) as u64`.
    match expr {
        Expr::Cast(inner) => {
            matches!(&*inner.ty, Type::Path(p) if p.path.is_ident("i128") || p.path.is_ident("u128"))
        }
        Expr::Paren(p) => expr_type_is_wide_int(&p.expr),
        // Also flag any `as u64` where the source is a path (variable) — conservative
        // but catches the common `amount as u64` pattern in token contracts.
        Expr::Path(_) => true,
        Expr::MethodCall(_) => true,
        _ => false,
    }
}

struct Visitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl Visit<'_> for Visitor<'_> {
    fn visit_expr_cast(&mut self, i: &ExprCast) {
        if type_is_u64(&i.ty) && expr_type_is_wide_int(&i.expr) {
            self.out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::Medium,
                file_path: String::new(),
                line: i.span().start().line,
                function_name: self.fn_name.clone(),
                description: format!(
                    "`as u64` cast in `{}` may silently truncate an `i128`/`u128` value \
                     that exceeds `u64::MAX` or is negative. Use `u64::try_from(value)` \
                     and handle the error, or validate the range before casting.",
                    self.fn_name
                ),
            });
        }
        visit::visit_expr_cast(self, i);
    }
}

pub struct I128ToU64Check;

impl Check for I128ToU64Check {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = Visitor {
                fn_name,
                out: &mut out,
            };
            v.visit_block(&method.block);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    #[test]
    fn flags_variable_as_u64() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn convert(_env: Env, amount: i128) -> u64 {
        amount as u64
    }
}
"#;
        let file = parse_file(src)?;
        let hits = I128ToU64Check.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        Ok(())
    }

    #[test]
    fn flags_nested_i128_cast_as_u64() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn convert(_env: Env, x: u32) -> u64 {
        (x as i128) as u64
    }
}
"#;
        let file = parse_file(src)?;
        let hits = I128ToU64Check.run(&file, "");
        // outer cast is flagged
        assert!(!hits.is_empty());
        Ok(())
    }

    #[test]
    fn no_finding_for_try_from() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn convert(_env: Env, amount: i128) -> Option<u64> {
        u64::try_from(amount).ok()
    }
}
"#;
        let file = parse_file(src)?;
        let hits = I128ToU64Check.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn no_finding_outside_contractimpl() -> Result<(), syn::Error> {
        let src = r#"
pub struct C;
impl C {
    pub fn convert(amount: i128) -> u64 {
        amount as u64
    }
}
"#;
        let file = parse_file(src)?;
        let hits = I128ToU64Check.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
