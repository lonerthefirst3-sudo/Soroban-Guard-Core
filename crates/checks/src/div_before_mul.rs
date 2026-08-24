//! Division before multiplication causing precision loss in `#[contractimpl]` methods.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, ExprBinary, File};

const CHECK_NAME: &str = "div-before-mul";

/// Flags `#[contractimpl]` methods where a division expression is used as the left-hand
/// operand of a multiplication, which can cause silent precision loss.
pub struct DivBeforeMulCheck;

impl Check for DivBeforeMulCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = ArithVisitor {
                fn_name: fn_name.clone(),
                out: &mut out,
            };
            v.visit_block(&method.block);
        }
        out
    }
}

struct ArithVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl Visit<'_> for ArithVisitor<'_> {
    fn visit_expr_binary(&mut self, i: &ExprBinary) {
        // Check if this is a multiplication with a division on the left
        if let BinOp::Mul(_) = &i.op {
            if is_division_expr(&i.left) {
                self.out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Medium,
                    file_path: String::new(),
                    line: i.span().start().line,
                    function_name: self.fn_name.clone(),
                    description: format!(
                        "Division used as left operand of multiplication in `{}`. \
                         `(a / b) * c` truncates intermediate results—consider `(a * c) / b` \
                         for better precision.",
                        self.fn_name
                    ),
                });
            }
        }
        // Continue visiting child expressions
        visit::visit_expr_binary(self, i);
    }
}

fn is_division_expr(expr: &Expr) -> bool {
    match expr {
        Expr::Binary(binary) => matches!(binary.op, BinOp::Div(_)),
        Expr::Paren(paren) => is_division_expr(&paren.expr),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run_on_src(src: &str) -> Result<Vec<Finding>, syn::Error> {
        let file = parse_file(src)?;
        Ok(DivBeforeMulCheck.run(&file, src))
    }

    #[test]
    fn flags_div_before_mul() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn calculate_share(env: Env, total: i128, parts: i128, multiplier: i128) -> i128 {
        let result = (total / parts) * multiplier;
        result
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "calculate_share");
        assert_eq!(hits[0].severity, Severity::Medium);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        Ok(())
    }

    #[test]
    fn does_not_flag_mul_before_div() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn calculate_share(env: Env, total: i128, parts: i128, multiplier: i128) -> i128 {
        (total * multiplier) / parts
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 0);
        Ok(())
    }

    #[test]
    fn does_not_flag_regular_division() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn calculate_share(env: Env, total: i128, parts: i128) -> i128 {
        total / parts
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 0);
        Ok(())
    }

    #[test]
    fn flags_nested_div_before_mul() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn complex_calc(env: Env, a: i128, b: i128, c: i128, d: i128) -> i128 {
        let intermediate = ((a / b) / c) * d;
        intermediate
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        Ok(())
    }
}