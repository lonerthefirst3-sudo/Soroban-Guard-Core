//! Detects loop bounds that use function parameters without capping.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use std::collections::HashSet;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprForLoop, ExprWhile, File, FnArg, Pat};

const CHECK_NAME: &str = "loop-bound-no-cap";

/// Flags `for i in 0..param` or `while i < param` patterns where `param` is a function
/// parameter and no `cmp::min(param, MAX)` or equivalent cap precedes the loop.
pub struct LoopBoundNoCapCheck;

impl Check for LoopBoundNoCapCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();

            // Collect function parameter names
            let mut params = HashSet::new();
            for arg in &method.sig.inputs {
                if let FnArg::Typed(pat_type) = arg {
                    if let Pat::Ident(pat_ident) = &*pat_type.pat {
                        params.insert(pat_ident.ident.to_string());
                    }
                }
            }

            let mut visitor = LoopBoundVisitor {
                fn_name,
                params,
                out: &mut out,
            };
            visitor.visit_block(&method.block);
        }
        out
    }
}

struct LoopBoundVisitor<'a> {
    fn_name: String,
    params: HashSet<String>,
    out: &'a mut Vec<Finding>,
}

impl<'a> Visit<'_> for LoopBoundVisitor<'a> {
    fn visit_expr_for_loop(&mut self, i: &ExprForLoop) {
        // Check if the range uses a parameter
        if let Expr::Range(range) = &*i.expr {
            if let Some(end) = &range.end {
                if is_param_reference(end, &self.params) {
                    self.out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::High,
                        file_path: String::new(),
                        line: i.span().start().line,
                        function_name: self.fn_name.clone(),
                        description: format!(
                            "Loop bound in `{}` uses uncapped function parameter. \
                             An attacker can exhaust the transaction budget. \
                             Cap the parameter with `cmp::min(param, MAX_ITERATIONS)` before the loop.",
                            self.fn_name
                        ),
                    });
                }
            }
        }
        visit::visit_expr_for_loop(self, i);
    }

    fn visit_expr_while(&mut self, i: &ExprWhile) {
        // Check if the condition uses a parameter
        if is_param_in_expr(&i.cond, &self.params) {
            self.out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::High,
                file_path: String::new(),
                line: i.span().start().line,
                function_name: self.fn_name.clone(),
                description: format!(
                    "While loop condition in `{}` uses uncapped function parameter. \
                     An attacker can exhaust the transaction budget. \
                     Cap the parameter with `cmp::min(param, MAX_ITERATIONS)` before the loop.",
                    self.fn_name
                ),
            });
        }
        visit::visit_expr_while(self, i);
    }
}

fn is_param_reference(expr: &Expr, params: &HashSet<String>) -> bool {
    match expr {
        Expr::Path(p) => {
            if let Some(ident) = p.path.get_ident() {
                params.contains(&ident.to_string())
            } else {
                false
            }
        }
        _ => false,
    }
}

fn is_param_in_expr(expr: &Expr, params: &HashSet<String>) -> bool {
    match expr {
        Expr::Path(p) => {
            if let Some(ident) = p.path.get_ident() {
                params.contains(&ident.to_string())
            } else {
                false
            }
        }
        Expr::Binary(b) => is_param_in_expr(&b.left, params) || is_param_in_expr(&b.right, params),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_for_loop_with_uncapped_param() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn process(env: Env, count: u32) {
        for i in 0..count {
            let _ = i;
        }
    }
}
"#,
        )?;
        let hits = LoopBoundNoCapCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        Ok(())
    }

    #[test]
    fn flags_while_loop_with_uncapped_param() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn process(env: Env, count: u32) {
        let mut i = 0;
        while i < count {
            let _ = i;
            i += 1;
        }
    }
}
"#,
        )?;
        let hits = LoopBoundNoCapCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        Ok(())
    }

    #[test]
    fn passes_for_loop_with_literal_bound() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn process(env: Env) {
        for i in 0..100 {
            let _ = i;
        }
    }
}
"#,
        )?;
        let hits = LoopBoundNoCapCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_for_loop_with_capped_param() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn process(env: Env, count: u32) {
        let capped = std::cmp::min(count, 100);
        for i in 0..capped {
            let _ = i;
        }
    }
}
"#,
        )?;
        let hits = LoopBoundNoCapCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
