//! `vec.slice(start, end)` called with offsets from user input without bound checks.
//!
//! Calling `slice` with offsets derived from function parameters without validating
//! that `start <= end <= vec.len()` can cause a panic, crashing the contract.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File, FnArg, Pat};

const CHECK_NAME: &str = "vec-slice-unchecked";

struct SliceVisitor<'a> {
    fn_name: String,
    param_names: std::collections::HashSet<String>,
    out: &'a mut Vec<Finding>,
}

impl<'ast> Visit<'ast> for SliceVisitor<'ast> {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if i.method == "slice" && i.args.len() >= 2 {
            let start_arg = &i.args[0];
            let end_arg = &i.args[1];

            let start_is_param = self.expr_uses_param(start_arg);
            let end_is_param = self.expr_uses_param(end_arg);

            if start_is_param || end_is_param {
                self.out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Medium,
                    file_path: String::new(),
                    line: i.span().start().line,
                    function_name: self.fn_name.clone(),
                    description: format!(
                        "`slice` is called with user-controlled offsets in `{}` without bounds checking. \
                         Validate that `start <= end <= vec.len()` before calling `slice` to prevent panics.",
                        self.fn_name
                    ),
                });
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

impl<'a> SliceVisitor<'a> {
    fn expr_uses_param(&self, expr: &Expr) -> bool {
        struct ParamChecker<'a> {
            param_names: &'a std::collections::HashSet<String>,
            found: bool,
        }

        impl<'ast> Visit<'ast> for ParamChecker<'ast> {
            fn visit_expr(&mut self, i: &'ast Expr) {
                if let Expr::Path(p) = i {
                    if let Some(ident) = p.path.get_ident() {
                        if self.param_names.contains(&ident.to_string()) {
                            self.found = true;
                        }
                    }
                }
                visit::visit_expr(self, i);
            }
        }

        let mut checker = ParamChecker {
            param_names: &self.param_names,
            found: false,
        };
        checker.visit_expr(expr);
        checker.found
    }
}

pub struct VecSliceUncheckedCheck;

impl Check for VecSliceUncheckedCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut param_names = std::collections::HashSet::new();

            for arg in &method.sig.inputs {
                if let FnArg::Typed(pat_type) = arg {
                    if let Pat::Ident(pat_ident) = &*pat_type.pat {
                        param_names.insert(pat_ident.ident.to_string());
                    }
                }
            }

            let mut visitor = SliceVisitor {
                fn_name,
                param_names,
                out: &mut out,
            };
            visitor.visit_block(&method.block);
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
    fn flags_slice_with_param_start() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Env, Vec};
pub struct C;
#[contractimpl]
impl C {
    pub fn slice_it(env: Env, v: Vec<u32>, start: u32) {
        let result = v.slice(start, 10u32);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = VecSliceUncheckedCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        assert_eq!(hits[0].severity, Severity::Medium);
        Ok(())
    }

    #[test]
    fn flags_slice_with_param_end() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Env, Vec};
pub struct C;
#[contractimpl]
impl C {
    pub fn slice_it(env: Env, v: Vec<u32>, end: u32) {
        let result = v.slice(0u32, end);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = VecSliceUncheckedCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    fn flags_slice_with_both_params() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Env, Vec};
pub struct C;
#[contractimpl]
impl C {
    pub fn slice_it(env: Env, v: Vec<u32>, start: u32, end: u32) {
        let result = v.slice(start, end);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = VecSliceUncheckedCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    fn no_finding_with_literals() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Env, Vec};
pub struct C;
#[contractimpl]
impl C {
    pub fn slice_it(env: Env, v: Vec<u32>) {
        let result = v.slice(0u32, 10u32);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = VecSliceUncheckedCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
