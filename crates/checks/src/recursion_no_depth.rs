//! Detects recursive function calls without a depth counter.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprCall, File, FnArg, Pat};

const CHECK_NAME: &str = "recursion-no-depth";

/// Flags functions that call themselves (direct recursion) without a depth counter check.
pub struct RecursionNoDepthCheck;

impl Check for RecursionNoDepthCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();

        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            
            // Check if function has a depth parameter
            let has_depth_param = method.sig.inputs.iter().any(|arg| {
                if let FnArg::Typed(pat_type) = arg {
                    if let Pat::Ident(pat_ident) = &*pat_type.pat {
                        let param_name = pat_ident.ident.to_string();
                        param_name.contains("depth") || param_name.contains("recursion")
                    } else {
                        false
                    }
                } else {
                    false
                }
            });

            let mut visitor = RecursionVisitor {
                fn_name,
                has_depth_param,
                out: &mut out,
            };
            visitor.visit_block(&method.block);
        }
        out
    }
}

struct RecursionVisitor<'a> {
    fn_name: String,
    has_depth_param: bool,
    out: &'a mut Vec<Finding>,
}

impl<'a> Visit<'_> for RecursionVisitor<'a> {
    fn visit_expr_call(&mut self, i: &ExprCall) {
        // Check if this is a recursive call
        if let Expr::Path(p) = &*i.func {
            // Check if it's a simple ident or a qualified path like Self::func
            let called_fn = if let Some(ident) = p.path.get_ident() {
                ident.to_string()
            } else if p.path.segments.len() == 2 {
                // Handle Self::function_name
                p.path.segments.last().map(|s| s.ident.to_string()).unwrap_or_default()
            } else {
                String::new()
            };
            
            // Only flag if it's a recursive call and no depth parameter
            if called_fn == self.fn_name && !self.has_depth_param {
                self.out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::High,
                    file_path: String::new(),
                    line: i.span().start().line,
                    function_name: self.fn_name.clone(),
                    description: format!(
                        "Function `{}` calls itself recursively without a depth counter parameter. \
                         Recursive calls can hit the WASM stack limit. \
                         Add a depth counter parameter to prevent stack overflow.",
                        self.fn_name
                    ),
                });
            }
        }
        visit::visit_expr_call(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_direct_recursion_without_depth() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn factorial(env: Env, n: u32) -> u32 {
        if n <= 1 {
            1
        } else {
            n * Self::factorial(env, n - 1)
        }
    }
}
"#,
        )?;
        let hits = RecursionNoDepthCheck.run(&file, "");
        assert!(!hits.is_empty());
        assert_eq!(hits[0].severity, Severity::High);
        Ok(())
    }

    #[test]
    fn passes_recursion_with_depth_counter() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn factorial(env: Env, n: u32, depth: u32) -> u32 {
        if depth > 100 {
            return 0;
        }
        if n <= 1 {
            1
        } else {
            n * Self::factorial(env, n - 1, depth + 1)
        }
    }
}
"#,
        )?;
        let hits = RecursionNoDepthCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_non_recursive_call() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn helper(env: Env) -> u32 {
        42
    }

    pub fn process(env: Env) -> u32 {
        Self::helper(env)
    }
}
"#,
        )?;
        let hits = RecursionNoDepthCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
