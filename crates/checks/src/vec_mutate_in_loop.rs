//! Detects Vec mutations inside loop bodies.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprForLoop, ExprMethodCall, File};

const CHECK_NAME: &str = "vec-mutate-in-loop";

/// Flags `for` loops where the iterated Vec is mutated inside the loop body.
pub struct VecMutateInLoopCheck;

impl Check for VecMutateInLoopCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut visitor = LoopVisitor {
                fn_name,
                out: &mut out,
            };
            visitor.visit_block(&method.block);
        }
        out
    }
}

struct LoopVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl<'ast> Visit<'ast> for LoopVisitor<'_> {
    fn visit_expr_for_loop(&mut self, i: &'ast ExprForLoop) {
        let iter_var = extract_iter_collection(&i.expr);
        if let Some(var_name) = iter_var {
            let mut body_visitor = LoopBodyVisitor {
                iter_var: var_name.clone(),
                found_mutation: false,
                mutation_line: 0,
            };
            body_visitor.visit_block(&i.body);

            if body_visitor.found_mutation {
                self.out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::High,
                    file_path: String::new(),
                    line: body_visitor.mutation_line,
                    function_name: self.fn_name.clone(),
                    description: format!(
                        "Vec `{}` is mutated inside the loop body in `{}`. \
                         This can cause infinite loops, panics, or incorrect iteration.",
                        var_name, self.fn_name
                    ),
                });
            }
        }
        visit::visit_expr_for_loop(self, i);
    }
}

struct LoopBodyVisitor {
    iter_var: String,
    found_mutation: bool,
    mutation_line: usize,
}

impl<'a> Visit<'a> for LoopBodyVisitor {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if !self.found_mutation && is_vec_mutation_method(i) {
            if let Some(var) = extract_receiver_ident(&i.receiver) {
                if var == self.iter_var {
                    self.found_mutation = true;
                    self.mutation_line = i.span().start().line;
                }
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

fn extract_iter_collection(expr: &Expr) -> Option<String> {
    match expr {
        Expr::MethodCall(m) => extract_iter_collection(&m.receiver),
        Expr::Path(p) => p.path.segments.first().map(|seg| seg.ident.to_string()),
        _ => None,
    }
}

fn extract_receiver_ident(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Path(p) => p.path.segments.first().map(|seg| seg.ident.to_string()),
        Expr::MethodCall(m) => extract_receiver_ident(&m.receiver),
        _ => None,
    }
}

fn is_vec_mutation_method(m: &ExprMethodCall) -> bool {
    matches!(
        m.method.to_string().as_str(),
        "push_back" | "pop_back" | "insert" | "remove" | "set"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_vec_push_in_loop() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env, Vec};

pub struct C;

#[contractimpl]
impl C {
    pub fn process(env: Env, items: Vec<i32>) {
        for item in items.iter() {
            items.push_back(item + 1);
        }
    }
}
"#,
        )?;
        let hits = VecMutateInLoopCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        Ok(())
    }

    #[test]
    fn flags_vec_remove_in_loop() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env, Vec};

pub struct C;

#[contractimpl]
impl C {
    pub fn process(env: Env, items: Vec<i32>) {
        for item in items.iter() {
            items.remove(0);
        }
    }
}
"#,
        )?;
        let hits = VecMutateInLoopCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    fn passes_vec_read_in_loop() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env, Vec};

pub struct C;

#[contractimpl]
impl C {
    pub fn process(env: Env, items: Vec<i32>) {
        for item in items.iter() {
            let _ = item;
        }
    }
}
"#,
        )?;
        let hits = VecMutateInLoopCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_different_vec_mutation() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env, Vec};

pub struct C;

#[contractimpl]
impl C {
    pub fn process(env: Env, items: Vec<i32>, other: Vec<i32>) {
        for item in items.iter() {
            other.push_back(item + 1);
        }
    }
}
"#,
        )?;
        let hits = VecMutateInLoopCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
