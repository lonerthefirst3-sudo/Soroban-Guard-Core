//! Detects nested loops where both outer and inner loops iterate over storage-backed Vec values.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprForLoop, File};

const CHECK_NAME: &str = "nested-loop-storage";

/// Flags nested `for` loops (depth ≥ 2) where any iterable expression in a loop header
/// is a variable reference (likely storage-backed).
pub struct NestedLoopStorageCheck;

impl Check for NestedLoopStorageCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut visitor = NestedLoopVisitor {
                fn_name,
                loop_depth: 0,
                out: &mut out,
            };
            visitor.visit_block(&method.block);
        }
        out
    }
}

struct NestedLoopVisitor<'a> {
    fn_name: String,
    loop_depth: usize,
    out: &'a mut Vec<Finding>,
}

impl<'a> Visit<'_> for NestedLoopVisitor<'a> {
    fn visit_expr_for_loop(&mut self, i: &ExprForLoop) {
        self.loop_depth += 1;

        // Check if this is a nested loop with a variable reference
        if self.loop_depth >= 2 && is_variable_reference(&i.expr) {
            self.out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::High,
                file_path: String::new(),
                line: i.span().start().line,
                function_name: self.fn_name.clone(),
                description: format!(
                    "Nested loop at depth {} iterates over a variable in `{}`. \
                     If this variable is storage-backed, this has O(n²) compute cost and likely exceeds Soroban budget. \
                     Cache storage values in local variables before loops.",
                    self.loop_depth,
                    self.fn_name
                ),
            });
        }

        visit::visit_expr_for_loop(self, i);
        self.loop_depth -= 1;
    }
}

fn is_variable_reference(expr: &Expr) -> bool {
    match expr {
        Expr::Reference(r) => {
            // Check if it's a reference to a path (variable)
            matches!(&*r.expr, Expr::Path(_))
        }
        Expr::Path(_) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_nested_loop_over_storage_vec() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn process(env: Env) {
        let items: Vec<u32> = env.storage().instance().get(&"items").unwrap_or_default();
        for i in &items {
            let subitems: Vec<u32> = env.storage().instance().get(&"subitems").unwrap_or_default();
            for j in &subitems {
                let _ = (i, j);
            }
        }
    }
}
"#,
        )?;
        let hits = NestedLoopStorageCheck.run(&file, "");
        assert!(!hits.is_empty());
        assert_eq!(hits[0].severity, Severity::High);
        Ok(())
    }

    #[test]
    fn passes_single_loop_over_storage() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn process(env: Env) {
        let items: Vec<u32> = env.storage().instance().get(&"items").unwrap_or_default();
        for i in &items {
            let _ = i;
        }
    }
}
"#,
        )?;
        let hits = NestedLoopStorageCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_nested_loop_with_literal_range() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn process(env: Env) {
        for i in 0..10 {
            for j in 0..10 {
                let _ = (i, j);
            }
        }
    }
}
"#,
        )?;
        let hits = NestedLoopStorageCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
