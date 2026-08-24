//! `vec.iter().collect::<Vec<_>>()` creates unnecessary temporary copies.
//!
//! Calling `.iter()` and then `.collect()` on a Soroban `Vec` creates a temporary
//! copy, doubling memory usage. The original Vec can often be used directly.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "vec-iter-collect";

struct IterCollectVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl<'ast> Visit<'ast> for IterCollectVisitor<'ast> {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if i.method == "collect" {
            if let Expr::MethodCall(inner) = &*i.receiver {
                if inner.method == "iter" {
                    self.out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::Low,
                        file_path: String::new(),
                        line: i.span().start().line,
                        function_name: self.fn_name.clone(),
                        description: format!(
                            "`iter().collect::<Vec<_>>()` in `{}` creates an unnecessary temporary copy. \
                             Consider using the original Vec directly or use a reference instead.",
                            self.fn_name
                        ),
                    });
                }
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

pub struct VecIterCollectCheck;

impl Check for VecIterCollectCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut visitor = IterCollectVisitor {
                fn_name,
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
    fn flags_iter_collect() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Env, Vec};
pub struct C;
#[contractimpl]
impl C {
    pub fn copy_vec(env: Env, v: Vec<u32>) {
        let copy = v.iter().collect::<Vec<_>>();
    }
}
"#;
        let file = parse_file(src)?;
        let hits = VecIterCollectCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        assert_eq!(hits[0].severity, Severity::Low);
        Ok(())
    }

    #[test]
    fn no_finding_without_collect() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Env, Vec};
pub struct C;
#[contractimpl]
impl C {
    pub fn iterate(env: Env, v: Vec<u32>) {
        for item in v.iter() {
            // do something
        }
    }
}
"#;
        let file = parse_file(src)?;
        let hits = VecIterCollectCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn no_finding_collect_without_iter() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Env, Vec};
pub struct C;
#[contractimpl]
impl C {
    pub fn collect_something(env: Env) {
        let v: Vec<u32> = Vec::new(&env);
        let x = some_iter().collect::<Vec<_>>();
    }
}
"#;
        let file = parse_file(src)?;
        let hits = VecIterCollectCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
