//! Flags `.unwrap()` on `Vec::pop_back()` / `Vec::pop_front()` results.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "vec-pop-unwrap";

/// Flags `vec.pop_back().unwrap()` and `vec.pop_front().unwrap()` in `#[contractimpl]` methods.
/// Both methods return `Option`; calling `.unwrap()` on an empty `Vec` panics.
pub struct VecPopUnwrapCheck;

impl Check for VecPopUnwrapCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = VecPopVisitor {
                fn_name: fn_name.clone(),
                out: &mut out,
            };
            v.visit_block(&method.block);
        }
        out
    }
}

fn is_vec_pop_unwrap(m: &ExprMethodCall) -> Option<&'static str> {
    if m.method != "unwrap" {
        return None;
    }
    match &*m.receiver {
        Expr::MethodCall(inner) if inner.method == "pop_back" => Some("pop_back"),
        Expr::MethodCall(inner) if inner.method == "pop_front" => Some("pop_front"),
        _ => None,
    }
}

struct VecPopVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl Visit<'_> for VecPopVisitor<'_> {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if let Some(pop_method) = is_vec_pop_unwrap(i) {
            self.out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::Low,
                file_path: String::new(),
                line: i.span().start().line,
                function_name: self.fn_name.clone(),
                description: format!(
                    "`{}` calls `.{pop_method}().unwrap()`. \
                     `{pop_method}` returns `Option` and panics on an empty `Vec`. \
                     Use `unwrap_or`, `unwrap_or_else`, or match the `Option` explicitly.",
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

    fn run(src: &str) -> Vec<Finding> {
        VecPopUnwrapCheck.run(&parse_file(src).unwrap(), src)
    }

    const PRELUDE: &str = r#"
use soroban_sdk::{contract, contractimpl, Env, Vec};

#[contract]
pub struct C;

#[contractimpl]
impl C {
"#;

    #[test]
    fn flags_pop_back_unwrap() {
        let src = format!(
            "{PRELUDE}    pub fn bad(env: Env, mut v: Vec<u32>) -> u32 {{ v.pop_back().unwrap() }}\n}}"
        );
        let hits = run(&src);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Low);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        assert!(hits[0].description.contains("pop_back"));
    }

    #[test]
    fn flags_pop_front_unwrap() {
        let src = format!(
            "{PRELUDE}    pub fn bad(env: Env, mut v: Vec<u32>) -> u32 {{ v.pop_front().unwrap() }}\n}}"
        );
        let hits = run(&src);
        assert_eq!(hits.len(), 1);
        assert!(hits[0].description.contains("pop_front"));
    }

    #[test]
    fn passes_pop_back_unwrap_or() {
        let src = format!(
            "{PRELUDE}    pub fn ok(env: Env, mut v: Vec<u32>) -> u32 {{ v.pop_back().unwrap_or(0) }}\n}}"
        );
        assert!(run(&src).is_empty());
    }

    #[test]
    fn passes_pop_front_match() {
        let src = format!(
            "{PRELUDE}    pub fn ok(env: Env, mut v: Vec<u32>) -> u32 {{ match v.pop_front() {{ Some(x) => x, None => 0 }} }}\n}}"
        );
        assert!(run(&src).is_empty());
    }

    #[test]
    fn ignores_non_contractimpl() {
        let src = r#"
pub struct C;
impl C {
    pub fn bad(mut v: Vec<u32>) -> u32 { v.pop_back().unwrap() }
}
"#;
        assert!(run(src).is_empty());
    }
}
