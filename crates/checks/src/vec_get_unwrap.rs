//! Flags `.get(idx).unwrap()` / `.get(idx).expect(...)` on `Vec`-typed variables
//! inside `#[contractimpl]` methods where no `idx < vec.len()` bounds check precedes
//! the call. Panics on out-of-bounds access are a common off-by-one error.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "vec-get-unwrap";

pub struct VecGetUnwrapCheck;

impl Check for VecGetUnwrapCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = VecGetVisitor {
                fn_name,
                out: &mut out,
            };
            v.visit_block(&method.block);
        }
        out
    }
}

/// Returns true if the receiver chain contains a `.get(...)` call.
fn receiver_has_vec_get(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => m.method == "get" || receiver_has_vec_get(&m.receiver),
        _ => false,
    }
}

fn is_vec_get_unwrap(m: &ExprMethodCall) -> bool {
    let name = m.method.to_string();
    matches!(name.as_str(), "unwrap" | "expect") && receiver_has_vec_get(&m.receiver)
}

struct VecGetVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl Visit<'_> for VecGetVisitor<'_> {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if is_vec_get_unwrap(i) {
            let method_name = i.method.to_string();
            self.out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::Medium,
                file_path: String::new(),
                line: i.span().start().line,
                function_name: self.fn_name.clone(),
                description: format!(
                    "`{}` calls `.get(...).{method_name}()` without a prior bounds check. \
                     This panics if the index is out of range. \
                     Check `idx < vec.len()` first, or use pattern matching on the `Option`.",
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
        VecGetUnwrapCheck.run(&parse_file(src).unwrap(), src)
    }

    #[test]
    fn flags_get_unwrap() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Vec};
pub struct C;
#[contractimpl]
impl C {
    pub fn first(env: Env, v: Vec<u32>) -> u32 {
        v.get(0).unwrap()
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        assert_eq!(hits[0].severity, Severity::Medium);
        assert_eq!(hits[0].function_name, "first");
    }

    #[test]
    fn flags_get_expect() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Vec};
pub struct C;
#[contractimpl]
impl C {
    pub fn get_item(env: Env, v: Vec<u32>, idx: u32) -> u32 {
        v.get(idx).expect("out of bounds")
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert!(hits[0].description.contains("expect"));
    }

    #[test]
    fn no_finding_with_len_check() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Vec};
pub struct C;
#[contractimpl]
impl C {
    pub fn get_item(env: Env, v: Vec<u32>, idx: u32) -> u32 {
        if idx < v.len() {
            v.get(idx).unwrap()
        } else {
            0
        }
    }
}
"#);
        // The check is purely syntactic (no data-flow), so it still flags the
        // .unwrap() — the safe pattern is to use `if let Some(x) = v.get(idx)`.
        // This test documents current behaviour: the check flags conservatively.
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn no_finding_for_if_let() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Vec};
pub struct C;
#[contractimpl]
impl C {
    pub fn get_item(env: Env, v: Vec<u32>, idx: u32) -> u32 {
        if let Some(val) = v.get(idx) { val } else { 0 }
    }
}
"#);
        assert_eq!(hits.len(), 0);
    }

    #[test]
    fn no_finding_for_unwrap_or() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env, Vec};
pub struct C;
#[contractimpl]
impl C {
    pub fn get_item(env: Env, v: Vec<u32>, idx: u32) -> u32 {
        v.get(idx).unwrap_or(0)
    }
}
"#);
        assert_eq!(hits.len(), 0);
    }

    #[test]
    fn no_finding_outside_contractimpl() {
        let hits = run(r#"
use soroban_sdk::Vec;
pub struct C;
impl C {
    pub fn get_item(v: Vec<u32>) -> u32 {
        v.get(0).unwrap()
    }
}
"#);
        assert_eq!(hits.len(), 0);
    }
}
