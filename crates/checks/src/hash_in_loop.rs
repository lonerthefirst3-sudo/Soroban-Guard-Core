//! Detects `crypto().sha256(...)` or `crypto().keccak256(...)` called inside loops.
//!
//! Hash functions are expensive host calls. Calling them inside a loop body
//! can exhaust the compute budget. Hash once outside the loop instead.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "hash-in-loop";

pub struct HashInLoopCheck;

impl Check for HashInLoopCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut visitor = LoopVisitor { fn_name, loop_depth: 0, out: &mut out };
            visitor.visit_block(&method.block);
        }
        out
    }
}

struct LoopVisitor<'a> {
    fn_name: String,
    loop_depth: usize,
    out: &'a mut Vec<Finding>,
}

impl<'a> Visit<'_> for LoopVisitor<'a> {
    fn visit_expr_for_loop(&mut self, i: &syn::ExprForLoop) {
        self.loop_depth += 1;
        visit::visit_expr_for_loop(self, i);
        self.loop_depth -= 1;
    }

    fn visit_expr_while(&mut self, i: &syn::ExprWhile) {
        self.loop_depth += 1;
        visit::visit_expr_while(self, i);
        self.loop_depth -= 1;
    }

    fn visit_expr_loop(&mut self, i: &syn::ExprLoop) {
        self.loop_depth += 1;
        visit::visit_expr_loop(self, i);
        self.loop_depth -= 1;
    }

    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if self.loop_depth > 0 && is_hash_call(i) {
            self.out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::Medium,
                file_path: String::new(),
                line: i.span().start().line,
                function_name: self.fn_name.clone(),
                description: format!(
                    "`crypto().{}(...)` called inside a loop in `{}`. \
                     Hash functions are expensive host calls; compute the hash \
                     once outside the loop to avoid exhausting the compute budget.",
                    i.method, self.fn_name
                ),
            });
        }
        visit::visit_expr_method_call(self, i);
    }
}

fn is_hash_call(m: &ExprMethodCall) -> bool {
    if m.method != "sha256" && m.method != "keccak256" {
        return false;
    }
    is_crypto_receiver(&m.receiver)
}

fn is_crypto_receiver(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "crypto" {
                return true;
            }
            is_crypto_receiver(&m.receiver)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        HashInLoopCheck.run(&parse_file(src).unwrap(), src)
    }

    #[test]
    fn flags_sha256_in_for_loop() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn process(env: Env) {
        for i in 0..10u32 {
            let _ = env.crypto().sha256(&env.crypto().sha256(&()));
        }
    }
}
"#);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].severity, Severity::Medium);
    }

    #[test]
    fn flags_keccak256_in_while_loop() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn process(env: Env) {
        let mut i = 0;
        while i < 5 {
            let _ = env.crypto().keccak256(&());
            i += 1;
        }
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
    }

    #[test]
    fn passes_hash_outside_loop() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn process(env: Env) {
        let h = env.crypto().sha256(&());
        for i in 0..10u32 {
            let _ = (i, &h);
        }
    }
}
"#);
        assert!(hits.is_empty());
    }
}
