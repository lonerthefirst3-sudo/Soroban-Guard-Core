//! Detects `env.invoke_contract()` called inside loops in `#[contractimpl]` methods.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "invoke-in-loop";

pub struct InvokeInLoopCheck;

impl Check for InvokeInLoopCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut visitor = LoopVisitor {
                fn_name,
                loop_depth: 0,
                out: &mut out,
            };
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
        if self.loop_depth > 0 && is_invoke_contract_call(i) {
            self.out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::High,
                file_path: String::new(),
                line: i.span().start().line,
                function_name: self.fn_name.clone(),
                description: format!(
                    "`env.invoke_contract()` is called inside a loop in `{}`. This multiplies cross-contract calls per iteration and can exhaust compute or create unexpected reentrancy.",
                    self.fn_name
                ),
            });
        }
        visit::visit_expr_method_call(self, i);
    }
}

fn is_invoke_contract_call(m: &ExprMethodCall) -> bool {
    if m.method != "invoke_contract" {
        return false;
    }
    match &*m.receiver {
        Expr::Path(p) => p.path.is_ident("env"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    fn run_on_src(src: &str) -> Result<Vec<Finding>, syn::Error> {
        let file = parse_file(src)?;
        Ok(InvokeInLoopCheck.run(&file, src))
    }

    #[test]
    fn flags_invoke_contract_in_for_loop() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn process(env: Env) {
        for _ in 0..3 {
            env.invoke_contract(&env, &env, &(), &());
        }
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        Ok(())
    }

    #[test]
    fn flags_invoke_contract_in_while_loop() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn process(env: Env) {
        let mut i = 0;
        while i < 1 {
            env.invoke_contract(&env, &env, &(), &());
            i += 1;
        }
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    fn flags_invoke_contract_in_loop_block() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn process(env: Env) {
        loop {
            env.invoke_contract(&env, &env, &(), &());
            break;
        }
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    fn does_not_flag_invoke_contract_outside_loop() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn process(env: Env) {
        env.invoke_contract(&env, &env, &(), &());
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }
}
