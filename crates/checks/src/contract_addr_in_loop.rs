//! Detects env.current_contract_address() called inside loops.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "contract-addr-in-loop";

/// Flags `env.current_contract_address()` calls that appear inside `for`, `while`, or `loop` blocks.
pub struct ContractAddrInLoopCheck;

impl Check for ContractAddrInLoopCheck {
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
        if self.loop_depth > 0 && is_current_contract_address_call(i) {
            self.out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::Low,
                file_path: String::new(),
                line: i.span().start().line,
                function_name: self.fn_name.clone(),
                description: format!(
                    "`env.current_contract_address()` is called inside a loop in `{}`. \
                     This is a host call with non-trivial cost. Cache the result in a local \
                     variable before the loop to avoid wasting compute budget.",
                    self.fn_name
                ),
            });
        }
        visit::visit_expr_method_call(self, i);
    }
}

fn is_current_contract_address_call(m: &ExprMethodCall) -> bool {
    if m.method != "current_contract_address" {
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

    #[test]
    fn flags_current_contract_address_in_for_loop() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn process(env: Env) {
        for i in 0..10 {
            let addr = env.current_contract_address();
            let _ = (i, addr);
        }
    }
}
"#,
        )?;
        let hits = ContractAddrInLoopCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Low);
        Ok(())
    }

    #[test]
    fn flags_current_contract_address_in_while_loop() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn process(env: Env) {
        let mut i = 0;
        while i < 10 {
            let addr = env.current_contract_address();
            let _ = addr;
            i += 1;
        }
    }
}
"#,
        )?;
        let hits = ContractAddrInLoopCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Low);
        Ok(())
    }

    #[test]
    fn passes_current_contract_address_outside_loop() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn process(env: Env) {
        let addr = env.current_contract_address();
        for i in 0..10 {
            let _ = (i, &addr);
        }
    }
}
"#,
        )?;
        let hits = ContractAddrInLoopCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_current_contract_address_in_loop_block() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn process(env: Env) {
        loop {
            let addr = env.current_contract_address();
            let _ = addr;
            break;
        }
    }
}
"#,
        )?;
        let hits = ContractAddrInLoopCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        Ok(())
    }
}
