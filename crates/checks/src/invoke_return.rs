//! Flags `env.invoke_contract(...)` calls whose return value is ignored.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File, Pat, Stmt};

const CHECK_NAME: &str = "invoke-return";

/// Flags `env.invoke_contract(...)` calls whose result is bound to `_` or immediately dropped.
pub struct InvokeReturnCheck;

impl Check for InvokeReturnCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = InvokeVisitor {
                fn_name: fn_name.clone(),
                out: &mut out,
            };
            v.visit_block(&method.block);
        }
        out
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

struct InvokeVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl<'a> Visit<'a> for InvokeVisitor<'a> {
    fn visit_stmt(&mut self, i: &'a Stmt) {
        match i {
            Stmt::Expr(expr, _) => {
                if let Expr::MethodCall(m) = expr {
                    if is_invoke_contract_call(m) {
                        self.out.push(Finding {
                            check_name: CHECK_NAME.to_string(),
                            severity: Severity::Low,
                            file_path: String::new(),
                            line: m.span().start().line,
                            function_name: self.fn_name.clone(),
                            description: "Return value of `env.invoke_contract()` is ignored. \
                                           The caller cannot detect failure or unexpected results \
                                           from the callee."
                                .to_string(),
                        });
                    }
                }
            }
            Stmt::Local(local) => {
                if let Pat::Wild(_) = local.pat {
                    if let Some((_, init)) = &local.init {
                        if let Expr::MethodCall(m) = &**init {
                            if is_invoke_contract_call(m) {
                                self.out.push(Finding {
                                    check_name: CHECK_NAME.to_string(),
                                    severity: Severity::Low,
                                    file_path: String::new(),
                                    line: m.span().start().line,
                                    function_name: self.fn_name.clone(),
                                    description: "Return value of `env.invoke_contract()` is \
                                                   ignored (bound to `_`). The caller cannot \
                                                   detect failure or unexpected results from the \
                                                   callee."
                                        .to_string(),
                                });
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        visit::visit_stmt(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run_on_src(src: &str) -> Result<Vec<Finding>, syn::Error> {
        let file = parse_file(src)?;
        Ok(InvokeReturnCheck.run(&file, src))
    }

    #[test]
    fn flags_invoke_contract_as_statement() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Address};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn call_other(env: Env, contract: Address) {
        env.invoke_contract(&contract, &Symbol::new(&env, "method"), &());
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "call_other");
        assert_eq!(hits[0].severity, Severity::Low);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        Ok(())
    }

    #[test]
    fn flags_invoke_contract_bound_to_wildcard() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Address};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn call_other(env: Env, contract: Address) {
        let _ = env.invoke_contract(&contract, &Symbol::new(&env, "method"), &());
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "call_other");
        Ok(())
    }

    #[test]
    fn passes_when_return_value_used() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Address};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn call_other(env: Env, contract: Address) {
        let result = env.invoke_contract(&contract, &Symbol::new(&env, "method"), &());
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_non_contractimpl_impl() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{Env, Address};

pub struct Contract;

impl Contract {
    pub fn helper(env: Env, contract: Address) {
        env.invoke_contract(&contract, &Symbol::new(&env, "method"), &());
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }
}
