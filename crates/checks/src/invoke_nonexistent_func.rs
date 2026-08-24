//! Flags `invoke_contract` calls with function names that don't exist in the callee contract.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File, Lit};

const CHECK_NAME: &str = "invoke-nonexistent-func";

/// Flags `env.invoke_contract(...)` calls whose function name literal is not a known standard function.
pub struct InvokeNonexistentFuncCheck;

impl Check for InvokeNonexistentFuncCheck {
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

// Known standard functions that are safe to call
const KNOWN_STANDARD_FUNCTIONS: &[&str] = &[
    "transfer",
    "balance_of",
    "allowance",
    "approve",
    "total_supply",
    "name",
    "symbol",
    "decimals",
];

struct InvokeVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl<'a> Visit<'a> for InvokeVisitor<'a> {
    fn visit_expr_method_call(&mut self, i: &'a ExprMethodCall) {
        if is_invoke_contract_call(i) {
            // Look for the function name argument - it's usually the second argument
            if i.args.len() >= 2 {
                if let Some(func_name) = extract_func_name_arg(&i.args[1]) {
                    // Check if this is a known standard function
                    if !KNOWN_STANDARD_FUNCTIONS.contains(&func_name.as_str()) {
                        self.out.push(Finding {
                            check_name: CHECK_NAME.to_string(),
                            severity: Severity::Low,
                            file_path: String::new(),
                            line: i.span().start().line,
                            function_name: self.fn_name.clone(),
                            description: format!(
                                "`invoke_contract` called with function name `{}` which is not a known standard function. This may be a typo or invalid function name.",
                                func_name
                            ),
                        });
                    }
                }
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

/// Extract a string from a function name argument: literal "foo", &"foo", or Symbol::new(&env, "foo").
fn extract_func_name_arg(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Lit(lit) => {
            if let Lit::Str(s) = &lit.lit {
                Some(s.value())
            } else {
                None
            }
        }
        Expr::Reference(r) => extract_func_name_arg(&r.expr),
        Expr::Call(c) => {
            // Symbol::new(&env, "func_name") — last arg is the string literal
            c.args.last().and_then(extract_func_name_arg)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run_on_src(src: &str) -> Result<Vec<Finding>, syn::Error> {
        let file = parse_file(src)?;
        Ok(InvokeNonexistentFuncCheck.run(&file, src))
    }

    #[test]
    fn flags_nonexistent_function() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Address};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn call_other(env: Env, contract: Address) {
        env.invoke_contract(&contract, &Symbol::new(&env, "nonexistent_func"), &());
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
    fn passes_for_known_standard_functions() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Address};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn call_transfer(env: Env, contract: Address) {
        env.invoke_contract(&contract, &Symbol::new(&env, "transfer"), &());
    }
    
    pub fn call_balance_of(env: Env, contract: Address) {
        env.invoke_contract(&contract, &Symbol::new(&env, "balance_of"), &());
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }
}
