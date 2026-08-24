//! `Symbol::from_str` used at runtime instead of the `symbol_short!` compile-time macro.
//!
//! `symbol_short!` validates the string at compile time and produces a zero-cost constant.
//! `Symbol::from_str(&env, name)` defers validation to runtime, so misspelled symbols
//! are only caught when the contract executes on-chain.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprCall, File};

const CHECK_NAME: &str = "runtime-symbol";

fn is_symbol_from_str(call: &ExprCall) -> bool {
    let Expr::Path(p) = &*call.func else {
        return false;
    };
    let segs = &p.path.segments;
    segs.len() == 2 && segs[0].ident == "Symbol" && segs[1].ident == "from_str"
}

struct Visitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl Visit<'_> for Visitor<'_> {
    fn visit_expr_call(&mut self, i: &ExprCall) {
        if is_symbol_from_str(i) {
            self.out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::Low,
                file_path: String::new(),
                line: i.span().start().line,
                function_name: self.fn_name.clone(),
                description: format!(
                    "`Symbol::from_str` used at runtime in `{}`. \
                     For compile-time constant strings (≤9 chars) prefer `symbol_short!` \
                     which validates the value at compile time and has zero runtime cost.",
                    self.fn_name
                ),
            });
        }
        visit::visit_expr_call(self, i);
    }
}

pub struct RuntimeSymbolCheck;

impl Check for RuntimeSymbolCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = Visitor {
                fn_name,
                out: &mut out,
            };
            v.visit_block(&method.block);
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
    fn flags_symbol_from_str() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Env, Symbol};
pub struct C;
#[contractimpl]
impl C {
    pub fn get_key(env: Env) -> Symbol {
        Symbol::from_str(&env, "counter")
    }
}
"#;
        let file = parse_file(src)?;
        let hits = RuntimeSymbolCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Low);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        Ok(())
    }

    #[test]
    fn no_finding_for_symbol_short() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, symbol_short, Env, Symbol};
pub struct C;
#[contractimpl]
impl C {
    pub fn get_key(_env: Env) -> Symbol {
        symbol_short!("counter")
    }
}
"#;
        let file = parse_file(src)?;
        let hits = RuntimeSymbolCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn no_finding_outside_contractimpl() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{Env, Symbol};
pub struct C;
impl C {
    pub fn get_key(env: Env) -> Symbol {
        Symbol::from_str(&env, "counter")
    }
}
"#;
        let file = parse_file(src)?;
        let hits = RuntimeSymbolCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
