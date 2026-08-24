//! Detects price/rate parameters stored without min and max bound validation.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use std::collections::HashSet;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, ExprBinary, ExprMethodCall, File, FnArg, Macro, Pat, Visibility};

const CHECK_NAME: &str = "unvalidated-price";

const PRICE_FN_NAMES: &[&str] = &["set_price", "update_price", "set_rate", "update_rate"];

/// Flags `set_price`/`update_price`/`set_rate` functions that write a `price`/`rate`
/// parameter to storage without both a lower-bound and upper-bound check.
pub struct UnvalidatedPriceCheck;

impl Check for UnvalidatedPriceCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            if !matches!(method.vis, Visibility::Public(_)) {
                continue;
            }
            let fn_name = method.sig.ident.to_string();
            if !PRICE_FN_NAMES.contains(&fn_name.as_str()) {
                continue;
            }
            let price_params = collect_price_params(method);
            if price_params.is_empty() {
                continue;
            }
            let mut scan = BoundScan::default();
            scan.visit_block(&method.block);
            if !scan.has_storage_write {
                continue;
            }
            if !scan.has_lower_bound || !scan.has_upper_bound {
                let line = method.sig.fn_token.span().start().line;
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::High,
                    file_path: String::new(),
                    line,
                    function_name: fn_name.clone(),
                    description: format!(
                        "Function `{fn_name}` stores a price/rate parameter without both a \
                         lower-bound and upper-bound validation. An attacker can set the price \
                         to 0 or i128::MAX, enabling free tokens or blocking all trades."
                    ),
                });
            }
        }
        out
    }
}

fn collect_price_params(method: &syn::ImplItemFn) -> HashSet<String> {
    let mut names = HashSet::new();
    for arg in &method.sig.inputs {
        let FnArg::Typed(pt) = arg else { continue };
        let Pat::Ident(pi) = &*pt.pat else { continue };
        let name = pi.ident.to_string();
        if name.contains("price") || name.contains("rate") {
            names.insert(name);
        }
    }
    names
}

#[derive(Default)]
struct BoundScan {
    has_lower_bound: bool,
    has_upper_bound: bool,
    has_storage_write: bool,
}

impl<'ast> Visit<'ast> for BoundScan {
    fn visit_macro(&mut self, i: &'ast Macro) {
        if let Ok(expr) = i.parse_body::<Expr>() {
            self.visit_expr(&expr);
        }
        syn::visit::visit_macro(self, i);
    }

    fn visit_expr_binary(&mut self, i: &'ast ExprBinary) {
        match i.op {
            BinOp::Gt(_) | BinOp::Ge(_) => self.has_lower_bound = true,
            BinOp::Lt(_) | BinOp::Le(_) => self.has_upper_bound = true,
            _ => {}
        }
        visit::visit_expr_binary(self, i);
    }

    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if i.method == "set" && receiver_has_storage(&i.receiver) {
            self.has_storage_write = true;
        }
        visit::visit_expr_method_call(self, i);
    }
}

fn receiver_has_storage(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "storage" {
                return true;
            }
            receiver_has_storage(&m.receiver)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_set_price_without_bounds() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn set_price(env: Env, price: i128) {
        env.storage().instance().set(&"price", &price);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = UnvalidatedPriceCheck.run(&file, src);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        Ok(())
    }

    #[test]
    fn passes_with_both_bounds() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn set_price(env: Env, price: i128) {
        assert!(price > 0 && price <= 1_000_000);
        env.storage().instance().set(&"price", &price);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = UnvalidatedPriceCheck.run(&file, src);
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn flags_set_rate_without_upper_bound() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn set_rate(env: Env, rate: i128) {
        assert!(rate > 0);
        env.storage().instance().set(&"rate", &rate);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = UnvalidatedPriceCheck.run(&file, src);
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    fn ignores_unrelated_fn_names() -> Result<(), syn::Error> {
        let src = r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn deposit(env: Env, price: i128) {
        env.storage().instance().set(&"price", &price);
    }
}
"#;
        let file = parse_file(src)?;
        let hits = UnvalidatedPriceCheck.run(&file, src);
        assert!(hits.is_empty());
        Ok(())
    }
}
