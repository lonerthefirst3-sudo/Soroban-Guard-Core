//! Flags `Address::from_str` calls with hardcoded strings that don't validate as Stellar addresses.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprCall, File, Lit};

const CHECK_NAME: &str = "invalid-address-literal";

/// Flags `Address::from_str(...)` calls whose string argument is a literal that does not match the Stellar address format.
pub struct InvalidAddressLiteralCheck;

impl Check for InvalidAddressLiteralCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();

        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = AddressVisitor {
                fn_name: fn_name.clone(),
                out: &mut out,
            };
            v.visit_block(&method.block);
        }

        out
    }
}

fn is_address_from_str_call(expr: &Expr) -> bool {
    if let Expr::Call(call) = expr {
        if let Expr::Path(path) = &*call.func {
            // Check for Address::from_str
            if path.path.segments.len() == 2 {
                if let Some(first) = path.path.segments.first() {
                    if let Some(second) = path.path.segments.last() {
                        return first.ident == "Address" && second.ident == "from_str";
                    }
                }
            }
        }
    }
    false
}

fn is_stellar_address(s: &str) -> bool {
    if s.len() != 56 {
        return false;
    }
    if !s.starts_with('G') {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

struct AddressVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl<'a> Visit<'a> for AddressVisitor<'a> {
    fn visit_expr_call(&mut self, i: &'a ExprCall) {
        if is_address_from_str_call(&Expr::Call(i.clone())) {
            // Check if the first argument is a string literal
            if i.args.len() >= 2 {
                if let Expr::Lit(lit) = &i.args[1] {
                    if let Lit::Str(lit_str) = &lit.lit {
                        let value = lit_str.value();
                        if !is_stellar_address(&value) {
                            self.out.push(Finding {
                                check_name: CHECK_NAME.to_string(),
                                severity: Severity::Medium,
                                file_path: String::new(),
                                line: i.span().start().line,
                                function_name: self.fn_name.clone(),
                                description: format!(
                                    "`Address::from_str` called with hardcoded string `{}` which does not match the Stellar address format (56 characters starting with 'G'). This will always panic at runtime.",
                                    value
                                ),
                            });
                        }
                    }
                }
            }
        }
        visit::visit_expr_call(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run_on_src(src: &str) -> Result<Vec<Finding>, syn::Error> {
        let file = parse_file(src)?;
        Ok(InvalidAddressLiteralCheck.run(&file, src))
    }

    #[test]
    fn flags_invalid_address_literal() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Address};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn transfer_to_admin(env: Env) {
        let admin = Address::from_str(&env, "invalid_g_address");
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "transfer_to_admin");
        assert_eq!(hits[0].severity, Severity::Medium);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        Ok(())
    }

    #[test]
    fn passes_for_valid_stellar_address() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Address};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn transfer_to_admin(env: Env) {
        let admin = Address::from_str(&env, "GABC1234567890123456789012345678901234567890123456789012");
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn flags_short_addresses() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Address};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn transfer_to_admin(env: Env) {
        let admin = Address::from_str(&env, "GABC");
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        Ok(())
    }
}
