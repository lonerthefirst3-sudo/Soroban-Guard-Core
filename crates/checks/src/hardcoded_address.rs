//! Hardcoded Stellar address strings in `#[contractimpl]` methods.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{ExprLit, File, Lit};

const CHECK_NAME: &str = "hardcoded-address";

/// Flags string literals that match the Stellar address pattern: 56-character
/// uppercase alphanumeric strings starting with 'G'.
pub struct HardcodedAddressCheck;

impl Check for HardcodedAddressCheck {
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

fn is_stellar_address(s: &str) -> bool {
    if s.len() != 56 {
        return false;
    }
    if !s.starts_with('G') {
        return false;
    }
    s.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

struct AddressVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl Visit<'_> for AddressVisitor<'_> {
    fn visit_expr_lit(&mut self, i: &ExprLit) {
        if let Lit::Str(lit_str) = &i.lit {
            let value = lit_str.value();
            if is_stellar_address(&value) {
                self.out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Low,
                    file_path: String::new(),
                    line: i.span().start().line,
                    function_name: self.fn_name.clone(),
                    description: format!(
                        "Hardcoded Stellar address `{}` in `{}`. \
                         Addresses should be stored in contract storage or passed as parameters \
                         to avoid maintenance and security risks.",
                        value, self.fn_name
                    ),
                });
            }
        }
        // Continue visiting child expressions
        visit::visit_expr_lit(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run_on_src(src: &str) -> Result<Vec<Finding>, syn::Error> {
        let file = parse_file(src)?;
        Ok(HardcodedAddressCheck.run(&file, src))
    }

    #[test]
    fn flags_hardcoded_stellar_address() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn transfer_to_admin(env: Env, amount: i128) {
        let admin = "GABC1234567890123456789012345678901234567890123456789012";
        // something
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "transfer_to_admin");
        assert_eq!(hits[0].severity, Severity::Low);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        Ok(())
    }

    #[test]
    fn does_not_flag_short_strings() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn some_method(env: Env) {
        let short = "short";
        let long_but_wrong_start = "XABC123456789012345678901234567890123456789012345678901234567890";
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 0);
        Ok(())
    }

    #[test]
    fn does_not_flag_lowercase_addresses() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn some_method(env: Env) {
        let lowercase = "gabc123456789012345678901234567890123456789012345678901234567890";
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 0);
        Ok(())
    }

    #[test]
    fn flags_multiple_hardcoded_addresses() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn transfer_between_admins(env: Env, amount: i128) {
        let admin1 = "GABC1234567890123456789012345678901234567890123456789012";
        let admin2 = "GDEF1234567890123456789012345678901234567890123456789012";
        // do something
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 2);
        Ok(())
    }
}