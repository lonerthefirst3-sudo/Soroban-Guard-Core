//! Detects u64/u32 used for token amount parameters instead of i128.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::{File, FnArg, PatType};

const CHECK_NAME: &str = "amount-type";

/// Flags function parameters named `amount`, `balance`, `value`, or `quantity` in
/// `#[contractimpl]` functions whose type is `u64` or `u32` instead of `i128`.
pub struct AmountTypeCheck;

impl Check for AmountTypeCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            for arg in &method.sig.inputs {
                if let FnArg::Typed(PatType { pat, ty, .. }) = arg {
                    if let syn::Pat::Ident(pat_ident) = &**pat {
                        let param_name = pat_ident.ident.to_string();
                        if matches!(
                            param_name.as_str(),
                            "amount" | "balance" | "value" | "quantity"
                        ) {
                            if is_u64_or_u32_type(ty) {
                                let line = arg.span().start().line;
                                out.push(Finding {
                                    check_name: CHECK_NAME.to_string(),
                                    severity: Severity::Medium,
                                    file_path: String::new(),
                                    line,
                                    function_name: fn_name.clone(),
                                    description: format!(
                                        "Parameter `{}` in `{}` is `u64` or `u32`, but the \
                                         Soroban token interface uses `i128` for amounts. Using \
                                         the wrong type silently truncates values and is \
                                         incompatible with the standard token interface.",
                                        param_name, fn_name
                                    ),
                                });
                            }
                        }
                    }
                }
            }
        }
        out
    }
}

fn is_u64_or_u32_type(ty: &syn::Type) -> bool {
    match ty {
        syn::Type::Path(p) => {
            if let Some(seg) = p.path.segments.last() {
                let ident = seg.ident.to_string();
                matches!(ident.as_str(), "u64" | "u32")
            } else {
                false
            }
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_u64_amount_parameter() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn transfer(env: Env, amount: u64) {
        let _ = (env, amount);
    }
}
"#,
        )?;
        let hits = AmountTypeCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        assert!(hits[0].description.contains("amount"));
        Ok(())
    }

    #[test]
    fn flags_u32_balance_parameter() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn set_balance(env: Env, balance: u32) {
        let _ = (env, balance);
    }
}
"#,
        )?;
        let hits = AmountTypeCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        Ok(())
    }

    #[test]
    fn passes_i128_amount() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn transfer(env: Env, amount: i128) {
        let _ = (env, amount);
    }
}
"#,
        )?;
        let hits = AmountTypeCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_unrelated_u64_params() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn process(env: Env, count: u64) {
        let _ = (env, count);
    }
}
"#,
        )?;
        let hits = AmountTypeCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
