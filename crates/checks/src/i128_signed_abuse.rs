//! Detects `i128` used for semantically non-negative values (balances, counts, supply, etc.).
//!
//! Using `i128` for values that can never be negative allows silent negative-value bugs
//! to propagate. The type should enforce the invariant by using `u128` or `u64` instead.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::{File, FnArg, PatType};

const CHECK_NAME: &str = "i128-signed-abuse";

const FLAGGED_NAMES: &[&str] = &[
    "balance", "supply", "count", "total", "amount", "size", "length", "cap", "limit",
];

pub struct I128SignedAbuseCheck;

impl Check for I128SignedAbuseCheck {
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
                        let name = pat_ident.ident.to_string().to_lowercase();
                        if is_i128(ty) && FLAGGED_NAMES.iter().any(|kw| name.contains(kw)) {
                            out.push(Finding {
                                check_name: CHECK_NAME.to_string(),
                                severity: Severity::Low,
                                file_path: String::new(),
                                line: arg.span().start().line,
                                function_name: fn_name.clone(),
                                description: format!(
                                    "Parameter `{}` in `{}` is `i128` but its name implies a \
                                     non-negative value. Use `u128` or `u64` to enforce the \
                                     invariant at the type level and prevent silent \
                                     negative-value bugs.",
                                    pat_ident.ident, fn_name
                                ),
                            });
                        }
                    }
                }
            }
        }
        out
    }
}

fn is_i128(ty: &syn::Type) -> bool {
    matches!(ty, syn::Type::Path(p) if p.path.segments.last().is_some_and(|s| s.ident == "i128"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        I128SignedAbuseCheck.run(&parse_file(src).unwrap(), "")
    }

    #[test]
    fn flags_i128_balance() {
        let hits = run(
            r#"pub struct C; #[contractimpl] impl C {
                pub fn deposit(env: Env, balance: i128) { let _ = (env, balance); }
            }"#,
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Low);
        assert!(hits[0].description.contains("balance"));
    }

    #[test]
    fn flags_multiple_names() {
        let hits = run(
            r#"pub struct C; #[contractimpl] impl C {
                pub fn f(env: Env, total: i128, supply: i128, cap: i128) { let _ = (env, total, supply, cap); }
            }"#,
        );
        assert_eq!(hits.len(), 3);
    }

    #[test]
    fn passes_u128_balance() {
        let hits = run(
            r#"pub struct C; #[contractimpl] impl C {
                pub fn deposit(env: Env, balance: u128) { let _ = (env, balance); }
            }"#,
        );
        assert!(hits.is_empty());
    }

    #[test]
    fn passes_i128_unrelated_name() {
        let hits = run(
            r#"pub struct C; #[contractimpl] impl C {
                pub fn set_fee(env: Env, fee: i128) { let _ = (env, fee); }
            }"#,
        );
        assert!(hits.is_empty());
    }
}
