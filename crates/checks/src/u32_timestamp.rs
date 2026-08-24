//! Detects `u32` used for timestamp-related parameters.
//!
//! Soroban ledger timestamps are `u64`. Using `u32` silently truncates values
//! after 2038-01-19 (Year 2038 problem), causing incorrect deadline/expiry comparisons.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::{File, FnArg, PatType};

const CHECK_NAME: &str = "u32-timestamp";

const FLAGGED_NAMES: &[&str] = &["time", "timestamp", "deadline", "expiry", "expiration"];

pub struct U32TimestampCheck;

impl Check for U32TimestampCheck {
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
                        if is_u32(ty) && FLAGGED_NAMES.iter().any(|kw| name.contains(kw)) {
                            out.push(Finding {
                                check_name: CHECK_NAME.to_string(),
                                severity: Severity::Medium,
                                file_path: String::new(),
                                line: arg.span().start().line,
                                function_name: fn_name.clone(),
                                description: format!(
                                    "Parameter `{}` in `{}` is `u32` but its name implies a \
                                     timestamp. Soroban ledger timestamps are `u64`; using `u32` \
                                     silently truncates values after 2038-01-19 (Year 2038 \
                                     overflow), leading to incorrect deadline or expiry \
                                     comparisons.",
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

fn is_u32(ty: &syn::Type) -> bool {
    matches!(ty, syn::Type::Path(p) if p.path.segments.last().is_some_and(|s| s.ident == "u32"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        U32TimestampCheck.run(&parse_file(src).unwrap(), "")
    }

    #[test]
    fn flags_u32_timestamp() {
        let hits = run(
            r#"pub struct C; #[contractimpl] impl C {
                pub fn set_expiry(env: Env, timestamp: u32) { let _ = (env, timestamp); }
            }"#,
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        assert!(hits[0].description.contains("timestamp"));
    }

    #[test]
    fn flags_u32_deadline_and_expiry() {
        let hits = run(
            r#"pub struct C; #[contractimpl] impl C {
                pub fn lock(env: Env, deadline: u32, expiry: u32) { let _ = (env, deadline, expiry); }
            }"#,
        );
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn passes_u64_timestamp() {
        let hits = run(
            r#"pub struct C; #[contractimpl] impl C {
                pub fn set_expiry(env: Env, timestamp: u64) { let _ = (env, timestamp); }
            }"#,
        );
        assert!(hits.is_empty());
    }

    #[test]
    fn passes_u32_unrelated_name() {
        let hits = run(
            r#"pub struct C; #[contractimpl] impl C {
                pub fn set_count(env: Env, count: u32) { let _ = (env, count); }
            }"#,
        );
        assert!(hits.is_empty());
    }

    #[test]
    fn flags_u32_time_and_expiration() {
        let hits = run(
            r#"pub struct C; #[contractimpl] impl C {
                pub fn schedule(env: Env, time: u32, expiration: u32) { let _ = (env, time, expiration); }
            }"#,
        );
        assert_eq!(hits.len(), 2);
    }
}
