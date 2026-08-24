//! Detects `keccak256` used in contracts without Ethereum-compatibility requirements.
//!
//! `keccak256` should only be used for Ethereum-compatible operations (e.g., verifying
//! Ethereum signatures). For general integrity checks, `sha256` is sufficient and
//! more idiomatic in Soroban contracts.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "keccak-misuse";

/// Flags `env.crypto().keccak256(...)` calls in contracts that have no
/// Ethereum-compatibility requirement (no `ecrecover` or `eth_`-prefixed calls).
pub struct KeccakMisuseCheck;

impl Check for KeccakMisuseCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, source: &str) -> Vec<Finding> {
        // If the source contains Ethereum-compat indicators, skip
        if has_eth_compat(source) {
            return vec![];
        }

        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut scan = KeccakScan {
                fn_name,
                out: &mut out,
            };
            scan.visit_block(&method.block);
        }
        out
    }
}

fn has_eth_compat(source: &str) -> bool {
    source.contains("ecrecover") || source.contains("eth_")
}

struct KeccakScan<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl<'ast> Visit<'ast> for KeccakScan<'_> {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if i.method == "keccak256" {
            if let Expr::MethodCall(inner) = &*i.receiver {
                if inner.method == "crypto" {
                    let line = i.span().start().line;
                    self.out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::Low,
                        file_path: String::new(),
                        line,
                        function_name: self.fn_name.clone(),
                        description: format!(
                            "Method `{}` uses `env.crypto().keccak256()` without an \
                             Ethereum-compatibility requirement. Use `sha256` for general \
                             integrity checks in Soroban contracts.",
                            self.fn_name
                        ),
                    });
                }
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_keccak256_without_eth_compat() {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn hash_data(env: Env, data: Bytes) -> BytesN<32> {
        env.crypto().keccak256(&data)
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let findings = KeccakMisuseCheck.run(&file, code);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check_name, CHECK_NAME);
        assert_eq!(findings[0].severity, Severity::Low);
    }

    #[test]
    fn allows_keccak256_with_ecrecover() {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn verify_eth_sig(env: Env, data: Bytes) -> BytesN<32> {
        // ecrecover usage
        env.crypto().keccak256(&data)
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let findings = KeccakMisuseCheck.run(&file, code);
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_sha256_usage() {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn hash_data(env: Env, data: Bytes) -> BytesN<32> {
        env.crypto().sha256(&data)
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let findings = KeccakMisuseCheck.run(&file, code);
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_keccak256_with_eth_prefix() {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn eth_verify(env: Env, data: Bytes) -> BytesN<32> {
        env.crypto().keccak256(&data)
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let findings = KeccakMisuseCheck.run(&file, code);
        assert!(findings.is_empty());
    }
}
