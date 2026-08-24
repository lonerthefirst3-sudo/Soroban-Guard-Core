//! Detects hardcoded Stellar network passphrase strings in contract functions.
//!
//! Hardcoding network passphrases (e.g. `"Test SDF Network ; September 2015"`,
//! `"Public Global Stellar Network ; September 2015"`) is fragile and error-prone.
//! They should be obtained from the environment or passed as parameters.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{ExprLit, File, Lit};

const CHECK_NAME: &str = "hardcoded-passphrase";

/// Flags string literals matching known Stellar network passphrase patterns.
pub struct HardcodedPassphraseCheck;

impl Check for HardcodedPassphraseCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = PassphraseVisitor {
                fn_name,
                out: &mut out,
            };
            v.visit_block(&method.block);
        }
        out
    }
}

fn is_network_passphrase(s: &str) -> bool {
    s.contains("Network ;")
        || s.contains("Test SDF")
        || s.contains("Public Global Stellar")
        || s.contains("Standalone Network")
}

struct PassphraseVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl Visit<'_> for PassphraseVisitor<'_> {
    fn visit_expr_lit(&mut self, i: &ExprLit) {
        if let Lit::Str(lit_str) = &i.lit {
            let value = lit_str.value();
            if is_network_passphrase(&value) {
                self.out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Low,
                    file_path: String::new(),
                    line: i.span().start().line,
                    function_name: self.fn_name.clone(),
                    description: format!(
                        "Method `{}` contains a hardcoded Stellar network passphrase `{}`. \
                         Passphrases should be obtained from the environment or passed as \
                         parameters to avoid fragility across network deployments.",
                        self.fn_name, value
                    ),
                });
            }
        }
        visit::visit_expr_lit(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_testnet_passphrase() {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn verify(env: Env) {
        let network = "Test SDF Network ; September 2015";
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let findings = HardcodedPassphraseCheck.run(&file, code);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check_name, CHECK_NAME);
        assert_eq!(findings[0].severity, Severity::Low);
    }

    #[test]
    fn flags_mainnet_passphrase() {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn verify(env: Env) {
        let network = "Public Global Stellar Network ; September 2015";
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let findings = HardcodedPassphraseCheck.run(&file, code);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Low);
    }

    #[test]
    fn flags_network_semicolon_pattern() {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn verify(env: Env) {
        let network = "Standalone Network ; February 2017";
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let findings = HardcodedPassphraseCheck.run(&file, code);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_unrelated_strings() {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn verify(env: Env) {
        let msg = "hello world";
        let key = "admin";
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let findings = HardcodedPassphraseCheck.run(&file, code);
        assert!(findings.is_empty());
    }
}
