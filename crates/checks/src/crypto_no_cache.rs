//! Detects repeated `env.crypto()` calls without caching in a local variable.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "crypto-no-cache";

/// Flags functions that call `env.crypto()` more than twice without caching the result.
pub struct CryptoNoCacheCheck;

impl Check for CryptoNoCacheCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = CryptoCallVisitor {
                call_lines: Vec::new(),
            };
            v.visit_block(&method.block);

            if v.call_lines.len() > 2 {
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Low,
                    file_path: String::new(),
                    line: v.call_lines[0],
                    function_name: fn_name.clone(),
                    description: format!(
                        "`env.crypto()` is called {} times in `{}` without caching. \
                         Each call crosses the host boundary. Cache the result in a local \
                         variable to avoid wasting compute budget.",
                        v.call_lines.len(),
                        fn_name
                    ),
                });
            }
        }
        out
    }
}

struct CryptoCallVisitor {
    call_lines: Vec<usize>,
}

impl Visit<'_> for CryptoCallVisitor {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if is_env_crypto_call(i) {
            self.call_lines.push(i.span().start().line);
        }
        visit::visit_expr_method_call(self, i);
    }
}

fn is_env_crypto_call(m: &ExprMethodCall) -> bool {
    if m.method != "crypto" {
        return false;
    }
    match &*m.receiver {
        Expr::Path(p) => p.path.is_ident("env"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn flags_three_crypto_calls() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn process(env: Env, data: soroban_sdk::Bytes) {
        let h1 = env.crypto().sha256(&data);
        let h2 = env.crypto().sha256(&data);
        let h3 = env.crypto().sha256(&data);
        let _ = (h1, h2, h3);
    }
}
"#,
        )?;
        let hits = CryptoNoCacheCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Low);
        assert!(hits[0].description.contains("3 times"));
        Ok(())
    }

    #[test]
    fn passes_two_crypto_calls() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn process(env: Env, data: soroban_sdk::Bytes) {
        let h1 = env.crypto().sha256(&data);
        let h2 = env.crypto().sha256(&data);
        let _ = (h1, h2);
    }
}
"#,
        )?;
        let hits = CryptoNoCacheCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_cached_crypto() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn process(env: Env, data: soroban_sdk::Bytes) {
        let crypto = env.crypto();
        let h1 = crypto.sha256(&data);
        let h2 = crypto.sha256(&data);
        let h3 = crypto.sha256(&data);
        let _ = (h1, h2, h3);
    }
}
"#,
        )?;
        let hits = CryptoNoCacheCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn flags_four_crypto_calls() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn verify(env: Env, a: soroban_sdk::Bytes, b: soroban_sdk::Bytes) {
        let _ = env.crypto().sha256(&a);
        let _ = env.crypto().sha256(&b);
        let _ = env.crypto().keccak256(&a);
        let _ = env.crypto().keccak256(&b);
    }
}
"#,
        )?;
        let hits = CryptoNoCacheCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert!(hits[0].description.contains("4 times"));
        Ok(())
    }
}
