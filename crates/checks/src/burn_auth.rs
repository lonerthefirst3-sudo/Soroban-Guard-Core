//! `burn` / `burn_from` in `#[contractimpl]` blocks without any `require_auth` call.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Block, ExprMethodCall, File, Visibility};

const CHECK_NAME: &str = "burn-missing-auth";

pub struct BurnAuthCheck;

impl Check for BurnAuthCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            if !matches!(method.vis, Visibility::Public(_)) {
                continue;
            }
            let name = method.sig.ident.to_string();
            if name != "burn" && name != "burn_from" {
                continue;
            }
            if body_has_auth_gate(&method.block) {
                continue;
            }
            out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::High,
                file_path: String::new(),
                line: method.sig.fn_token.span().start().line,
                function_name: name.clone(),
                description: format!(
                    "Token function `{name}` has no `require_auth()` or \
                     `require_auth_for_args()` call. Any caller can destroy tokens \
                     belonging to any address."
                ),
            });
        }
        out
    }
}

fn body_has_auth_gate(block: &Block) -> bool {
    let mut v = AuthScan { found: false };
    v.visit_block(block);
    v.found
}

#[derive(Default)]
struct AuthScan {
    found: bool,
}

impl<'ast> Visit<'ast> for AuthScan {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        let m = i.method.to_string();
        if matches!(m.as_str(), "require_auth" | "require_auth_for_args") {
            self.found = true;
        }
        visit::visit_expr_method_call(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    #[test]
    fn flags_burn_without_auth() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct Token;
#[contractimpl]
impl Token {
    pub fn burn(env: Env, from: Address, amount: i128) {
        // no auth
        let _ = (env, from, amount);
    }
}
"#,
        )?;
        let hits = BurnAuthCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        assert_eq!(hits[0].function_name, "burn");
        Ok(())
    }

    #[test]
    fn flags_burn_from_without_auth() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct Token;
#[contractimpl]
impl Token {
    pub fn burn_from(env: Env, spender: Address, from: Address, amount: i128) {
        let _ = (env, spender, from, amount);
    }
}
"#,
        )?;
        let hits = BurnAuthCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "burn_from");
        Ok(())
    }

    #[test]
    fn passes_burn_with_require_auth() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};
pub struct Token;
#[contractimpl]
impl Token {
    pub fn burn(env: Env, from: Address, amount: i128) {
        from.require_auth();
        let _ = (env, amount);
    }
}
"#,
        )?;
        let hits = BurnAuthCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_non_burn_functions() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};
pub struct Token;
#[contractimpl]
impl Token {
    pub fn mint(env: Env, amount: i128) {
        let _ = (env, amount);
    }
}
"#,
        )?;
        let hits = BurnAuthCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
