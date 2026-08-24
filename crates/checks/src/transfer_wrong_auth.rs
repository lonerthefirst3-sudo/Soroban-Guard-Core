//! Transfer function requires auth on `from` parameter, not `to`.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File, Ident};

const CHECK_NAME: &str = "transfer-wrong-auth";

/// Flags `transfer` methods that call `require_auth` on `to`/`recipient` instead of `from`/`sender`.
pub struct TransferWrongAuthCheck;

impl Check for TransferWrongAuthCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            if fn_name != "transfer" {
                continue;
            }
            let mut scan = TransferAuthScan::default();
            scan.visit_block(&method.block);
            if let Some(line) = scan.wrong_auth_line {
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::High,
                    file_path: String::new(),
                    line,
                    function_name: fn_name.clone(),
                    description: format!(
                        "Method `{fn_name}` calls `require_auth` on `to`/`recipient` instead of \
                         `from`/`sender`. Requiring auth on the recipient allows any spender to \
                         drain the `from` account."
                    ),
                });
            }
        }
        out
    }
}

#[derive(Default)]
struct TransferAuthScan {
    wrong_auth_line: Option<usize>,
}

impl<'ast> Visit<'ast> for TransferAuthScan {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if self.wrong_auth_line.is_none() && i.method == "require_auth" {
            if let Expr::Path(p) = &*i.receiver {
                if let Some(ident) = p.path.get_ident() {
                    let name = ident.to_string();
                    if matches!(name.as_str(), "to" | "recipient") {
                        self.wrong_auth_line = Some(i.span().start().line);
                    }
                }
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run_on_src(src: &str) -> Result<Vec<Finding>, syn::Error> {
        let file = parse_file(src)?;
        Ok(TransferWrongAuthCheck.run(&file, src))
    }

    #[test]
    fn flags_require_auth_on_to() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        to.require_auth();
        let _ = (env, from, amount);
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        Ok(())
    }

    #[test]
    fn flags_require_auth_on_recipient() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn transfer(env: Env, from: Address, recipient: Address, amount: i128) {
        recipient.require_auth();
        let _ = (env, from, amount);
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    fn passes_when_require_auth_on_from() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        let _ = (env, to, amount);
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_when_require_auth_on_sender() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn transfer(env: Env, sender: Address, recipient: Address, amount: i128) {
        sender.require_auth();
        let _ = (env, recipient, amount);
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_non_transfer_functions() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn other_fn(env: Env, to: Address) {
        to.require_auth();
        let _ = env;
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }
}
