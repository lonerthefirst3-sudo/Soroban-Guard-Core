//! Detects `env.crypto().ed25519_verify(...)` calls whose boolean result is ignored.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File, Stmt};

const CHECK_NAME: &str = "ed25519-unchecked";

pub struct Ed25519UncheckedCheck;

impl Check for Ed25519UncheckedCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut visitor = StmtVisitor {
                fn_name,
                out: &mut out,
            };
            visitor.visit_block(&method.block);
        }
        out
    }
}

struct StmtVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl<'a> Visit<'_> for StmtVisitor<'a> {
    fn visit_stmt(&mut self, stmt: &Stmt) {
        if let Some(expr) = match stmt {
            Stmt::Semi(expr, _) => Some(expr),
            Stmt::Expr(expr) => Some(expr),
            _ => None,
        } {
            if is_unchecked_ed25519_verify(expr) {
                self.out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::High,
                    file_path: String::new(),
                    line: expr.span().start().line,
                    function_name: self.fn_name.clone(),
                    description: format!(
                        "`env.crypto().ed25519_verify(...)` is used as a bare statement in `{}`. The boolean result is ignored, so signature verification may be bypassed.",
                        self.fn_name
                    ),
                });
            }
        }
        visit::visit_stmt(self, stmt);
    }
}

fn is_unchecked_ed25519_verify(expr: &Expr) -> bool {
    let Expr::MethodCall(method_call) = expr else {
        return false;
    };
    if method_call.method != "ed25519_verify" {
        return false;
    }
    receiver_chain_is_crypto(&method_call.receiver)
}

fn receiver_chain_is_crypto(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(method) => {
            if method.method == "crypto" {
                return receiver_chain_is_env(&method.receiver);
            }
            receiver_chain_is_crypto(&method.receiver)
        }
        Expr::Path(path) => path.path.is_ident("env"),
        Expr::Field(f) => receiver_chain_is_crypto(&f.base),
        _ => false,
    }
}

fn receiver_chain_is_env(expr: &Expr) -> bool {
    matches!(expr, Expr::Path(path) if path.path.is_ident("env"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run_on_src(src: &str) -> Result<Vec<Finding>, syn::Error> {
        let file = parse_file(src)?;
        Ok(Ed25519UncheckedCheck.run(&file, src))
    }

    #[test]
    fn flags_ed25519_verify_used_as_statement() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn verify(env: Env) {
        env.crypto().ed25519_verify(&env, &(), &());
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        Ok(())
    }

    #[test]
    fn does_not_flag_ed25519_verify_assigned() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn verify(env: Env) {
        let ok = env.crypto().ed25519_verify(&env, &(), &());
        if ok {
            return;
        }
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }
}
