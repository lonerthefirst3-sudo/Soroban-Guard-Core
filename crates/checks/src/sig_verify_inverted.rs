//! Detects inverted `ed25519_verify` results used as access conditions.
//!
//! Flags `!env.crypto().ed25519_verify(...)` and
//! `env.crypto().ed25519_verify(...) == false` when used as `if` conditions.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprBinary, ExprIf, ExprUnary, File, UnOp};

const CHECK_NAME: &str = "sig-verify-inverted";

pub struct SigVerifyInvertedCheck;

impl Check for SigVerifyInvertedCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut visitor = Visitor {
                fn_name,
                out: &mut out,
            };
            visitor.visit_block(&method.block);
        }
        out
    }
}

struct Visitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl<'a> Visit<'_> for Visitor<'a> {
    fn visit_expr_if(&mut self, i: &ExprIf) {
        if is_inverted_verify(&i.cond) {
            self.out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::High,
                file_path: String::new(),
                line: i.cond.span().start().line,
                function_name: self.fn_name.clone(),
                description: format!(
                    "Inverted `ed25519_verify` result used as condition in `{}`. \
                     This allows unauthorized callers and rejects legitimate ones.",
                    self.fn_name
                ),
            });
        }
        visit::visit_expr_if(self, i);
    }
}

/// Returns true for `!crypto().ed25519_verify(...)` or
/// `crypto().ed25519_verify(...) == false`.
fn is_inverted_verify(expr: &Expr) -> bool {
    match expr {
        Expr::Unary(ExprUnary {
            op: UnOp::Not(_),
            expr,
            ..
        }) => is_ed25519_verify_call(expr),
        Expr::Binary(ExprBinary {
            left,
            op: syn::BinOp::Eq(_),
            right,
            ..
        }) => {
            (is_ed25519_verify_call(left) && is_bool_false(right))
                || (is_ed25519_verify_call(right) && is_bool_false(left))
        }
        _ => false,
    }
}

fn is_ed25519_verify_call(expr: &Expr) -> bool {
    let Expr::MethodCall(m) = expr else {
        return false;
    };
    if m.method != "ed25519_verify" {
        return false;
    }
    is_crypto_receiver(&m.receiver)
}

fn is_crypto_receiver(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "crypto" {
                return true;
            }
            is_crypto_receiver(&m.receiver)
        }
        _ => false,
    }
}

fn is_bool_false(expr: &Expr) -> bool {
    matches!(expr, Expr::Lit(l) if matches!(&l.lit, syn::Lit::Bool(b) if !b.value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        SigVerifyInvertedCheck.run(&parse_file(src).unwrap(), src)
    }

    #[test]
    fn flags_not_verify() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn auth(env: Env) {
        if !env.crypto().ed25519_verify(&env, &(), &()) {
            return;
        }
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
    }

    #[test]
    fn flags_eq_false() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn auth(env: Env) {
        if env.crypto().ed25519_verify(&env, &(), &()) == false {
            return;
        }
    }
}
"#);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn passes_normal_verify() {
        let hits = run(r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn auth(env: Env) {
        if env.crypto().ed25519_verify(&env, &(), &()) {
            return;
        }
    }
}
"#);
        assert!(hits.is_empty());
    }
}
