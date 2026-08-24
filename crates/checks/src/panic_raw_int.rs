//! Detects `panic_with_error!` macro invocations where the second argument is
//! a raw integer literal instead of a typed `#[contracterror]` enum variant.
//!
//! `panic_with_error!(&env, 1)` produces an opaque error code that is hard to
//! interpret on-chain. Contracts should use a `#[contracterror]`-annotated enum
//! for structured, self-documenting error reporting.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, File, Lit, Macro};

const CHECK_NAME: &str = "panic-raw-int";

/// Flags `panic_with_error!` calls whose second argument is an integer literal.
pub struct PanicRawIntCheck;

impl Check for PanicRawIntCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut scan = PanicRawIntScan {
                fn_name,
                out: &mut out,
            };
            scan.visit_block(&method.block);
        }
        out
    }
}

struct PanicRawIntScan<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl<'ast> Visit<'ast> for PanicRawIntScan<'_> {
    fn visit_macro(&mut self, i: &'ast Macro) {
        let macro_name = i.path.segments.last().map(|s| s.ident.to_string());

        if macro_name.as_deref() == Some("panic_with_error") {
            // The macro signature is: panic_with_error!(env, error)
            // Flag when the second argument is an integer literal.
            if let Ok(args) = syn::parse2::<PanicArgs>(i.tokens.clone()) {
                if let Some(second) = args.1 {
                    if is_int_literal(&second) {
                        let line = i.span().start().line;
                        self.out.push(Finding {
                            check_name: CHECK_NAME.to_string(),
                            severity: Severity::Low,
                            file_path: String::new(),
                            line,
                            function_name: self.fn_name.clone(),
                            description: format!(
                                "Method `{}` calls `panic_with_error!` with a raw integer literal. \
                                 Use a `#[contracterror]`-annotated enum variant for structured \
                                 error reporting.",
                                self.fn_name
                            ),
                        });
                    }
                }
            }
        }

        visit::visit_macro(self, i);
    }
}

/// Checks whether an expression is an integer literal (optionally negated).
fn is_int_literal(expr: &Expr) -> bool {
    match expr {
        Expr::Lit(lit) => matches!(lit.lit, Lit::Int(_)),
        Expr::Unary(u) => matches!(u.op, syn::UnOp::Neg(_)) && is_int_literal(&u.expr),
        _ => false,
    }
}

/// Minimal parser for `panic_with_error!(expr, expr)` — extracts up to two
/// comma-separated expressions from the macro token stream.
#[allow(dead_code)]
struct PanicArgs(Expr, Option<Expr>);

impl syn::parse::Parse for PanicArgs {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let first: Expr = input.parse()?;
        if input.peek(syn::Token![,]) {
            let _: syn::Token![,] = input.parse()?;
            let second: Expr = input.parse()?;
            Ok(PanicArgs(first, Some(second)))
        } else {
            Ok(PanicArgs(first, None))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    #[test]
    fn detects_raw_int_literal() {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn fail(env: Env) {
        panic_with_error!(&env, 1);
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let findings = PanicRawIntCheck.run(&file, code);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check_name, CHECK_NAME);
        assert_eq!(findings[0].severity, Severity::Low);
        assert_eq!(findings[0].function_name, "fail");
    }

    #[test]
    fn detects_raw_int_zero() {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn fail(env: Env) {
        panic_with_error!(&env, 0);
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let findings = PanicRawIntCheck.run(&file, code);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_enum_variant() {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn fail(env: Env) {
        panic_with_error!(&env, Error::InvalidInput);
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let findings = PanicRawIntCheck.run(&file, code);
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_variable_error() {
        let code = r#"
#[contractimpl]
impl MyContract {
    pub fn fail(env: Env, err: MyError) {
        panic_with_error!(&env, err);
    }
}
        "#;
        let file = parse_file(code).unwrap();
        let findings = PanicRawIntCheck.run(&file, code);
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_outside_contractimpl() {
        let code = r#"
fn helper(env: &Env) {
    panic_with_error!(env, 42);
}

#[contractimpl]
impl MyContract {
    pub fn safe(env: Env) {}
}
        "#;
        let file = parse_file(code).unwrap();
        let findings = PanicRawIntCheck.run(&file, code);
        assert!(findings.is_empty());
    }
}
