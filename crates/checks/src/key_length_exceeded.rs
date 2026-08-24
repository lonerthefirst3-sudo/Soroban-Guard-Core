//! Storage key length exceeds Soroban's maximum allowed length (32 bytes).

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "key-length-exceeded";
const MAX_KEY_LENGTH: usize = 32;

pub struct KeyLengthExceededCheck;

impl Check for KeyLengthExceededCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let mut v = KeyLengthVisitor {
                fn_name: method.sig.ident.to_string(),
                out: &mut out,
            };
            v.visit_block(&method.block);
        }
        out
    }
}

fn receiver_chain_contains_storage(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "storage" {
                return true;
            }
            receiver_chain_contains_storage(&m.receiver)
        }
        Expr::Field(f) => receiver_chain_contains_storage(&f.base),
        _ => false,
    }
}

fn is_storage_key_call(m: &ExprMethodCall) -> bool {
    let name = m.method.to_string();
    matches!(name.as_str(), "set" | "get" | "has" | "remove")
        && receiver_chain_contains_storage(&m.receiver)
}

fn first_arg_str(m: &ExprMethodCall) -> Option<String> {
    let arg = m.args.first()?;
    match arg {
        Expr::Reference(r) => expr_to_string(&r.expr),
        other => expr_to_string(other),
    }
}

fn expr_to_string(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Lit(l) => match &l.lit {
            syn::Lit::Str(s) => Some(s.value()),
            _ => None,
        },
        _ => None,
    }
}

struct KeyLengthVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl Visit<'_> for KeyLengthVisitor<'_> {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if is_storage_key_call(i) {
            if let Some(key) = first_arg_str(i) {
                if key.len() > MAX_KEY_LENGTH {
                    self.out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::Low,
                        file_path: String::new(),
                        line: i.span().start().line,
                        function_name: self.fn_name.clone(),
                        description: format!(
                            "Storage key `{}` is {} bytes, exceeding Soroban's maximum of {} bytes. \
                             This will cause a runtime failure.",
                            key, key.len(), MAX_KEY_LENGTH
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
    use crate::Check;
    use syn::parse_file;

    #[test]
    fn flags_oversized_string_key() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn bad(env: Env) {
        env.storage().persistent().set(&"this_is_a_very_long_key_that_exceeds_limit", &1u32);
    }
}
"#,
        )?;
        let hits = KeyLengthExceededCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Low);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        Ok(())
    }

    #[test]
    fn no_finding_for_short_key() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn good(env: Env) {
        env.storage().persistent().set(&"short", &1u32);
    }
}
"#,
        )?;
        let hits = KeyLengthExceededCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn no_finding_for_exactly_max_length() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn good(env: Env) {
        env.storage().persistent().set(&"12345678901234567890123456789012", &1u32);
    }
}
"#,
        )?;
        let hits = KeyLengthExceededCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn flags_oversized_key_in_get() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn bad(env: Env) {
        let _ = env.storage().persistent().get(&"this_is_a_very_long_key_that_exceeds_limit");
    }
}
"#,
        )?;
        let hits = KeyLengthExceededCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        Ok(())
    }
}
