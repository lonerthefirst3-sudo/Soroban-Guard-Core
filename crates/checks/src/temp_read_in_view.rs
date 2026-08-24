//! Detects `env.storage().temporary().get()` in read-only contract methods without a preceding `has()` guard.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Block, Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "temp-read-in-view";

pub struct TempReadInViewCheck;

impl Check for TempReadInViewCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            if function_has_temporary_write(&method.block) {
                continue;
            }
            let fn_name = method.sig.ident.to_string();
            let mut visitor = TempReadInViewVisitor {
                fn_name: fn_name.clone(),
                has_temporary_has: false,
                out: &mut out,
            };
            visitor.visit_block(&method.block);
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

fn receiver_chain_contains_temporary(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "temporary" {
                return true;
            }
            receiver_chain_contains_temporary(&m.receiver)
        }
        Expr::Field(f) => receiver_chain_contains_temporary(&f.base),
        _ => false,
    }
}

fn is_temporary_get_call(m: &ExprMethodCall) -> bool {
    m.method == "get"
        && receiver_chain_contains_storage(&m.receiver)
        && receiver_chain_contains_temporary(&m.receiver)
}

fn is_temporary_has_call(m: &ExprMethodCall) -> bool {
    m.method == "has"
        && receiver_chain_contains_storage(&m.receiver)
        && receiver_chain_contains_temporary(&m.receiver)
}

fn is_temporary_set_call(m: &ExprMethodCall) -> bool {
    m.method == "set"
        && receiver_chain_contains_storage(&m.receiver)
        && receiver_chain_contains_temporary(&m.receiver)
}

fn is_temporary_remove_call(m: &ExprMethodCall) -> bool {
    m.method == "remove"
        && receiver_chain_contains_storage(&m.receiver)
        && receiver_chain_contains_temporary(&m.receiver)
}

fn function_has_temporary_write(block: &Block) -> bool {
    let mut detector = TemporaryWriteDetector { has_write: false };
    detector.visit_block(block);
    detector.has_write
}

struct TemporaryWriteDetector {
    has_write: bool,
}

impl<'ast> Visit<'ast> for TemporaryWriteDetector {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if is_temporary_set_call(i) || is_temporary_remove_call(i) {
            self.has_write = true;
        }
        visit::visit_expr_method_call(self, i);
    }
}

struct TempReadInViewVisitor<'a> {
    fn_name: String,
    has_temporary_has: bool,
    out: &'a mut Vec<Finding>,
}

impl Visit<'_> for TempReadInViewVisitor<'_> {
    fn visit_expr_method_call(&mut self, i: &ExprMethodCall) {
        if is_temporary_has_call(i) {
            self.has_temporary_has = true;
        } else if is_temporary_get_call(i) && !self.has_temporary_has {
            self.out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::Low,
                file_path: String::new(),
                line: i.span().start().line,
                function_name: self.fn_name.clone(),
                description: format!(
                    "`env.storage().temporary().get()` in `{}` is not guarded by a preceding `has()` check. Temporary storage entries can expire, so `get()` may return stale defaults without error.",
                    self.fn_name
                ),
            });
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
    fn flags_temporary_get_without_has_in_view() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn get_value(env: Env, key: u32) -> Option<u32> {
        env.storage().temporary().get(&key)
    }
}
"#,
        )?;
        let hits = TempReadInViewCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Low);
        Ok(())
    }

    #[test]
    fn allows_temporary_get_with_has() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn get_value(env: Env, key: u32) -> Option<u32> {
        if env.storage().temporary().has(&key) {
            Some(env.storage().temporary().get(&key))
        } else {
            None
        }
    }
}
"#,
        )?;
        let hits = TempReadInViewCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn ignores_temporary_get_in_mutating_method() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn update_value(env: Env, key: u32, value: u32) {
        env.storage().temporary().set(&key, &value);
        env.storage().temporary().get(&key);
    }
}
"#,
        )?;
        let hits = TempReadInViewCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
