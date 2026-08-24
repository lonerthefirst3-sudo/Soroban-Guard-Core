//! Missing has() guard before get().unwrap() on instance storage.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "instance-get-without-guard";

pub struct InstanceGetGuardCheck;

impl Check for InstanceGetGuardCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let mut scan = InstanceGetScan::default();
            scan.visit_block(&method.block);
            for unguarded in scan.unguarded_unwraps {
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Medium,
                    file_path: String::new(),
                    line: unguarded,
                    function_name: method.sig.ident.to_string(),
                    description: "Calling `.get().unwrap()` on instance storage without a prior `has()` check will panic if the key is absent.".to_string(),
                });
            }
        }
        out
    }
}

fn receiver_chain_contains_instance(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "instance" {
                return true;
            }
            receiver_chain_contains_instance(&m.receiver)
        }
        Expr::Field(f) => receiver_chain_contains_instance(&f.base),
        _ => false,
    }
}

fn is_instance_get_unwrap(m: &ExprMethodCall) -> bool {
    if m.method != "unwrap" && m.method != "expect" {
        return false;
    }
    match &*m.receiver {
        Expr::MethodCall(inner) => {
            inner.method == "get" && receiver_chain_contains_instance(&inner.receiver)
        }
        _ => false,
    }
}

fn is_instance_has(m: &ExprMethodCall) -> bool {
    m.method == "has" && receiver_chain_contains_instance(&m.receiver)
}

#[derive(Default)]
struct InstanceGetScan {
    has_guard: bool,
    unguarded_unwraps: Vec<usize>,
}

impl<'ast> Visit<'ast> for InstanceGetScan {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if is_instance_has(i) {
            self.has_guard = true;
        } else if is_instance_get_unwrap(i) && !self.has_guard {
            self.unguarded_unwraps.push(i.span().start().line);
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
    fn flags_get_unwrap_without_has() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn get_value(env: Env) {
        let val = env.storage().instance().get(&"key").unwrap();
    }
}
"#,
        )?;
        let hits = InstanceGetGuardCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        Ok(())
    }

    #[test]
    fn passes_when_has_guard_present() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn get_value(env: Env) {
        if env.storage().instance().has(&"key") {
            let val = env.storage().instance().get(&"key").unwrap();
        }
    }
}
"#,
        )?;
        let hits = InstanceGetGuardCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
