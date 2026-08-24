//! Flags contracts that use `env.storage().instance().set(...)` but never call `env.storage().instance().extend_ttl(...)` anywhere in the file.

use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "instance-ttl-missing";

pub struct InstanceTtlCheck;

impl Check for InstanceTtlCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut v = InstanceTtlVisitor::default();
        v.visit_file(file);

        if v.has_instance_set && !v.has_instance_extend_ttl {
            vec![Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::Medium,
                file_path: String::new(),
                line: v.first_set_line.unwrap_or(0),
                function_name: String::new(),
                description: "Contract uses `env.storage().instance().set(...)` but never calls `env.storage().instance().extend_ttl(...)`. Instance storage may expire, making the contract inaccessible.".to_string(),
            }]
        } else {
            vec![]
        }
    }
}

fn receiver_chain_contains_instance(expr: &Expr) -> bool {
    let mut has_storage = false;
    let mut has_instance = false;
    let mut current = expr;
    while let Expr::MethodCall(m) = current {
        if m.method == "storage" {
            has_storage = true;
        } else if m.method == "instance" {
            has_instance = true;
        }
        current = &m.receiver;
    }
    has_storage && has_instance
}

#[derive(Default)]
struct InstanceTtlVisitor {
    has_instance_set: bool,
    has_instance_extend_ttl: bool,
    first_set_line: Option<usize>,
}

impl<'ast> Visit<'ast> for InstanceTtlVisitor {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        let name = i.method.to_string();
        if name == "set" && receiver_chain_contains_instance(&i.receiver) {
            self.has_instance_set = true;
            if self.first_set_line.is_none() {
                self.first_set_line = Some(i.span().start().line);
            }
        }
        if name == "extend_ttl" && receiver_chain_contains_instance(&i.receiver) {
            self.has_instance_extend_ttl = true;
        }
        visit::visit_expr_method_call(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        InstanceTtlCheck.run(&parse_file(src).unwrap(), src)
    }

    #[test]
    fn flags_instance_set_without_extend_ttl() {
        let hits = run(r#"
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn store(env: Env, val: i128) {
        env.storage().instance().set(&KEY, &val);
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        assert_eq!(hits[0].check_name, CHECK_NAME);
    }

    #[test]
    fn passes_when_extend_ttl_present() {
        let hits = run(r#"
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn store(env: Env, val: i128) {
        env.storage().instance().set(&KEY, &val);
        env.storage().instance().extend_ttl(1000, 2000);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn ignores_non_instance_set() {
        let hits = run(r#"
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn store(env: Env, val: i128) {
        env.storage().persistent().set(&KEY, &val);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn ignores_when_only_extend_ttl() {
        let hits = run(r#"
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn extend(env: Env) {
        env.storage().instance().extend_ttl(1000, 2000);
    }
}
"#);
        assert!(hits.is_empty());
    }
}
