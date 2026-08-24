//! Flags contracts where every `#[contractimpl]` function calls
//! `instance().extend_ttl(...)`, suggesting wasteful unconditional TTL extension.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "ttl-every-call";

fn receiver_has_instance(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => m.method == "instance" || receiver_has_instance(&m.receiver),
        _ => false,
    }
}

#[derive(Default)]
struct InstanceExtendScanner {
    found: bool,
}

impl<'ast> Visit<'ast> for InstanceExtendScanner {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if i.method == "extend_ttl" && receiver_has_instance(&i.receiver) {
            self.found = true;
        }
        visit::visit_expr_method_call(self, i);
    }
}

pub struct TtlEveryCallCheck;

impl Check for TtlEveryCallCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let fns = contractimpl_functions(file);
        if fns.len() < 2 {
            return vec![];
        }

        let all_extend = fns.iter().all(|m| {
            let mut s = InstanceExtendScanner::default();
            s.visit_block(&m.block);
            s.found
        });

        if !all_extend {
            return vec![];
        }

        vec![Finding {
            check_name: CHECK_NAME.to_string(),
            severity: Severity::Low,
            file_path: String::new(),
            line: 0,
            function_name: String::new(),
            description: "Every entrypoint in this contract calls `instance().extend_ttl(...)`. \
                 Unconditionally extending the instance TTL on every call is wasteful; \
                 consider checking the remaining TTL first or extending less frequently."
                .to_string(),
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        TtlEveryCallCheck.run(&parse_file(src).unwrap(), src)
    }

    #[test]
    fn flags_every_fn_extends_instance_ttl() {
        let hits = run(r#"
pub struct C;
#[contractimpl]
impl C {
    pub fn foo(env: Env) {
        env.storage().instance().extend_ttl(1000, 2000);
        env.storage().instance().set(&KEY, &1u32);
    }
    pub fn bar(env: Env) {
        env.storage().instance().extend_ttl(1000, 2000);
        env.storage().instance().get::<_, u32>(&KEY).unwrap_or(0);
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Low);
    }

    #[test]
    fn no_flag_when_not_every_fn_extends() {
        let hits = run(r#"
pub struct C;
#[contractimpl]
impl C {
    pub fn foo(env: Env) {
        env.storage().instance().extend_ttl(1000, 2000);
    }
    pub fn bar(env: Env) {
        env.storage().instance().get::<_, u32>(&KEY).unwrap_or(0);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn no_flag_single_fn() {
        let hits = run(r#"
pub struct C;
#[contractimpl]
impl C {
    pub fn foo(env: Env) {
        env.storage().instance().extend_ttl(1000, 2000);
    }
}
"#);
        assert!(hits.is_empty());
    }
}
