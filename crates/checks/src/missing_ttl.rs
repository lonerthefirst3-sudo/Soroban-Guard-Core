//! Flags `env.storage().persistent().set(...)` calls without a corresponding `extend_ttl` in the same function.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "missing-ttl-extension";

pub struct MissingTtlExtensionCheck;

impl Check for MissingTtlExtensionCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = TtlScanner::default();
            v.visit_block(&method.block);

            if v.persistent_set && !v.extend_ttl {
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Medium,
                    file_path: String::new(),
                    line: v.set_line.unwrap_or(0),
                    function_name: fn_name.clone(),
                    description: format!(
                        "Method `{fn_name}` writes to `env.storage().persistent()` but never \
                         calls `extend_ttl`. The entry may expire unexpectedly, causing silent data loss."
                    ),
                });
            }
        }
        out
    }
}

fn receiver_has(expr: &Expr, method: &str) -> bool {
    match expr {
        Expr::MethodCall(m) => m.method == method || receiver_has(&m.receiver, method),
        _ => false,
    }
}

#[derive(Default)]
struct TtlScanner {
    persistent_set: bool,
    extend_ttl: bool,
    set_line: Option<usize>,
}

impl<'ast> Visit<'ast> for TtlScanner {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        let name = i.method.to_string();
        if name == "set" && receiver_has(&i.receiver, "persistent") {
            self.persistent_set = true;
            self.set_line = Some(i.span().start().line);
        }
        if name == "extend_ttl" && receiver_has(&i.receiver, "persistent") {
            self.extend_ttl = true;
        }
        visit::visit_expr_method_call(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        MissingTtlExtensionCheck.run(&parse_file(src).unwrap(), src)
    }

    #[test]
    fn flags_persistent_set_without_extend_ttl() {
        let hits = run(r#"
pub struct C;
#[contractimpl]
impl C {
    pub fn store(env: Env, val: i128) {
        env.storage().persistent().set(&KEY, &val);
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
pub struct C;
#[contractimpl]
impl C {
    pub fn store(env: Env, val: i128) {
        env.storage().persistent().set(&KEY, &val);
        env.storage().persistent().extend_ttl(&KEY, 1000, 2000);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn ignores_non_persistent_set() {
        let hits = run(r#"
pub struct C;
#[contractimpl]
impl C {
    pub fn store(env: Env, val: i128) {
        env.storage().instance().set(&KEY, &val);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn ignores_non_contractimpl() {
        let hits = run(r#"
pub struct C;
impl C {
    pub fn store(env: Env, val: i128) {
        env.storage().persistent().set(&KEY, &val);
    }
}
"#);
        assert!(hits.is_empty());
    }
}
