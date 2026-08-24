//! Flags functions that read from `persistent()` storage without calling
//! `extend_ttl` or `bump_to_ttl` afterward, allowing the TTL to decay silently.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "bump-after-read";

fn receiver_has(expr: &Expr, method: &str) -> bool {
    match expr {
        Expr::MethodCall(m) => m.method == method || receiver_has(&m.receiver, method),
        _ => false,
    }
}

#[derive(Default)]
struct ReadScan {
    persistent_get: bool,
    has_extend: bool,
    get_line: Option<usize>,
}

impl<'ast> Visit<'ast> for ReadScan {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        let name = i.method.to_string();
        if matches!(name.as_str(), "get" | "get_unchecked")
            && receiver_has(&i.receiver, "persistent")
        {
            self.persistent_get = true;
            if self.get_line.is_none() {
                self.get_line = Some(i.span().start().line);
            }
        }
        if matches!(name.as_str(), "extend_ttl" | "bump_to_ttl")
            && receiver_has(&i.receiver, "persistent")
        {
            self.has_extend = true;
        }
        visit::visit_expr_method_call(self, i);
    }
}

pub struct BumpAfterReadCheck;

impl Check for BumpAfterReadCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut scan = ReadScan::default();
            scan.visit_block(&method.block);

            if scan.persistent_get && !scan.has_extend {
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Low,
                    file_path: String::new(),
                    line: scan.get_line.unwrap_or(0),
                    function_name: fn_name.clone(),
                    description: format!(
                        "Method `{fn_name}` reads from `persistent()` storage but does not \
                         call `extend_ttl` or `bump_to_ttl`. The entry's TTL continues to \
                         decay on every access, risking unexpected expiry."
                    ),
                });
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        BumpAfterReadCheck.run(&parse_file(src).unwrap(), src)
    }

    #[test]
    fn flags_get_without_extend() {
        let hits = run(r#"
pub struct C;
#[contractimpl]
impl C {
    pub fn read(env: Env) -> u32 {
        env.storage().persistent().get(&KEY).unwrap_or(0)
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Low);
    }

    #[test]
    fn no_flag_when_extend_present() {
        let hits = run(r#"
pub struct C;
#[contractimpl]
impl C {
    pub fn read(env: Env) -> u32 {
        let v = env.storage().persistent().get(&KEY).unwrap_or(0);
        env.storage().persistent().extend_ttl(&KEY, 1000, 2000);
        v
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn no_flag_for_temporary_get() {
        let hits = run(r#"
pub struct C;
#[contractimpl]
impl C {
    pub fn read(env: Env) -> u32 {
        env.storage().temporary().get(&KEY).unwrap_or(0)
    }
}
"#);
        assert!(hits.is_empty());
    }
}
