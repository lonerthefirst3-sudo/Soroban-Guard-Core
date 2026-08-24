//! Flags host function calls whose return value (Result) is ignored.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File, Pat, Stmt};

const CHECK_NAME: &str = "host-result-ignored";

/// Flags host function calls (set, publish, deploy, extend_ttl) whose Result is ignored.
pub struct HostResultIgnoredCheck;

impl Check for HostResultIgnoredCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = HostResultVisitor {
                fn_name: fn_name.clone(),
                out: &mut out,
            };
            v.visit_block(&method.block);
        }
        out
    }
}

fn is_host_result_call(m: &ExprMethodCall) -> bool {
    let method_name = m.method.to_string();
    if !matches!(
        method_name.as_str(),
        "set" | "publish" | "deploy" | "extend_ttl" | "remove" | "bump" | "append"
    ) {
        return false;
    }
    // Check if receiver chain contains env
    receiver_chain_contains_env(&m.receiver)
}

fn receiver_chain_contains_env(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => receiver_chain_contains_env(&m.receiver),
        Expr::Path(p) => p.path.is_ident("env"),
        _ => false,
    }
}

struct HostResultVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl<'a> Visit<'a> for HostResultVisitor<'a> {
    fn visit_stmt(&mut self, i: &'a Stmt) {
        match i {
            Stmt::Expr(Expr::MethodCall(m), _) => {
                if is_host_result_call(m) {
                    self.out.push(Finding {
                        check_name: CHECK_NAME.to_string(),
                        severity: Severity::Medium,
                        file_path: String::new(),
                        line: m.span().start().line,
                        function_name: self.fn_name.clone(),
                        description: format!(
                            "Return value of `env.{}()` is ignored. Host function calls \
                             return `Result` and ignoring the result may hide critical \
                             failures like storage exhaustion or event buffer overflow.",
                            m.method
                        ),
                    });
                }
            }
            Stmt::Local(local) => {
                if let Pat::Wild(_) = local.pat {
                    if let Some(init) = &local.init {
                        if let Expr::MethodCall(m) = &*init.expr {
                            if is_host_result_call(m) {
                                self.out.push(Finding {
                                    check_name: CHECK_NAME.to_string(),
                                    severity: Severity::Medium,
                                    file_path: String::new(),
                                    line: m.span().start().line,
                                    function_name: self.fn_name.clone(),
                                    description: format!(
                                        "Return value of `env.{}()` is ignored (bound to `_`). \
                                         Host function calls return `Result` and ignoring the \
                                         result may hide critical failures.",
                                        m.method
                                    ),
                                });
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        visit::visit_stmt(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run_on_src(src: &str) -> Result<Vec<Finding>, syn::Error> {
        let file = parse_file(src)?;
        Ok(HostResultIgnoredCheck.run(&file, src))
    }

    #[test]
    fn flags_storage_set_as_statement() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn test(env: Env) {
        env.storage().instance().set(&Symbol::new(&env, "key"), &42);
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "test");
        assert_eq!(hits[0].severity, Severity::Medium);
        Ok(())
    }

    #[test]
    fn flags_events_publish_as_statement() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn test(env: Env) {
        env.events().publish((Symbol::new(&env, "topic"),), 42);
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "test");
        Ok(())
    }

    #[test]
    fn allows_result_handling() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn test(env: Env) {
        env.storage().instance().set(&Symbol::new(&env, "key"), &42)?;
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 0);
        Ok(())
    }
}
