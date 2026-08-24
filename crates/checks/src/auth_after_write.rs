//! require_auth() called after state mutation (TOCTOU).

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Block, Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "auth-after-write";

/// Flags `#[contractimpl]` functions where `env.require_auth()` appears
/// *after* the first `env.storage()...set(...)` call in statement order.
pub struct AuthAfterWriteCheck;

impl Check for AuthAfterWriteCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            let mut v = AuthWriteVisitor {
                fn_name: fn_name.clone(),
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

fn is_storage_set_call(m: &ExprMethodCall) -> bool {
    m.method == "set" && receiver_chain_contains_storage(&m.receiver)
}

fn is_env_require_auth(m: &ExprMethodCall) -> bool {
    if m.method != "require_auth" {
        return false;
    }
    match &*m.receiver {
        Expr::Path(p) => p.path.is_ident("env"),
        _ => false,
    }
}

struct AuthWriteVisitor<'a> {
    fn_name: String,
    out: &'a mut Vec<Finding>,
}

impl<'ast> Visit<'ast> for AuthWriteVisitor<'ast> {
    fn visit_block(&mut self, i: &'ast Block) {
        let mut first_set_idx: Option<usize> = None;
        let mut first_auth_idx: Option<usize> = None;

        for (idx, stmt) in i.stmts.iter().enumerate() {
            let mut set_finder = SetFinder { found: false };
            set_finder.visit_stmt(stmt);
            if set_finder.found && first_set_idx.is_none() {
                first_set_idx = Some(idx);
            }

            let mut auth_finder = AuthFinder { found: false };
            auth_finder.visit_stmt(stmt);
            if auth_finder.found && first_auth_idx.is_none() {
                first_auth_idx = Some(idx);
            }
        }

        // If set comes before auth, flag it
        if let (Some(set_idx), Some(auth_idx)) = (first_set_idx, first_auth_idx) {
            if set_idx < auth_idx {
                // Find the line of the first set call
                for stmt in &i.stmts {
                    let mut line_finder = FirstSetLineFinder { line: None };
                    line_finder.visit_stmt(stmt);
                    if let Some(line) = line_finder.line {
                        self.out.push(Finding {
                            check_name: CHECK_NAME.to_string(),
                            severity: Severity::High,
                            file_path: String::new(),
                            line,
                            function_name: self.fn_name.clone(),
                            description: format!(
                                "Method `{}` calls `env.require_auth()` *after* a storage write. \
                                 Authorization must be checked *before* any state mutation to \
                                 prevent TOCTOU (time-of-check/time-of-use) vulnerabilities.",
                                self.fn_name
                            ),
                        });
                        break;
                    }
                }
            }
        }

        visit::visit_block(self, i);
    }
}

struct SetFinder {
    found: bool,
}

impl<'ast> Visit<'ast> for SetFinder {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if is_storage_set_call(i) {
            self.found = true;
        }
        visit::visit_expr_method_call(self, i);
    }
}

struct AuthFinder {
    found: bool,
}

impl<'ast> Visit<'ast> for AuthFinder {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if is_env_require_auth(i) {
            self.found = true;
        }
        visit::visit_expr_method_call(self, i);
    }
}

struct FirstSetLineFinder {
    line: Option<usize>,
}

impl<'ast> Visit<'ast> for FirstSetLineFinder {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if self.line.is_none() && is_storage_set_call(i) {
            self.line = Some(i.span().start().line);
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
    fn flags_require_auth_after_storage_write() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env, Symbol};

pub struct C;

#[contractimpl]
impl C {
    pub fn bad_order(env: Env, user: Address, amount: i128) {
        env.storage().instance().set(&Symbol::new(&env, "bal"), &amount);
        env.require_auth();
    }
}
"#,
        )?;
        let hits = AuthAfterWriteCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        assert_eq!(hits[0].function_name, "bad_order");
        Ok(())
    }

    #[test]
    fn passes_when_auth_before_write() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env, Symbol};

pub struct C;

#[contractimpl]
impl C {
    pub fn good_order(env: Env, user: Address, amount: i128) {
        env.require_auth();
        env.storage().instance().set(&Symbol::new(&env, "bal"), &amount);
    }
}
"#,
        )?;
        let hits = AuthAfterWriteCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_when_no_storage_write() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Address, Env};

pub struct C;

#[contractimpl]
impl C {
    pub fn read_only(env: Env, user: Address) {
        env.require_auth();
        let _ = (env, user);
    }
}
"#,
        )?;
        let hits = AuthAfterWriteCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_when_no_auth() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contractimpl, Env, Symbol};

pub struct C;

#[contractimpl]
impl C {
    pub fn no_auth(env: Env, amount: i128) {
        env.storage().instance().set(&Symbol::new(&env, "bal"), &amount);
    }
}
"#,
        )?;
        let hits = AuthAfterWriteCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
