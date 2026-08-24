//! Require_auth called inside conditional branch but not in all branches.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Block, Expr, ExprIf, ExprMatch, ExprMethodCall, File, Stmt};

const CHECK_NAME: &str = "auth-in-branch";

/// Flags methods where `require_auth` is called in some branches but not all.
pub struct AuthInBranchCheck;

impl Check for AuthInBranchCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();
            if has_incomplete_auth_branches(&method.block) {
                let line = method.sig.fn_token.span().start().line;
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::High,
                    file_path: String::new(),
                    line,
                    function_name: fn_name.clone(),
                    description: format!(
                        "Method `{fn_name}` calls `require_auth` in some branches but not all. \
                         All code paths must have consistent authorization gates."
                    ),
                });
            }
        }
        out
    }
}

fn has_incomplete_auth_branches(block: &Block) -> bool {
    let mut v = BranchAuthScan::default();
    v.visit_block(block);
    v.incomplete_branch
}

#[derive(Default)]
struct BranchAuthScan {
    incomplete_branch: bool,
}

impl<'ast> Visit<'ast> for BranchAuthScan {
    fn visit_expr_if(&mut self, i: &'ast ExprIf) {
        let then_has_auth = block_has_auth(&i.then_branch);
        if let Some((_, else_expr)) = &i.else_branch {
            let else_has_auth = expr_has_auth(else_expr);
            if then_has_auth != else_has_auth {
                self.incomplete_branch = true;
            }
        } else if then_has_auth {
            // if without else, and then has auth — missing else path
            self.incomplete_branch = true;
        }
        visit::visit_expr_if(self, i);
    }

    fn visit_expr_match(&mut self, i: &'ast ExprMatch) {
        if i.arms.is_empty() {
            return;
        }
        let first_has_auth = block_has_auth(&i.arms[0].body);
        for arm in &i.arms {
            let arm_has_auth = block_has_auth(&arm.body);
            if arm_has_auth != first_has_auth {
                self.incomplete_branch = true;
                break;
            }
        }
        visit::visit_expr_match(self, i);
    }
}

fn block_has_auth(block: &Block) -> bool {
    let mut v = AuthScan::default();
    v.visit_block(block);
    v.found
}

fn expr_has_auth(expr: &Expr) -> bool {
    match expr {
        Expr::Block(b) => block_has_auth(&b.block),
        _ => {
            let mut v = AuthScan::default();
            v.visit_expr(expr);
            v.found
        }
    }
}

#[derive(Default)]
struct AuthScan {
    found: bool,
}

impl<'ast> Visit<'ast> for AuthScan {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        let m = i.method.to_string();
        if matches!(m.as_str(), "require_auth" | "require_auth_for_args") {
            self.found = true;
        }
        visit::visit_expr_method_call(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Check;
    use syn::parse_file;

    fn run_on_src(src: &str) -> Result<Vec<Finding>, syn::Error> {
        let file = parse_file(src)?;
        Ok(AuthInBranchCheck.run(&file, src))
    }

    #[test]
    fn flags_auth_in_if_but_not_else() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn conditional_auth(env: Env, user: Address, is_admin: bool) {
        if is_admin {
            user.require_auth();
        } else {
            let _ = env;
        }
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        Ok(())
    }

    #[test]
    fn flags_auth_in_else_but_not_if() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn conditional_auth(env: Env, user: Address, is_admin: bool) {
        if is_admin {
            let _ = env;
        } else {
            user.require_auth();
        }
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    fn flags_if_without_else_but_with_auth() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn conditional_auth(env: Env, user: Address, is_admin: bool) {
        if is_admin {
            user.require_auth();
        }
        let _ = env;
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    fn passes_when_auth_in_all_branches() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn conditional_auth(env: Env, user: Address, is_admin: bool) {
        if is_admin {
            user.require_auth();
        } else {
            user.require_auth();
        }
        let _ = env;
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn passes_when_no_auth_in_any_branch() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn no_auth(env: Env, is_admin: bool) {
        if is_admin {
            let _ = env;
        } else {
            let _ = env;
        }
    }
}
"#,
        )?;
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn flags_match_with_inconsistent_auth() -> Result<(), syn::Error> {
        let hits = run_on_src(
            r#"
use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn match_auth(env: Env, user: Address, role: u32) {
        match role {
            1 => user.require_auth(),
            2 => { let _ = env; },
            _ => { let _ = env; },
        }
    }
}
"#,
        )?;
        assert_eq!(hits.len(), 1);
        Ok(())
    }
}
