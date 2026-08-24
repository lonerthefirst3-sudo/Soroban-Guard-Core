//! Flags `initialize`/`init`/`setup` functions that write an `Address` parameter to storage
//! without first calling `require_auth`.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Block, ExprMethodCall, File, FnArg, Pat, Type};

const CHECK_NAME: &str = "init-admin-no-auth";

const INIT_NAMES: &[&str] = &["initialize", "init", "setup"];

pub struct InitAdminNoAuthCheck;

impl Check for InitAdminNoAuthCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let name = method.sig.ident.to_string();
            if !INIT_NAMES.contains(&name.as_str()) {
                continue;
            }
            if !has_address_param(&method.sig.inputs) {
                continue;
            }
            if body_has_require_auth(&method.block) {
                continue;
            }
            if !body_has_storage_set(&method.block) {
                continue;
            }
            let line = method.sig.fn_token.span().start().line;
            out.push(Finding {
                check_name: CHECK_NAME.to_string(),
                severity: Severity::High,
                file_path: String::new(),
                line,
                function_name: name.clone(),
                description: format!(
                    "`{name}` writes an `Address` parameter to storage without calling \
                     `require_auth()`. Any caller can become admin on first invocation."
                ),
            });
        }
        out
    }
}

fn has_address_param(inputs: &syn::punctuated::Punctuated<FnArg, syn::token::Comma>) -> bool {
    inputs.iter().any(|arg| {
        if let FnArg::Typed(pat_type) = arg {
            type_is_address(&pat_type.ty)
        } else {
            false
        }
    })
}

fn type_is_address(ty: &Type) -> bool {
    match ty {
        Type::Path(p) => p
            .path
            .segments
            .last()
            .is_some_and(|s| s.ident == "Address"),
        _ => false,
    }
}

fn body_has_require_auth(block: &Block) -> bool {
    let mut v = AuthScan::default();
    v.visit_block(block);
    v.found
}

#[derive(Default)]
struct AuthScan {
    found: bool,
}

impl<'ast> Visit<'ast> for AuthScan {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if matches!(
            i.method.to_string().as_str(),
            "require_auth" | "require_auth_for_args"
        ) {
            self.found = true;
        }
        visit::visit_expr_method_call(self, i);
    }
}

fn body_has_storage_set(block: &Block) -> bool {
    let mut v = StorageSetScan::default();
    v.visit_block(block);
    v.found
}

#[derive(Default)]
struct StorageSetScan {
    found: bool,
}

impl<'ast> Visit<'ast> for StorageSetScan {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if i.method == "set" {
            // Check receiver chain contains storage()
            let mut cur = &*i.receiver;
            loop {
                match cur {
                    syn::Expr::MethodCall(m) => {
                        if m.method == "storage" {
                            self.found = true;
                            break;
                        }
                        cur = &m.receiver;
                    }
                    _ => break,
                }
            }
        }
        visit::visit_expr_method_call(self, i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_file;

    fn run(src: &str) -> Vec<Finding> {
        InitAdminNoAuthCheck.run(&parse_file(src).unwrap(), src)
    }

    #[test]
    fn flags_initialize_without_auth() {
        let hits = run(r#"
use soroban_sdk::{contract, contractimpl, Address, Env};
#[contract] pub struct C;
#[contractimpl]
impl C {
    pub fn initialize(env: Env, admin: Address) {
        env.storage().instance().set(&"admin", &admin);
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        assert_eq!(hits[0].function_name, "initialize");
    }

    #[test]
    fn passes_when_require_auth_present() {
        let hits = run(r#"
use soroban_sdk::{contract, contractimpl, Address, Env};
#[contract] pub struct C;
#[contractimpl]
impl C {
    pub fn initialize(env: Env, admin: Address) {
        admin.require_auth();
        env.storage().instance().set(&"admin", &admin);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn flags_init_fn_name() {
        let hits = run(r#"
use soroban_sdk::{contract, contractimpl, Address, Env};
#[contract] pub struct C;
#[contractimpl]
impl C {
    pub fn init(env: Env, owner: Address) {
        env.storage().persistent().set(&"owner", &owner);
    }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "init");
    }

    #[test]
    fn ignores_no_address_param() {
        let hits = run(r#"
use soroban_sdk::{contract, contractimpl, Env};
#[contract] pub struct C;
#[contractimpl]
impl C {
    pub fn initialize(env: Env, value: u32) {
        env.storage().instance().set(&"val", &value);
    }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn ignores_non_init_fn() {
        let hits = run(r#"
use soroban_sdk::{contract, contractimpl, Address, Env};
#[contract] pub struct C;
#[contractimpl]
impl C {
    pub fn set_admin(env: Env, admin: Address) {
        env.storage().instance().set(&"admin", &admin);
    }
}
"#);
        assert!(hits.is_empty());
    }
}
