//! Flags `#[contractimpl]` functions whose names match Soroban SDK reserved identifiers.
//!
//! Naming a contract entry-point the same as a Soroban SDK internal (e.g. `__constructor`,
//! `__check_auth`) can cause unexpected dispatch behaviour or silent no-ops on the Stellar
//! network.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::spanned::Spanned;
use syn::File;

const CHECK_NAME: &str = "reserved-fn-name";

/// Soroban SDK reserved / special function names.
const RESERVED_NAMES: &[&str] = &["__constructor", "__check_auth", "__check_auth_weak"];

pub struct ReservedFnNameCheck;

impl Check for ReservedFnNameCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let name = method.sig.ident.to_string();
            if RESERVED_NAMES.contains(&name.as_str()) {
                let line = method.sig.fn_token.span().start().line;
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Medium,
                    file_path: String::new(),
                    line,
                    function_name: name.clone(),
                    description: format!(
                        "`{name}` is a Soroban SDK reserved identifier. Defining it inside \
                         `#[contractimpl]` can cause unexpected dispatch behaviour or silent \
                         no-ops on the Stellar network."
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
        ReservedFnNameCheck.run(&parse_file(src).unwrap(), src)
    }

    #[test]
    fn flags_constructor_reserved_name() {
        let hits = run(r#"
use soroban_sdk::{contract, contractimpl, Env};
#[contract] pub struct C;
#[contractimpl]
impl C {
    pub fn __constructor(env: Env) { let _ = env; }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        assert_eq!(hits[0].function_name, "__constructor");
    }

    #[test]
    fn flags_check_auth_reserved_name() {
        let hits = run(r#"
use soroban_sdk::{contract, contractimpl, Env};
#[contract] pub struct C;
#[contractimpl]
impl C {
    pub fn __check_auth(env: Env) { let _ = env; }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "__check_auth");
    }

    #[test]
    fn flags_check_auth_weak_reserved_name() {
        let hits = run(r#"
use soroban_sdk::{contract, contractimpl, Env};
#[contract] pub struct C;
#[contractimpl]
impl C {
    pub fn __check_auth_weak(env: Env) { let _ = env; }
}
"#);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function_name, "__check_auth_weak");
    }

    #[test]
    fn passes_for_normal_fn_name() {
        let hits = run(r#"
use soroban_sdk::{contract, contractimpl, Env};
#[contract] pub struct C;
#[contractimpl]
impl C {
    pub fn initialize(env: Env) { let _ = env; }
    pub fn transfer(env: Env) { let _ = env; }
}
"#);
        assert!(hits.is_empty());
    }

    #[test]
    fn ignores_reserved_name_outside_contractimpl() {
        let hits = run(r#"
use soroban_sdk::Env;
pub struct C;
impl C {
    pub fn __constructor(env: Env) { let _ = env; }
}
"#);
        assert!(hits.is_empty());
    }
}
