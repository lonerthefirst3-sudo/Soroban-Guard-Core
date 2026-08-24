//! Ownership transfer functions missing event emission.

use crate::util::contractimpl_functions;
use crate::{Check, Finding, Severity};
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, File};

const CHECK_NAME: &str = "ownership-no-event";

/// Flags `#[contractimpl]` methods named `transfer_ownership`, `set_admin`,
/// `renounce_ownership`, or `accept_ownership` that do not contain a call to
/// `env.events().publish(...)`.
pub struct OwnershipNoEventCheck;

impl Check for OwnershipNoEventCheck {
    fn name(&self) -> &str {
        CHECK_NAME
    }

    fn run(&self, file: &File, _source: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        for method in contractimpl_functions(file) {
            let fn_name = method.sig.ident.to_string();

            // Check if this is an ownership-related function
            if !matches!(
                fn_name.as_str(),
                "transfer_ownership" | "set_admin" | "renounce_ownership" | "accept_ownership"
            ) {
                continue;
            }

            let mut scan = EventScan::default();
            scan.visit_block(&method.block);

            if !scan.events_publish {
                let line = method.sig.ident.span().start().line;
                out.push(Finding {
                    check_name: CHECK_NAME.to_string(),
                    severity: Severity::Medium,
                    file_path: String::new(),
                    line,
                    function_name: fn_name.clone(),
                    description: format!(
                        "Method `{fn_name}` performs a critical state change (ownership transfer) \
                         but does not emit an event via `env.events().publish(...)`. Off-chain \
                         monitors cannot detect admin changes without events. Add an event emission."
                    ),
                });
            }
        }
        out
    }
}

fn is_events_publish(m: &ExprMethodCall) -> bool {
    if m.method != "publish" {
        return false;
    }
    receiver_chain_contains_events(&m.receiver)
}

fn receiver_chain_contains_events(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            if m.method == "events" {
                return true;
            }
            receiver_chain_contains_events(&m.receiver)
        }
        Expr::Field(f) => receiver_chain_contains_events(&f.base),
        _ => false,
    }
}

#[derive(Default)]
struct EventScan {
    events_publish: bool,
}

impl<'ast> Visit<'ast> for EventScan {
    fn visit_expr_method_call(&mut self, i: &'ast ExprMethodCall) {
        if is_events_publish(i) {
            self.events_publish = true;
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
    fn flags_transfer_ownership_without_event() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn transfer_ownership(env: Env, new_owner: Address) {
        env.storage().instance().set(&"owner", &new_owner);
    }
}
"#,
        )?;
        let hits = OwnershipNoEventCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        assert_eq!(hits[0].check_name, CHECK_NAME);
        Ok(())
    }

    #[test]
    fn passes_transfer_ownership_with_event() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contract, contractimpl, Address, Env, symbol_short};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn transfer_ownership(env: Env, new_owner: Address) {
        env.storage().instance().set(&"owner", &new_owner);
        env.events().publish((symbol_short!("ownership_transferred"),), new_owner);
    }
}
"#,
        )?;
        let hits = OwnershipNoEventCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn flags_set_admin_without_event() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn set_admin(env: Env, admin: Address) {
        env.storage().instance().set(&"admin", &admin);
    }
}
"#,
        )?;
        let hits = OwnershipNoEventCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    fn flags_renounce_ownership_without_event() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn renounce_ownership(env: Env) {
        env.storage().instance().remove(&"owner");
    }
}
"#,
        )?;
        let hits = OwnershipNoEventCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    fn flags_accept_ownership_without_event() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn accept_ownership(env: Env, new_owner: Address) {
        env.storage().instance().set(&"owner", &new_owner);
    }
}
"#,
        )?;
        let hits = OwnershipNoEventCheck.run(&file, "");
        assert_eq!(hits.len(), 1);
        Ok(())
    }

    #[test]
    fn ignores_non_ownership_functions() -> Result<(), syn::Error> {
        let file = parse_file(
            r#"
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn some_other_function(env: Env) {
        env.storage().instance().set(&"key", &42);
    }
}
"#,
        )?;
        let hits = OwnershipNoEventCheck.run(&file, "");
        assert!(hits.is_empty());
        Ok(())
    }
}
